# Talos Lab Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go/cobra `lab` CLI under `test/lab/` that stands up a multi-cluster Talos IPv6-BGP fabric on containerlab (containers only) with fabric-only egress, a persistent local registry mirror, and deploys the ectobase substrate — coexisting additively with the existing kind/clab fabric.

**Architecture:** Approach B (single `fabric` topology, no mage). A typed `lab.yaml` → derive per-cluster prefixes → sprig-render templates into `build/<name>/` → containerlab deploy of VyOS edges (default-origin + DNS64 + Tayga NAT64) + VyOS switches (RA + transit) + Tayga + WAN sim + registry:2 + Talos container nodes (native GoBGP) → per-cluster Talos bootstrap → Cilium → deploy ectobase. Reuses the exact mechanics of `/home/nik/Development/icn/sandbox` (Go lab) and `/home/nik/Development/icn/images` (container image builds); those are in-tree references to read and adapt.

**Tech Stack:** Go 1.26 + cobra + Masterminds/sprig/v3, containerlab, Talos (container mode) + talosctl, VyOS, Tayga, Docker registry:2, Cilium (Helm), the existing `deploy/charts/ectobase` chart + `central/config`.

**References (read these; do not modify them):**
- Go lab: `/home/nik/Development/icn/sandbox/` — `pkg/`, `topologies/fabric/`, `magefiles/`.
- Images: `/home/nik/Development/icn/images/{talos,tayga,vyos}/`.

---

## Validation model (READ FIRST)

Two tiers, mirroring the tier2 plan:
- **Unit (CI-safe, TDD):** config load/validate, prefix derivation, and template rendering (golden files) — `go test ./test/lab/...`. Write these test-first.
- **Live checkpoints (fabric host):** image builds, `lab up`, `lab down`, `lab test`. These need sudo + docker + containerlab + talosctl. Each phase ends with a **LIVE CHECKPOINT** that is the real gate for that layer.

Run Go tooling in the nix devShell: `nix develop --command bash -c '...'`. Live commands need real `/run/wrappers/bin/sudo`. Commit after every green step.

---

## File Structure

```
test/lab/
  go.mod                          # module github.com/trevex/ectobase/test/lab
  main.go                         # cobra root + --config
  cmd/{up,down,render,deploy,test,access}.go
  internal/
    config/{config.go,validate.go,derive.go,*_test.go}
    render/{render.go,render_test.go}
    clab/clab.go
    talos/{gen.go,bootstrap.go}
    vyos/vyos.go
    registry/registry.go
    deploy/deploy.go
    exec/exec.go  wait/wait.go  log/log.go
  templates/
    fabric.clab.yml.tmpl
    vyos/{edge.set.tmpl,switch.set.tmpl}
    talos/{cluster-patch.yaml.tmpl,node-patch.yaml.tmpl,bgp-peer.yaml.tmpl}
    k8s/cilium-values.yaml.tmpl
  topology/fabric.go              # orchestration (Render/Up/Down/Test/Deploy)
  lab.yaml                        # default config (3 clusters, 1 node each)
  livetest/*_test.go              # //go:build live
  build/                          # gitignored
test/images/
  talos/{container/Dockerfile,scripts/extract-rootfs.sh,versions.env}
  tayga/{Dockerfile,entrypoint.sh}
  vyos/{clab/Dockerfile,clab/*,scripts/{fetch-iso.sh,extract-rootfs.sh},versions.env}
Makefile                          # + lab-images / image-{talos,tayga,vyos}
flake.nix                         # + squashfs-tools-ng, libarchive, talosctl
```

---

## Phase 0 — Module scaffold + typed config

### Task 1: Go module + cobra skeleton

**Files:**
- Create: `test/lab/go.mod`, `test/lab/main.go`, `test/lab/cmd/root.go`, `test/lab/.gitignore`
- Modify: `go.work`

- [ ] **Step 1: Create the module + root command**

`test/lab/go.mod`:
```
module github.com/trevex/ectobase/test/lab

go 1.26.0

require (
	github.com/Masterminds/sprig/v3 v3.3.0
	github.com/spf13/cobra v1.8.1
)
```

`test/lab/main.go`:
```go
package main

import "github.com/trevex/ectobase/test/lab/cmd"

func main() { cmd.Execute() }
```

`test/lab/cmd/root.go`:
```go
// Package cmd is the `lab` CLI: it stands up a multi-cluster Talos IPv6-BGP
// fabric on containerlab and deploys the ectobase substrate onto it.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var cfgPath string

var rootCmd = &cobra.Command{
	Use:   "lab",
	Short: "ectobase Talos fabric lab harness",
	// Every subprocess (render, tests) reads $LAB_CONFIG; set it from --config once here.
	PersistentPreRunE: func(*cobra.Command, []string) error {
		abs, err := absConfig(cfgPath)
		if err != nil {
			return err
		}
		return os.Setenv("LAB_CONFIG", abs)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", defaultConfigPath(), "path to lab.yaml (or $LAB_CONFIG)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
```

`test/lab/cmd/config_path.go`:
```go
package cmd

import (
	"os"
	"path/filepath"
)

// defaultConfigPath resolves $LAB_CONFIG, else ./test/lab/lab.yaml, else ./lab.yaml.
func defaultConfigPath() string {
	if v := os.Getenv("LAB_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat("test/lab/lab.yaml"); err == nil {
		return "test/lab/lab.yaml"
	}
	return "lab.yaml"
}

func absConfig(p string) (string, error) { return filepath.Abs(p) }
```

`test/lab/.gitignore`:
```
build/
```

- [ ] **Step 2: Add to the workspace + tidy**

Add `./test/lab` to the `use (...)` block in `go.work`. Then:
Run: `nix develop --command bash -c 'cd test/lab && go mod tidy && go build ./... && go run . --help'`
Expected: builds; `--help` prints the `lab` usage with the `--config` flag.

- [ ] **Step 3: Commit**
```bash
git add test/lab go.work && git commit -m "feat(lab): cobra skeleton + module scaffold"
```

### Task 2: Config types + Load + Validate (TDD)

**Files:**
- Create: `test/lab/internal/config/config.go`, `validate.go`, `config_test.go`

- [ ] **Step 1: Write the failing test**

`test/lab/internal/config/config_test.go`:
```go
package config

import "testing"

func TestLoadValid(t *testing.T) {
	c, err := LoadBytes([]byte(`
name: ectobase
images: {talos: t, vyos: v, tayga: g, registry: registry:2}
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  nat64Prefix: 64:ff9b::/96
  registry: {upstreams: [docker.io], push: [flowplane]}
  clusters:
    - {name: central, nodes: 1}
    - {name: k02, nodes: 2}
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Name != "ectobase" || len(c.Fabric.Clusters) != 2 || c.Fabric.Clusters[1].Nodes != 2 {
		t.Fatalf("parsed wrong: %+v", c)
	}
	if c.TotalNodes() != 3 {
		t.Fatalf("total nodes = %d, want 3", c.TotalNodes())
	}
}

func TestValidateRejects(t *testing.T) {
	for _, tc := range []string{
		`name: x` + "\n" + `fabric: {as: {edge: 0, switch: 1, host: 2}, clusters: [{name: a, nodes: 1}]}`,       // edge ASN 0
		`name: x` + "\n" + `fabric: {as: {edge: 1, switch: 1, host: 1}, clusters: [{name: a, nodes: 99}]}`,      // nodes > 15
		`name: x` + "\n" + `fabric: {as: {edge: 1, switch: 1, host: 1}, clusters: [{name: a, nodes: 1},{name: a, nodes: 1}]}`, // dup name
	} {
		if _, err := LoadBytes([]byte(tc)); err == nil {
			t.Fatalf("expected error for %q", tc)
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/config/ 2>&1 | tail -5'`
Expected: FAIL (undefined `LoadBytes`).

- [ ] **Step 3: Implement config + validate**

`test/lab/internal/config/config.go`:
```go
// Package config loads and validates the lab.yaml, and derives per-cluster IPv6
// prefixes so parallel clusters on one fabric never collide.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Name   string            `yaml:"name"`
	Images map[string]string `yaml:"images"`
	Fabric Fabric            `yaml:"fabric"`
}

type Fabric struct {
	AS          ASConfig  `yaml:"as"`
	NAT64Prefix string    `yaml:"nat64Prefix"`
	Registry    Registry  `yaml:"registry"`
	Clusters    []Cluster `yaml:"clusters"`
}

type ASConfig struct {
	Edge   int `yaml:"edge"`
	Switch int `yaml:"switch"`
	Host   int `yaml:"host"`
}

type Registry struct {
	Upstreams []string `yaml:"upstreams"`
	Push      []string `yaml:"push"`
}

type Cluster struct {
	Name  string `yaml:"name"`
	Nodes int    `yaml:"nodes"`
}

// TotalNodes is the sum of node counts across all clusters (switch host-port count).
func (c *Config) TotalNodes() int {
	n := 0
	for _, cl := range c.Fabric.Clusters {
		n += cl.Nodes
	}
	return n
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return LoadBytes(b)
}

func LoadBytes(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true) // reject typos in the envelope
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse lab.yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.derive()
	return &c, nil
}
```

`test/lab/internal/config/bytes.go`:
```go
package config

import (
	"bytes"
	"io"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
```

`test/lab/internal/config/validate.go`:
```go
package config

import (
	"fmt"
	"net/netip"
)

func (c *Config) validate() error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	for label, as := range map[string]int{"edge": c.Fabric.AS.Edge, "switch": c.Fabric.AS.Switch, "host": c.Fabric.AS.Host} {
		if as <= 0 {
			return fmt.Errorf("fabric.as.%s must be > 0", label)
		}
	}
	if c.Fabric.NAT64Prefix != "" {
		if _, err := netip.ParsePrefix(c.Fabric.NAT64Prefix); err != nil {
			return fmt.Errorf("fabric.nat64Prefix: %w", err)
		}
	}
	if len(c.Fabric.Clusters) == 0 {
		return fmt.Errorf("at least one cluster is required")
	}
	seen := map[string]bool{}
	for _, cl := range c.Fabric.Clusters {
		if cl.Name == "" {
			return fmt.Errorf("cluster name is required")
		}
		if seen[cl.Name] {
			return fmt.Errorf("duplicate cluster name %q", cl.Name)
		}
		seen[cl.Name] = true
		if cl.Nodes < 1 || cl.Nodes > 15 {
			return fmt.Errorf("cluster %q: nodes must be 1..15 (got %d)", cl.Name, cl.Nodes)
		}
	}
	return nil
}
```

- [ ] **Step 4: Add `derive()` stub (implemented in Task 3), run tests**

Add a temporary no-op to `test/lab/internal/config/derive.go`:
```go
package config

func (c *Config) derive() {}
```
Run: `nix develop --command bash -c 'cd test/lab && go get gopkg.in/yaml.v3 && go test ./internal/config/ -run TestLoad -v && go test ./internal/config/ -run TestValidate -v'`
Expected: both PASS.

- [ ] **Step 5: Commit**
```bash
git add test/lab/internal/config test/lab/go.mod test/lab/go.sum && git commit -m "feat(lab): typed config load + validation"
```

### Task 3: Per-cluster / per-node prefix derivation (TDD)

**Files:**
- Modify: `test/lab/internal/config/derive.go`
- Create: `test/lab/internal/config/derive_test.go`

Model (mirrors `icn/sandbox/topologies/fabric/config.go` `deriveNodePrefix`): each cluster gets a stable `/48` from an FNV-1a hash of `name` under `fd00:cafe::/16` → `fd00:cafe:<h>::/48`; node `k` (1-based) identity = `fd00:cafe:<h>::k/128`; cluster API VIP = `fd00:cafe:<h>:1::1/128`; switch RA `/64` for the p-th host port (1-based, across all clusters) = `fd00:db8:0:p::/64`.

- [ ] **Step 1: Write the failing test**

`test/lab/internal/config/derive_test.go`:
```go
package config

import "testing"

func TestDeriveStableAndDistinct(t *testing.T) {
	c, _ := LoadBytes([]byte(`
name: ectobase
fabric:
  as: {edge: 65000, switch: 65010, host: 65100}
  clusters: [{name: central, nodes: 1}, {name: k02, nodes: 1}]
`))
	if c.Derived.Clusters["central"].Prefix48 == c.Derived.Clusters["k02"].Prefix48 {
		t.Fatal("cluster /48s must differ")
	}
	n := c.Derived.Clusters["central"].Nodes[0]
	if n.Identity == "" || n.RA64 == "" || c.Derived.Clusters["central"].APIVip == "" {
		t.Fatalf("derived fields empty: %+v", n)
	}
	// Deterministic: a second load yields the same /48.
	c2, _ := LoadBytes([]byte(`name: ectobase
fabric: {as: {edge: 65000, switch: 65010, host: 65100}, clusters: [{name: central, nodes: 1}]}`))
	if c2.Derived.Clusters["central"].Prefix48 != c.Derived.Clusters["central"].Prefix48 {
		t.Fatal("derivation not deterministic")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/config/ -run TestDerive 2>&1 | tail -5'`
Expected: FAIL (no `Derived` field).

- [ ] **Step 3: Implement derivation** (replace `derive.go`)

`test/lab/internal/config/derive.go`:
```go
package config

import (
	"fmt"
	"hash/fnv"
)

type Derived struct {
	Clusters map[string]DerivedCluster
}

type DerivedCluster struct {
	Prefix48 string // fd00:cafe:<h>::/48
	APIVip   string // fd00:cafe:<h>:1::1/128
	Nodes    []DerivedNode
}

type DerivedNode struct {
	Cluster  string
	Index    int    // 1-based within cluster
	PortSeq  int    // 1-based across ALL clusters (switch host-port index)
	Identity string // fd00:cafe:<h>::<index>/128 (dummy0, GoBGP-advertised)
	RA64     string // fd00:db8:0:<portSeq>::/64 (switch RA on this node's ports)
}

// hash48 maps a cluster name to a stable 16-bit group in fd00:cafe:<h>::/48.
func hash48(name string) uint16 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	v := uint16(h.Sum32())
	if v == 0 {
		v = 1
	}
	return v
}

func (c *Config) derive() {
	c.Derived.Clusters = map[string]DerivedCluster{}
	port := 0
	for _, cl := range c.Fabric.Clusters {
		h := hash48(cl.Name)
		dc := DerivedCluster{
			Prefix48: fmt.Sprintf("fd00:cafe:%x::/48", h),
			APIVip:   fmt.Sprintf("fd00:cafe:%x:1::1/128", h),
		}
		for i := 1; i <= cl.Nodes; i++ {
			port++
			dc.Nodes = append(dc.Nodes, DerivedNode{
				Cluster:  cl.Name,
				Index:    i,
				PortSeq:  port,
				Identity: fmt.Sprintf("fd00:cafe:%x::%d/128", h, i),
				RA64:     fmt.Sprintf("fd00:db8:0:%d::/64", port),
			})
		}
		c.Derived.Clusters[cl.Name] = dc
	}
}
```
Add `Derived Derived` (unexported yaml) to the `Config` struct in `config.go`:
```go
type Config struct {
	Name    string            `yaml:"name"`
	Images  map[string]string `yaml:"images"`
	Fabric  Fabric            `yaml:"fabric"`
	Derived Derived           `yaml:"-"`
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/config/ -v 2>&1 | tail -10'`
Expected: all PASS.

- [ ] **Step 5: Commit**
```bash
git add test/lab/internal/config && git commit -m "feat(lab): deterministic per-cluster/per-node prefix derivation"
```

---

## Phase 1 — Container images + Makefile

> These port `/home/nik/Development/icn/images/{tayga,vyos,talos}` — **container variants only**. Read each reference dir, copy its Dockerfile + scripts into `test/images/<x>/`, apply the noted deltas. Each task's test is "the image builds" (needs internet for ISO/imager the first time).

### Task 4: Tayga NAT64/DNS64 image

**Files:**
- Create: `test/images/tayga/Dockerfile`, `test/images/tayga/entrypoint.sh`
- Modify: `Makefile`

- [ ] **Step 1: Copy the reference verbatim**

Copy `/home/nik/Development/icn/images/tayga/Dockerfile` and `entrypoint.sh` into `test/images/tayga/` unchanged (base `debian:13-slim`; installs `tayga iptables iproute2 iputils-ping procps`; entrypoint renders `/etc/tayga.conf` with `prefix 64:ff9b::/96` + `dynamic-pool $POOL`, brings up `nat64` TUN, adds the prefix+pool routes, and `iptables -t nat -A POSTROUTING -s $POOL -o eth2 -j MASQUERADE`).

- [ ] **Step 2: Add the Makefile target**

Append to `Makefile`:
```makefile
IMG_REPO ?= ghcr.io/trevex/ectobase
.PHONY: image-tayga
image-tayga: ## Build the lab NAT64/DNS64 (tayga) image
	docker build -t $(IMG_REPO)/tayga:latest test/images/tayga
```

- [ ] **Step 3: Build (LIVE)**

Run: `make image-tayga`
Expected: image builds; `docker run --rm --entrypoint sh $(IMG_REPO)/tayga:latest -c 'command -v tayga'` prints a path.

- [ ] **Step 4: Commit**
```bash
git add test/images/tayga Makefile && git commit -m "build(lab): tayga NAT64/DNS64 image (from icn/images)"
```

### Task 5: VyOS clab image

**Files:**
- Create: `test/images/vyos/{clab/Dockerfile, clab/90-clab-addr-gen-mode.conf, clab/clab-lla-ensure.sh, clab/clab-lla-ensure.service, scripts/fetch-iso.sh, scripts/extract-rootfs.sh, versions.env}`
- Modify: `Makefile`, `flake.nix`

- [ ] **Step 1: Copy the reference**

Copy from `/home/nik/Development/icn/images/vyos/`: `clab/*`, `scripts/fetch-iso.sh`, `scripts/extract-rootfs.sh`, `versions.env` (amd64 rolling ISO URL + version) into `test/images/vyos/`. The clab Dockerfile is `FROM scratch` + `ADD rootfs-${TARGETARCH}.tar /` + the EUI-64 `clab-lla-ensure` service + masks getty/auditd/kea. (Skip the arm64 lines in `versions.env` — amd64-only for now.)

- [ ] **Step 2: Add rootfs tooling to the devShell**

In `flake.nix`, add to the devShell `buildInputs`/`packages`: `squashfs-tools-ng` (`sqfs2tar`), `libarchive` (`bsdtar`), `minisign`. (These are what `extract-rootfs.sh`/`fetch-iso.sh` call.)

- [ ] **Step 3: Add the Makefile target**

```makefile
.PHONY: image-vyos
image-vyos: ## Build the lab VyOS (clab) image from the pinned rolling ISO
	cd test/images/vyos && . ./versions.env && \
	  bash scripts/fetch-iso.sh "$$VYOS_ISO_URL" vyos-amd64.iso && \
	  bash scripts/extract-rootfs.sh vyos-amd64.iso rootfs-amd64.tar && \
	  docker build -f clab/Dockerfile -t $(IMG_REPO)/vyos:clab .
```

- [ ] **Step 4: Build (LIVE, needs internet + nix devShell)**

Run: `nix develop --command bash -c 'make image-vyos'`
Expected: fetches ISO, extracts rootfs, builds `$(IMG_REPO)/vyos:clab`.

- [ ] **Step 5: Commit**
```bash
git add test/images/vyos Makefile flake.nix && git commit -m "build(lab): VyOS clab image + rootfs tooling (from icn/images)"
```

### Task 6: Talos container image

**Files:**
- Create: `test/images/talos/{container/Dockerfile, container/in-container, scripts/extract-rootfs.sh, versions.env}`
- Modify: `Makefile`, `flake.nix`

- [ ] **Step 1: Copy the reference**

Copy from `/home/nik/Development/icn/images/talos/`: `container/Dockerfile`, `container/in-container` (= `true`), `scripts/extract-rootfs.sh`, `versions.env` (pin `TALOS_VERSION` + `TALOS_IMAGER_IMAGE`). The Dockerfile is `FROM scratch` + `ADD rootfs-${TARGETARCH}.tar /` + `COPY container/in-container /usr/etc/in-container` + `ENTRYPOINT ["/sbin/init"]`. `extract-rootfs.sh` runs the imager image to get `initramfs.xz`, unpacks (zstd+cpio), `sqfs2tar rootfs.sqsh` → tar (strips modules/firmware).

- [ ] **Step 2: Ensure devShell has talosctl**

In `flake.nix` devShell, add `talosctl` pinned to match `TALOS_VERSION` (icn pins talosctl 1.14.0-beta.0 from a github release; use the same source or nixpkgs `talosctl`). Also `zstd`, `cpio` for extraction.

- [ ] **Step 3: Makefile target**

```makefile
.PHONY: image-talos
image-talos: ## Build the lab Talos container image (rootfs from imager)
	cd test/images/talos && . ./versions.env && \
	  bash scripts/extract-rootfs.sh amd64 && \
	  docker build -f container/Dockerfile -t $(IMG_REPO)/talos:container .

.PHONY: lab-images
lab-images: image-tayga image-vyos image-talos ## Build all lab container images
```

- [ ] **Step 4: Build (LIVE)**

Run: `nix develop --command bash -c 'make image-talos'`
Expected: `$(IMG_REPO)/talos:container` built.

- [ ] **Step 5: Commit**
```bash
git add test/images/talos Makefile flake.nix && git commit -m "build(lab): Talos container image + lab-images target (from icn/images)"
```

**LIVE CHECKPOINT (Phase 1):** `nix develop --command bash -c 'make lab-images'` builds all three images; `docker images | grep -E 'talos:container|vyos:clab|tayga:latest'` shows them.

---

## Phase 2 — Render pipeline + templates

### Task 7: render package (TDD)

**Files:**
- Create: `test/lab/internal/render/render.go`, `render_test.go`

- [ ] **Step 1: Write the failing test**

`test/lab/internal/render/render_test.go`:
```go
package render

import (
	"strings"
	"testing"
)

func TestRenderString(t *testing.T) {
	out, err := String("{{ .Name | upper }}-{{ add 1 2 }}", map[string]any{"Name": "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "LAB-3" {
		t.Fatalf("got %q", out)
	}
}
```

- [ ] **Step 2: Run — FAIL** (`nix develop --command bash -c 'cd test/lab && go test ./internal/render/'`).

- [ ] **Step 3: Implement**

`test/lab/internal/render/render.go`:
```go
// Package render expands sprig templates to strings/files under build/<name>/.
package render

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

func String(tmpl string, data any) (string, error) {
	t, err := template.New("t").Funcs(sprig.TxtFuncMap()).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// File renders templatePath into outPath (creating parent dirs).
func File(templatePath, outPath string, data any) error {
	src, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	out, err := String(string(src), data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(out), 0o644)
}

// BuildDir returns build/<name>.
func BuildDir(name string) string { return filepath.Join("build", name) }
```

- [ ] **Step 4: Run — PASS.** **Step 5: Commit** `git commit -am "feat(lab): sprig render helpers"`.

### Task 8: clab topology template (TDD golden)

**Files:**
- Create: `test/lab/templates/fabric.clab.yml.tmpl`, `test/lab/internal/render/clab_test.go`, `test/lab/testdata/golden/fabric.clab.yml`

- [ ] **Step 1: Write the template**

Adapt `/home/nik/Development/icn/sandbox/topologies/fabric/templates/fabric.clab.yml.tmpl`. Key deltas from the reference:
  - Iterate **clusters × nodes** (not a single cluster): for each `DerivedNode` emit a `talos` node `{{.Cluster}}-{{.Index}}` with `env-files: [talos/{{.Cluster}}-{{.Index}}.env]` + the `/var //run //etc/cni` + `/usr/lib/modules` binds.
  - Switch host-port links use `PortSeq` (`sw1:eth{{add 2 .PortSeq}}`, `sw2:eth{{add 2 .PortSeq}}`).
  - Add a `registry` node (`kind: linux`, image `{{index .Images "registry"}}`) on the WAN segment with a `binds` entry for the persistent cache dir + the pull-through `config.yml` rendered in Task 13.
  - Keep edges/switches/tayga/wan exactly as the reference.

- [ ] **Step 2: Write the golden test**

`clab_test.go` loads `test/lab/lab.yaml` (Task 16 creates it; for now embed the 2-cluster fixture inline), renders `fabric.clab.yml.tmpl`, and compares to `testdata/golden/fabric.clab.yml` (regenerate with `-update`). Assert: N talos nodes present, each switch has `eth{{2+PortSeq}}` links, the `registry` + `wan` + 2 edges + 2 switches + 2 tayga nodes exist.

- [ ] **Step 3: Generate golden + run**

Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/render/ -run Clab -update && go test ./internal/render/ -run Clab -v'`
Expected: PASS. Eyeball `testdata/golden/fabric.clab.yml` for the node/link counts.

- [ ] **Step 4: Commit** `git add test/lab/templates test/lab/internal/render test/lab/testdata && git commit -m "feat(lab): multi-cluster clab topology template + golden"`.

### Task 9: VyOS templates (edges + switches with RA)

**Files:**
- Create: `test/lab/templates/vyos/{edge.set.tmpl,switch.set.tmpl}`, `test/lab/internal/vyos/vyos.go`

- [ ] **Step 1: Adapt the reference templates**

From `icn/sandbox/.../templates/vyos/{edge.set.tmpl,switch.set.tmpl}`:
  - **edge.set.tmpl** (unchanged intent): AS `{{.Fabric.AS.Edge}}`, unnumbered eBGP peer-group to both switches, `default-originate`, advertise `{{.Fabric.NAT64Prefix}}`, DNS64 forwarding on the edge loopback (`fd00:ffff::e1`/`e2`), static route `64:ff9b::/96` via the tayga sidecar.
  - **switch.set.tmpl** (the RA source): AS `{{.Fabric.AS.Switch}}`, peer both edges + **every** `DerivedNode` port (`range` over all clusters' nodes), `as-override` on the host peer-group, and for each node port emit `set service router-advert interface eth{{add 2 .PortSeq}} prefix '{{.RA64}}'` + `name-server 'fd00:ffff::e1'`, plus the RA `/64` static route + BGP `network`.

- [ ] **Step 2: vyos render helper**

`test/lab/internal/vyos/vyos.go` — `RenderBoot(ctx, image, setPath, bootPath)` runs `docker run --rm -i --entrypoint vyos-commands-to-config <image> < setPath > bootPath` and asserts the output contains `system-as` (mirrors `icn/sandbox/pkg/vyos/vyos.go`).

- [ ] **Step 3: Golden test** for both `.set` renders (2-cluster fixture): switch set must contain `router-advert interface eth3` and `eth4` (2 nodes) and `as-override`.

Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/render/ -run Vyos -update && go test ./internal/render/ -run Vyos -v'`
Expected: PASS.

- [ ] **Step 4: Commit** `git commit -am "feat(lab): VyOS edge+switch(RA) templates + boot render"`.

### Task 10: Talos machineconfig templates + gen

**Files:**
- Create: `test/lab/templates/talos/{cluster-patch.yaml.tmpl,node-patch.yaml.tmpl,bgp-peer.yaml.tmpl}`, `test/lab/internal/talos/gen.go`

- [ ] **Step 1: Adapt the reference machine configs**

From `icn/sandbox/topologies/fabric/templates/talos/*` + `pkg/talos/gen.go`, with these ectobase deltas:
  - **cluster-patch** is rendered **per cluster** (own pod/svc subnets derived from the cluster `/48`, own etcd `advertisedSubnets` = the cluster prefix, own API-VIP static pod holding `{{.APIVip}}`). Add a `RegistryConfig` doc: `machine.registries.mirrors` mapping each `{{.Fabric.Registry.Upstreams}}` entry → the registry's fabric address (`http://[<registry-fabric-ip>]:5000`).
  - **No mgmt default route:** in the machine `network` config, set the mgmt interface (`eth0`) with `dhcp: true` but `routes: []` and add `machine.network.interfaces` so no default comes from mgmt; the default arrives via GoBGP/RA. (Verify against Talos `NetworkDefaultActionConfig`/route metrics; the concrete mechanism is a `machine.network.interfaces[eth0].dhcpOptions.routeMetric` high value so the BGP/RA default wins — confirm with `talosctl validate`.)
  - **node-patch** + **bgp-peer** as the reference: `dummy0 {{.Identity}}`, `BGPPeerConfig` advertising `dummy0`+`vip0`, peering both switches at `{{.Fabric.AS.Switch}}`.

- [ ] **Step 2: talos gen**

`gen.go` — port `icn/sandbox/pkg/talos/gen.go`: per cluster `talosctl gen secrets` (persist to `build/<name>/talos/<cluster>-secrets.yaml`), `talosctl gen config <cluster> https://[<apivip>]:6443 --config-patch @cluster.yaml`, docstrip unwanted docs, per node `machineconfig patch` + append bgp-peer, base64 → `build/<name>/talos/<cluster>-<n>.env`, mkdir mounts.

- [ ] **Step 3: Validate (LIVE-lite)**

Run: `nix develop --command bash -c 'cd test/lab && go test ./internal/render/ -run Talos -update' && talosctl validate -m container -c <(sed -n ... one rendered node config)`
Expected: golden renders; `talosctl validate` accepts the machineconfig (fix the mgmt-route/registry-mirror docs until it does).

- [ ] **Step 4: Commit** `git commit -am "feat(lab): per-cluster Talos machineconfig (registry mirror + no-mgmt-default) + gen"`.

### Task 11: Cilium values template

**Files:** Create `test/lab/templates/k8s/cilium-values.yaml.tmpl` (copy `icn/sandbox/.../k8s/cilium-values.yaml.tmpl` verbatim: IPv6-only, vxlan, kube-proxy replacement, KubePrism 7445, cluster-pool IPAM from the cluster pod CIDR, Talos cgroup/securityContext). Golden test. Commit `feat(lab): Cilium IPv6 values template`.

---

## Phase 3 — Lifecycle orchestration

### Task 12: exec / wait / log + clab wrapper

**Files:** Create `test/lab/internal/{exec/exec.go,wait/wait.go,log/log.go,clab/clab.go}`.

- [ ] Port `icn/sandbox/pkg/lab/{exec.go,wait.go,log.go,clab.go}` (Run/Output, WaitFor polling, slog init, `containerlab deploy/destroy -t <topofile>` via `sudo -E` when non-root). Keep signatures small. Build: `go build ./...`. Commit `feat(lab): exec/wait/log + containerlab wrapper`.

### Task 13: registry package (persistent pull-through + push local)

**Files:** Create `test/lab/internal/registry/registry.go`, `test/lab/templates/registry/config.yml.tmpl`.

- [ ] **Step 1:** `config.yml.tmpl` — a `registry:2` config with `proxy` disabled on the primary but per-upstream **proxy remotes** is not native to registry:2 (it proxies ONE upstream). Use the standard pattern: run registry:2 with `REGISTRY_PROXY_REMOTEURL` per upstream is single-upstream; instead configure **one registry per upstream** is heavy. Simpler: render a registry `config.yml` with a persistent `filesystem` rootdirectory (`/var/lib/registry`, bind-mounted to the named volume) and rely on **Talos mirror endpoints with `overridePath`** pointing each upstream at `registry/v2/<upstream-path>` — OR run the CNCF **`distribution` pull-through** once per upstream as sidecar ports. Pick the minimal working option during the LIVE checkpoint; default: registry:2 as a plain registry holding pushed `:dev` images + a second `registry:2` in `proxy` mode for `docker.io` (the highest-volume upstream), extended per-upstream as needed. Document the choice inline.
- [ ] **Step 2:** `registry.go` — `Up(ctx, cfg)`: ensure the named volume `ectobase-lab-registry-cache`; the registry container is a clab node (Task 8) so `Up` here just **pushes local images**: for each `{{.Fabric.Registry.Push}}` name, `docker tag ghcr.io/trevex/ectobase/<name>:dev <registry-host>/<name>:dev && docker push`. `Purge()` removes the volume.
- [ ] **Step 3:** Build + a unit test that `Up` composes the right `docker tag/push` argv (inject a fake exec). Commit `feat(lab): local registry mirror (persistent cache + push local :dev)`.

### Task 14: Talos bootstrap

**Files:** Create `test/lab/internal/talos/bootstrap.go` (port `icn/sandbox/pkg/talos/talos.go` `Bootstrap`, per cluster: `talosctl config endpoint/node`, wait Talos `/version`, `talosctl bootstrap`, wait k8s `/readyz`, `talosctl kubeconfig`). Build. Commit `feat(lab): per-cluster Talos bootstrap`.

### Task 15: k8s helpers (Cilium install)

**Files:** Create `test/lab/internal/deploy/k8s.go` (port `icn/sandbox/pkg/k8s/k8s.go`: `WaitAPIServer`, `HelmInstall` Cilium with the rendered values, `WaitNodesReady`, `AllowSchedulingOnControlPlanes`). Build. Commit `feat(lab): k8s wait + Cilium helm install`.

### Task 16: topology orchestration + `render`/`up`/`down` commands + default lab.yaml

**Files:** Create `test/lab/topology/fabric.go`, `test/lab/cmd/{render,up,down}.go`, `test/lab/lab.yaml`.

- [ ] **Step 1:** `lab.yaml` — the default 3-cluster/1-node config from spec §5 (images `ghcr.io/trevex/ectobase/{talos:container,vyos:clab,tayga:latest}`, `registry: registry:2`, upstreams + push list).
- [ ] **Step 2:** `fabric.go` — `Render(cfg)` (all templates → build/), `Up(cfg)` (render → registry push → clab deploy → per-cluster bootstrap+Cilium → **Deploy** (Task 17)), `Down(cfg, purge)` (clab destroy + rm build/, keep/purge cache). Wire cobra commands to call these with the loaded config.
- [ ] **Step 3 (LIVE CHECKPOINT):** `nix develop --command bash -c 'sudo -E env "PATH=$PATH" go run ./test/lab up'` → all clusters Ready; `go run ./test/lab kubectl central -- get nodes` Ready; a node curls the internet **via the fabric** (`talosctl -n <node> read /proc/net/ipv6_route` shows the default via the fabric, not mgmt) and pulls come from the registry. Iterate on the machineconfig/RA/registry until green. Commit each fix.

---

## Phase 4 — Ectobase deploy + tests

### Task 17: ectobase deploy (last step of `up`)

**Files:** Create `test/lab/internal/deploy/ectobase.go`, `test/lab/cmd/deploy.go`.

- [ ] **Step 1:** Port the Phase-3 kind steps I did live (see `docs/superpowers/specs/2026-08-05-tier2-live-gate-design.md` + git log on `feat/tier2-live-gate`) into Go, driving the **existing** artifacts: on the `central` cluster `kubectl apply -k central/config` (+ patch `-csi-cluster-id` if ceph present — skip for the foundation), apply the net.ectobase.dev + platform APIServices, deploy the reflector; on each compute cluster `helm upgrade --install ectobase deploy/charts/ectobase --set broker.enabled=true --set broker.clusterName=<name> --set apiserverAddress=https://127.0.0.1:6443`; mint the broker central token + create the `broker-central-kubeconfig` secret (quoted bracketed-v6 server); pre-create ClusterPools; wait both pools `Ready` with `nodePrefixes`.
- [ ] **Step 2 (LIVE CHECKPOINT):** `go run ./test/lab up` end-to-end → both compute pools `Ready`; attach two endpoints on different clusters (reuse `hack/multicluster-e2e.sh` `attach_endpoint` logic) → cross-cluster overlay ping passes. Commit fixes.

### Task 18: live connectivity suite

**Files:** Create `test/lab/livetest/{fabric_test.go,egress_test.go,registry_test.go,ectobase_test.go}` (`//go:build live`), `test/lab/cmd/test.go`.

- [ ] Port `icn/sandbox/topologies/fabric/livetest` patterns + add: **egress** (a node reaches `1.1.1.1` via NAT64 `64:ff9b::1.1.1.1` and its default route is the fabric, mgmt has none), **registry** (a pull-through image + a local `:dev` image both serve), **NAT64/DNS64** (dig synthesized AAAA), **ectobase** (both pools Ready + overlay ping). `lab test` runs `go test -tags live ./test/lab/livetest`. LIVE CHECKPOINT: `go run ./test/lab test` passes. Commit `test(lab): live connectivity + egress + registry + ectobase suite`.

### Task 19: docs + final verification

- [ ] Add `test/lab/README.md` (quickstart: `make lab-images && go run ./test/lab up`, the commands, the config, fabric-only-egress + registry-mirror notes). Update the repo README/CONTRIBUTING to point at the new harness (additive; kind/clab still documented).
- [ ] **Final verification:**
  - Unit: `nix develop --command bash -c 'cd test/lab && go test ./...'` green.
  - Existing flows untouched: `make chart-test` green; `git diff --name-only main...HEAD | grep -E '^flowplane/|\.rs$'` empty; central envtests green.
  - Live: `make lab-images && sudo -E go run ./test/lab up && go run ./test/lab test && go run ./test/lab down` clean; a second `up` is faster (warm registry cache).
- [ ] Commit; then run `superpowers:finishing-a-development-branch`.

---

## Self-review notes

- **Spec coverage:** §4 CLI→T1/16/17/18; §5 config→T2/3/16; §6 topology+egress→T8/9/10/16; §7 Talos+registry→T10/13; §8 ectobase→T17; §9 images+Makefile→T4/5/6; §10 testing→T2/3/7-11(unit)+T18(live); §11 success→T16/17/18/19 checkpoints. No gaps.
- **Known open detail (flagged, not a placeholder):** the exact registry-mirror shape (single proxy vs per-upstream) and the exact Talos "no mgmt default" mechanism are resolved at the Task 13/10 LIVE checkpoints against `talosctl validate` + a real pull — the plan says which knobs to turn and how to verify, rather than guessing the final YAML.
