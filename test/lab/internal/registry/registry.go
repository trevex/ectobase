// Package registry manages the lab's local image mirror: a persistent pull-through
// + push-local registry backed by a host directory under build/<name>/ that
// survives down/up. The registry container is wired into the topology at `lab up`
// (T16); this package owns the cache-dir lifecycle and the push-local step. A host
// directory (not a named docker volume) is used because clab binds cannot name
// docker volumes — the clab template binds `registry-cache:/var/lib/registry`
// relative to the topology file, so the dir name must match CacheDirName.
package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// CacheDirName is the registry cache directory, relative to build/<name>/. It
// matches the clab template bind `registry-cache:/var/lib/registry`. The dir
// survives `down` and is only removed by `down --purge` (PurgeCache).
const CacheDirName = "registry-cache"

// LocalRepo is the ghcr namespace the lab's :dev images live under.
const LocalRepo = "ghcr.io/trevex/ectobase"

// MirrorPath is LocalRepo with the ghcr.io registry host stripped. The Talos
// mirror endpoints carry no overridePath, so containerd requests the FULL
// original repository path from the mirror (e.g. pulling
// ghcr.io/trevex/ectobase/flowplane:dev becomes GET
// /v2/trevex/ectobase/flowplane/manifests/dev). Pushes must therefore land under
// this same path or the node pull 404s.
const MirrorPath = "trevex/ectobase"

// Runner runs a command; injectable so tests can capture the docker argv.
type Runner func(ctx context.Context, name string, args ...string) error

// Registry pushes local :dev images into (and manages the cache for) the in-fabric
// mirror. Host is the docker-reachable address of the registry:2 process — pushes
// go via the host-published localhost port "127.0.0.1:5000" (docker-default-
// insecure), while nodes pull from the same process via its fabric addr.
type Registry struct {
	Host string
	Run  Runner
}

// New returns a Registry driving the real docker CLI via exec.Run.
func New(host string) *Registry { return &Registry{Host: host, Run: exec.Run} }

// EnsureCache creates the persistent cache directory under buildDir (idempotent).
func EnsureCache(ctx context.Context, buildDir string) error {
	return os.MkdirAll(filepath.Join(buildDir, CacheDirName), 0o755)
}

// PurgeCache removes the cache directory under buildDir (for `lab down --purge`).
func PurgeCache(buildDir string) error {
	return os.RemoveAll(filepath.Join(buildDir, CacheDirName))
}

// PushLocal tags each ghcr.io/trevex/ectobase/<name>:dev to the in-fabric mirror
// and pushes it, so nodes pull the local images from the fabric. The destination
// repo path includes MirrorPath (trevex/ectobase/<name>) so it matches the full
// path the Talos mirror forwards to the registry — a bare <name> repo would 404
// on pull (the mirror endpoints carry no overridePath).
func (r *Registry) PushLocal(ctx context.Context, names []string) error {
	for _, n := range names {
		src := fmt.Sprintf("%s/%s:dev", LocalRepo, n)
		dst := fmt.Sprintf("%s/%s/%s:dev", r.Host, MirrorPath, n)
		if err := r.Run(ctx, "docker", "tag", src, dst); err != nil {
			return fmt.Errorf("tag %s: %w", n, err)
		}
		if err := r.Run(ctx, "docker", "push", dst); err != nil {
			return fmt.Errorf("push %s: %w", n, err)
		}
	}
	return nil
}
