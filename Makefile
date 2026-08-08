# ironcore-net-xdp — common workflows.
#
# Run these from inside the flake devShell (`nix develop`), which provides all tooling — the Rust
# toolchain (rustup), bpf-linker, protobuf, python3 (DPDK pyelftools), qemu,
# iproute2, ethtool, tcpdump. The targets use bare tool names; there are no host-specific paths.
#
# The e2e / ha / tap targets need passwordless sudo (XDP attach, netns, raw sockets);
# the scripts elevate individual commands themselves.

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --- build -----------------------------------------------------------------
.PHONY: build
build: ## Build the flowplane binary (host crates + the eBPF object via aya-build)
	cargo build -p flowplane

.PHONY: release
release: ## Build the flowplane binary in release mode
	cargo build -p flowplane --release

.PHONY: docs
docs: ## Build the mdbook documentation into docs/book
	mdbook-mermaid install docs
	mdbook build docs

.PHONY: docs-serve
docs-serve: ## Serve the mdbook docs locally with live reload
	mdbook-mermaid install docs
	mdbook serve docs

.PHONY: generate
generate: ## Regenerate deepcopy/conversion (kube::codegen) + CRD manifests (controller-gen)
	cd api && ./hack/update-codegen.sh
	cd central && ./hack/update-codegen.sh
	cd api && controller-gen crd paths=./net/v1alpha1/... output:crd:artifacts:config=../config/crd/bases
	cd api && controller-gen crd paths=./compiled/v1alpha1/... output:crd:artifacts:config=../config/crd/bases
	cd api && controller-gen crd paths=./compute/v1alpha1/... output:crd:artifacts:config=../config/crd/bases
	cd api && controller-gen crd paths=./storage/v1alpha1/... output:crd:artifacts:config=../config/crd/bases
	cd api && controller-gen crd paths=./platform/v1alpha1/... output:crd:artifacts:config=../central/config/crd
	./hack/sync-chart-crds.sh

.PHONY: proto-go
proto-go: ## Generate Go gRPC stubs for dataplane.v1 into cni/gen/dataplanev1
	protoc -I api/proto/dataplane/v1 \
		--go_out=cni/gen --go_opt=module=github.com/trevex/ectobase/cni/gen \
		--go-grpc_out=cni/gen --go-grpc_opt=module=github.com/trevex/ectobase/cni/gen \
		api/proto/dataplane/v1/dataplane.proto

.PHONY: proto-routebus
proto-routebus: ## Generate Go gRPC stubs for routebus.v1 into netplane/gen/routebusv1
	protoc -I api/proto/routebus/v1 \
		--go_out=netplane/gen --go_opt=module=github.com/trevex/ectobase/netplane/gen \
		--go-grpc_out=netplane/gen --go-grpc_opt=module=github.com/trevex/ectobase/netplane/gen \
		api/proto/routebus/v1/routebus.proto

IMAGE ?= ghcr.io/trevex/ectobase/flowplane
TAG   ?= dev
# The Dockerfile's builder does apt/curl/cargo network I/O. buildkit's default bridge
# network can't resolve the mirrors on some hosts (apt-get exit 100); host networking is
# reliable and harmless for a build. Override with DOCKER_BUILD_NET= to disable.
DOCKER_BUILD_NET ?= host
.PHONY: image
image: ## Build the flowplane container image (self-building Dockerfile; IMAGE/TAG overridable)
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) -t $(IMAGE):$(TAG) .

.PHONY: image-push
image-push: ## Push the flowplane image (needs `docker login ghcr.io`)
	docker push $(IMAGE):$(TAG)

NETPLANE_IMAGE ?= ghcr.io/trevex/ectobase/netplane
.PHONY: image-netplane
image-netplane: ## Build the netplane (reflector+agent) image
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) -f Dockerfile.netplane -t $(NETPLANE_IMAGE):$(TAG) .

CNI_IMAGE ?= ghcr.io/trevex/ectobase/cni
.PHONY: image-cni
image-cni: ## Build the flowplane CNI plugin + installer image
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) -f Dockerfile.cni -t $(CNI_IMAGE):$(TAG) .

KINDNODE_IMAGE ?= ghcr.io/trevex/ectobase/kind-node-fabric
.PHONY: image-kindnode
image-kindnode: ## Build the fabric kind-node image (node-IP = pre-kubelet BGP /64)
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) \
		-t $(KINDNODE_IMAGE):$(TAG) hack/kind-fabric-node

IMG_REPO ?= ghcr.io/trevex/ectobase
.PHONY: image-tayga
image-tayga: ## Build the lab NAT64/DNS64 (tayga) image
	docker build -t $(IMG_REPO)/tayga:latest test/images/tayga

.PHONY: image-vyos
image-vyos: ## Build the lab VyOS (clab) image from the pinned rolling ISO
	cd test/images/vyos && . ./versions.env && \
	  bash scripts/fetch-iso.sh "$$VYOS_ISO_URL" vyos-amd64.iso && \
	  bash scripts/extract-rootfs.sh vyos-amd64.iso rootfs-amd64.tar && \
	  docker build -f clab/Dockerfile -t $(IMG_REPO)/vyos:clab .

.PHONY: image-talos
image-talos: ## Build the lab Talos container image (rootfs from imager)
	cd test/images/talos && . ./versions.env && \
	  bash scripts/extract-rootfs.sh amd64 && \
	  docker build -f container/Dockerfile -t $(IMG_REPO)/talos:container .

.PHONY: image-wan
image-wan: ## Build the lab WAN-sim (nft masquerade + ECMP return) image via nix
	cd test/images/wan && nix build .#default && docker load -i result | tee /dev/stderr | grep -oE 'wan-simulator:latest' >/dev/null
	docker tag wan-simulator:latest $(IMG_REPO)/wan:latest

.PHONY: lab-images
lab-images: image-kindnode image-tayga image-vyos image-wan ## Build all test/lab container images

# --- lab (test/lab kind fabric) --------------------------------------------
# Run the Go lab CLI directly via `go run` (no stray prebuilt binary). The live
# commands drive containerlab + host networking, so they need real root; `sudo -E`
# preserves the env and we re-assert PATH so the devShell tools resolve under sudo.
# Run these from the repo root inside `nix develop`.
LAB      := go run ./test/lab
LAB_ROOT := sudo -E env "PATH=$$PATH" go run ./test/lab

.PHONY: lab-render lab-up lab-down lab-down-purge lab-deploy lab-ceph lab-tier2-up lab-test
lab-render: ## Render the lab build tree (no root)
	$(LAB) render
lab-up: ## Bring up the kind fabric + deploy the ectobase substrate
	$(LAB_ROOT) up
lab-down: ## Tear down the fabric (keeps the registry cache)
	$(LAB_ROOT) down
lab-down-purge: ## Tear down the fabric AND remove the registry cache
	$(LAB_ROOT) down --purge
lab-deploy: ## Re-run only the ectobase substrate deploy on an up fabric
	$(LAB_ROOT) deploy
lab-ceph: ## Deploy Ceph (ceph-csi + csi-addons); needs fabric.ceph.enabled
	$(LAB_ROOT) ceph
lab-tier2-up: ## Deploy the Tier-2 prereqs (KubeVirt + CDI + vm-materializer)
	$(LAB_ROOT) tier2 up
lab-test: ## Run the live lab suite
	$(LAB_ROOT) test

# --- quality ---------------------------------------------------------------
.PHONY: fmt
fmt: ## Format all Rust code
	cargo fmt --all

.PHONY: lint
lint: ## Clippy across all targets (host crates)
	cargo clippy --all-targets

.PHONY: check
check: ## fmt --check + clippy (what the pre-commit hooks run)
	cargo fmt --all -- --check
	cargo clippy --all-targets

# --- tests -----------------------------------------------------------------
.PHONY: test
test: ## Host unit + POD-layout tests (no root needed)
	cargo test -p flowplane-common -p flowplane

.PHONY: verifier
verifier: ## Load the edge XDP + guest-facing tc programs through the kernel verifier (needs root)
	# The main dataplane XDP (uplink_rx) is verifier-loaded by the sim-anchor byte-parity anchors;
	# these two cover the programs those anchors don't exercise: the edge WAN XDP, and all three
	# guest-facing tc classifiers (tc_guest_tx / tc_guest_nat64 / tc_guest_dhcp). verify_tc_guest is
	# what catches tc-datapath stack/verifier regressions (e.g. an over-budget egress subprogram).
	sudo -E $$(command -v cargo) test -p flowplane --test verify_edge_wan_rx -- --ignored
	sudo -E $$(command -v cargo) test -p flowplane --test verify_tc_guest -- --ignored

.PHONY: sim
sim: ## Fast in-process datapath tests (no root, no clab): pure-core + native sim
	cargo test -p flowplane-core -p flowplane-sim

.PHONY: sim-anchor
sim-anchor: verifier ## Privileged BPF_PROG_TEST_RUN byte-parity anchors (native pure-core vs real bytecode)
	cargo build -p flowplane
	# Each anchor runs the REAL compiled program via BPF_PROG_TEST_RUN and asserts its output is
	# byte-identical to the native SimNode for the same input + map state (and loads/verifies the
	# program as a side effect). One `--test` binary per datapath; `--ignored` runs its anchor(s).
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_uplink -- --ignored    # uplink_rx N-S decap+deliver
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_lb -- --ignored         # uplink_rx Maglev LB reforward
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dnat -- --ignored       # dnat return (native + golden)
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_guest_tx -- --ignored   # tc_guest_tx encap + flow-label ECMP
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dhcp -- --ignored       # tc_guest_dhcp DHCPv4 OFFER (native + golden)
	# NOT YET ANCHORED (coverage gaps, tracked separately — do not assume these are covered):
	#   - tc_guest_dhcp DHCPv6 ADVERTISE/REPLY (only the DHCPv4 OFFER is byte-anchored above).
	#   - guest-tx ARP/ND replies and the NAT64 egress/ingress translation have no byte-parity anchor.

.PHONY: e2e
e2e: ## 3-node netns end-to-end overlay test (needs sudo)
	./test/netns-e2e.sh run

.PHONY: ha
ha: ## HA pinned-maps smoke (kill+adopt; needs sudo)
	./test/ha-smoke.sh run

.PHONY: tap-dhcp-probe
tap-dhcp-probe: ## Native-mode DHCP frame-growth fidelity probe on a real tap (needs sudo)
	./test/tap-dhcp-probe.sh

.PHONY: tap-vm-smoke
tap-vm-smoke: ## Boot a CirrOS VM on a real tap and verify guest_tx/ARP (needs sudo + KVM)
	./test/tap-vm-smoke.sh run

.PHONY: test-all
test-all: test e2e ha ## Run the full local test matrix (needs sudo)

# --- housekeeping ----------------------------------------------------------
.PHONY: dpdk-check
dpdk-check: ## Probe host DPDK capability (hugepages/IOMMU/NICs)
	@hack/dpdk/check-host.sh

.PHONY: dpdk-afxdp-loopback
dpdk-afxdp-loopback: ## Run the af_xdp veth loopback e2e (needs sudo + hugepages)
	cargo build -p nfkit --example l2fwd
	sudo L2FWD_BIN=$(PWD)/target/debug/examples/l2fwd hack/dpdk/afxdp-loopback.sh

.PHONY: dpdk-afxdp-datapath
dpdk-afxdp-datapath: ## Run the af_xdp uplink datapath byte-parity e2e (needs sudo; self-manages hugepages)
	sudo -E env "PATH=$$PATH" "LD_LIBRARY_PATH=$${LD_LIBRARY_PATH:-}" \
		cargo test -p nfkit --test afxdp_datapath -- --test-threads=1 --nocapture

.PHONY: bpf-clean
bpf-clean: ## Free leaked flowplane BPF pins (host + kind/clab nodes); prevents conntrack-map OOM across clab cycles
	./hack/bpf-cleanup.sh

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
	rm -rf result

.PHONY: chart-sync-crds
chart-sync-crds: ## Vendor generated CRDs into the Helm chart.
	./hack/sync-chart-crds.sh

.PHONY: chart-test
chart-test: ## Run the Helm chart golden + validation tests.
	./deploy/charts/ectobase/tests/render.sh
