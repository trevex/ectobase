# ironcore-net-xdp — common workflows.
#
# Run these from inside the flake devShell (`nix develop`), which provides all tooling — the Rust
# toolchain (rustup), bpf-linker, protobuf, python3+scapy+pytest, qemu,
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

KINDNODE_IMAGE ?= ghcr.io/trevex/ectobase/kind-node-fabric
.PHONY: image-kindnode
image-kindnode: ## Build the fabric kind-node image (node-IP = pre-kubelet BGP /64)
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) \
		-t $(KINDNODE_IMAGE):$(TAG) hack/kind-fabric-node

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
verifier: ## Load both XDP programs through the kernel verifier (needs root)
	cargo test -p flowplane both_programs_pass_verifier -- --ignored

.PHONY: sim
sim: ## Fast in-process datapath tests (no root, no clab): pure-core + native sim
	cargo test -p flowplane-core -p flowplane-sim

.PHONY: sim-anchor
sim-anchor: ## Privileged BPF_PROG_TEST_RUN byte-parity anchor (native pure-core vs real bytecode)
	cargo build -p flowplane
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_uplink -- --ignored --exact uplink_rx_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_lb -- --ignored --exact uplink_rx_lb_deliver_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_guest_tx -- --ignored --exact guest_tx_snat_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_guest_tx -- --ignored --exact guest_tx_bytecode_matches_original_golden
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dnat -- --ignored --exact dnat_return_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dnat -- --ignored --exact dnat_return_bytecode_matches_original_golden
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_arp_nd -- --ignored --exact arp_nd_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_arp_nd -- --ignored --exact arp_nd_bytecode_matches_original_golden
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dhcp -- --ignored --exact dhcp_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dhcp -- --ignored --exact dhcp_bytecode_matches_original_golden
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_nat64 -- --ignored --exact nat64_egress_bytecode_matches_native_sim
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_nat64 -- --ignored --exact nat64_egress_bytecode_matches_original_golden

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
.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
	rm -rf result
