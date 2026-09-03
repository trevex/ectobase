# ironcore-net-xdp — common workflows.
#
# Run these from inside the flake devShell (`nix develop`), which provides all tooling — the Rust
# toolchain (rustup), bpf-linker, protobuf, python3, qemu,
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
docs: ## Build the mkdocs site (strict: broken links/nav fail the build)
	mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Serve the docs locally with live reload
	mkdocs serve

.PHONY: docs-crd-ref
docs-crd-ref: ## Generate the per-group CRD API reference (crd-ref-docs)
	@for g in net compute storage compiled platform; do \
	  echo "crd-ref-docs -> docs/reference/api/$$g.md"; \
	  crd-ref-docs --source-path=api/$$g/v1alpha1 --config=crd-ref-docs.yaml \
	    --renderer=markdown --output-path=docs/reference/api/$$g.md ; \
	done

.PHONY: generate
generate: ## Regenerate deepcopy/conversion (kube::codegen) + CRD manifests (controller-gen)
	cd api && ./hack/update-codegen.sh
	cd dispatch && ./hack/update-codegen.sh
	# CRDs: pool chart ships net + compiled; compute/storage/platform are dispatch-aggregated
	# (served by the dispatch apiserver, shipped in no chart) and generated to test/crds for envtest.
	cd api && controller-gen crd paths=./net/v1alpha1/... output:crd:artifacts:config=../charts/ectobase-pool/crd-bases
	cd api && controller-gen crd paths=./compiled/v1alpha1/... output:crd:artifacts:config=../charts/ectobase-pool/crd-bases
	cd api && controller-gen crd paths=./compute/v1alpha1/... output:crd:artifacts:config=../test/crds
	cd api && controller-gen crd paths=./storage/v1alpha1/... output:crd:artifacts:config=../test/crds
	cd api && controller-gen crd paths=./platform/v1alpha1/... output:crd:artifacts:config=../test/crds
	# RBAC: one ClusterRole rules file per component into each chart's files/<role>/.
	cd mesh && controller-gen rbac:roleName=mesh-controller paths=./cmd/controller/... output:rbac:artifacts:config=../charts/ectobase-dispatch/files/mesh-controller
	cd mesh && controller-gen rbac:roleName=mesh-agent paths=./cmd/agent/... output:rbac:artifacts:config=../charts/ectobase-pool/files/mesh-agent
	cd mesh && controller-gen rbac:roleName=vm-materializer paths=./cmd/vm-materializer/... output:rbac:artifacts:config=../charts/ectobase-pool/files/vm-materializer
	cd mesh && controller-gen rbac:roleName=pod-materializer paths=./cmd/pod-materializer/... output:rbac:artifacts:config=../charts/ectobase-pool/files/pod-materializer
	cd cni && controller-gen rbac:roleName=flowplane-cni paths=./... output:rbac:artifacts:config=../charts/ectobase-pool/files/flowplane-cni
	cd dispatch && controller-gen rbac:roleName=dispatch-controller paths=./cmd/controller/... output:rbac:artifacts:config=../charts/ectobase-dispatch/files/dispatch-controller
	cd dispatch && controller-gen rbac:roleName=dispatch-broker paths=./cmd/broker/rbac/dispatchside/... output:rbac:artifacts:config=../charts/ectobase-dispatch/files/dispatch-broker
	cd dispatch && controller-gen rbac:roleName=dispatch-broker paths=./cmd/broker/rbac/poolside/... output:rbac:artifacts:config=../charts/ectobase-pool/files/dispatch-broker
	# Docs: regenerate the per-group CRD API reference so it never drifts from the types.
	$(MAKE) docs-crd-ref

.PHONY: proto-go
proto-go: ## Generate Go gRPC stubs for dataplane.v1 into cni/gen/dataplanev1
	protoc -I api/proto/dataplane/v1 \
		--go_out=cni/gen --go_opt=module=github.com/trevex/ectobase/cni/gen \
		--go-grpc_out=cni/gen --go-grpc_opt=module=github.com/trevex/ectobase/cni/gen \
		api/proto/dataplane/v1/dataplane.proto

.PHONY: proto-routebus
proto-routebus: ## Generate Go gRPC stubs for routebus.v1 into mesh/gen/routebusv1
	protoc -I api/proto/routebus/v1 \
		--go_out=mesh/gen --go_opt=module=github.com/trevex/ectobase/mesh/gen \
		--go-grpc_out=mesh/gen --go-grpc_opt=module=github.com/trevex/ectobase/mesh/gen \
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

MESH_IMAGE ?= ghcr.io/trevex/ectobase/mesh
.PHONY: image-mesh
image-mesh: ## Build the mesh (reflector+agent) image
	docker build $(if $(DOCKER_BUILD_NET),--network=$(DOCKER_BUILD_NET)) -f Dockerfile.mesh -t $(MESH_IMAGE):$(TAG) .

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
lab-images: image-kindnode image-tayga image-wan ## Build all test/lab container images

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
verifier: ## Load the tcx overlay-ingress + guest-facing tc programs through the kernel verifier (needs root)
	# verify_edge_wan_rx covers the tcx overlay-ingress trio (uplink_rx / xdp_uplink_v6 / wan_rx —
	# all XDP pre-P2-Task-4b); verify_tc_guest covers the guest-facing tc classifiers (tc_guest_tx /
	# tc_guest_nat64 / tc_guest_dhcp / tc_guest_egress_v6). Between them this is what catches
	# stack/verifier regressions (e.g. an over-budget subprogram) across the whole eBPF datapath.
	sudo -E $$(command -v cargo) test -p flowplane --test verify_edge_wan_rx -- --ignored
	sudo -E $$(command -v cargo) test -p flowplane --test verify_tc_guest -- --ignored

.PHONY: sim
sim: ## Fast in-process datapath tests (no root, no clab): pure-core + native sim
	cargo test -p flowplane-core -p flowplane-sim

.PHONY: sim-anchor
sim-anchor: verifier ## Privileged BPF_PROG_TEST_RUN byte-parity anchors (native pure-core vs real bytecode)
	cargo build -p flowplane
	# Each anchor runs the REAL compiled program via BPF_PROG_TEST_RUN. Post-P2 Geneve retarget
	# (Task 7): `uplink_rx`'s decap-side `get_tunnel_key` has no BPF_PROG_TEST_RUN oracle (a fresh
	# test skb carries no tunnel-key metadata — see anchor_uplink.rs's module doc), so
	# anchor_uplink/anchor_lb/anchor_dnat now assert the real bytecode fails SAFE (TC_ACT_OK,
	# packet unchanged) ahead of that gate, with the delivery-target/DNAT/LB logic itself covered
	# bytecode-free by `flowplane-sim` (ns_scenario_test / lb_scenario_test / nat_test). The encap
	# side (anchor_guest_tx) still proves real bytecode: TC_ACT_REDIRECT + inner-unchanged, byte-
	# identical to the native sim. One `--test` binary per datapath; `--ignored` runs its anchor(s).
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_uplink -- --ignored    # uplink_rx fails safe (base N-S)
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_lb -- --ignored         # uplink_rx fails safe (LB local-deliver)
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_dnat -- --ignored       # uplink_rx fails safe (DNAT return)
	sudo -E $$(command -v cargo) test -p flowplane --test anchor_guest_tx -- --ignored   # tc_guest_tx encap: redirect + inner-unchanged
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
.PHONY: bpf-clean
bpf-clean: ## Free leaked flowplane BPF pins (host + kind/clab nodes); prevents conntrack-map OOM across clab cycles
	./hack/bpf-cleanup.sh

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean
	rm -rf result

.PHONY: chart-test
chart-test: ## Run the Helm chart unit tests (helm-unittest) for both charts.
	helm unittest charts/ectobase-dispatch charts/ectobase-pool
