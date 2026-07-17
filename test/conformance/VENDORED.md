vendored from ironcore-dev/dpservice test/local @ v0.3.22

Source: https://github.com/ironcore-dev/dpservice/tree/v0.3.22/test/local
Commit: 0eb5acbd262ba4b8e6ae2762352a27924e44f990

Adapted for flowplane:
- config.py: .pci overrides point to xdp-side veth names (xdtapN / xdtapvf_N)
- dp_service.py: DpService.__init__ builds `flowplane serve` command instead of dpservice-bin
- grpc_client.py: self.cmd uses local bin/dpservice-cli built from source
- setup-net.sh: veth topology + xdp_pass enablers (NEW)
- run.sh: build / net-up / pytest orchestrator (NEW)
- bin/dpservice-cli: built from dpservice v0.3.22 cli/dpservice-cli (gitignored)
