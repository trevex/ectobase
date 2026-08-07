package fabric

import "testing"

// TestKindRenderAccessors covers the accessors the kind render depends on: the
// registry-mirror host (bracketed v6 host:port, no scheme) and the node uplinks.
func TestKindRenderAccessors(t *testing.T) {
	v := &View{}
	if got, want := v.RegistryHost(), "[fd00:29::5]:5000"; got != want {
		t.Errorf("RegistryHost() = %q, want %q", got, want)
	}
	if got, want := v.NodeUplinks(), "eth1 eth2"; got != want {
		t.Errorf("NodeUplinks() = %q, want %q", got, want)
	}
}
