package routebus

// LbPort is one load-balancer service tuple, shared by the agent (which announces a backed VIP's
// tuples on the PublicPrefix channel and programs them at the edge) and the reflector (which stores
// and relays them verbatim). Proto is the IP protocol NUMBER (6=TCP, 17=UDP), matching the
// dataplane's PortProto — not the CRD's "TCP"/"UDP" string.
type LbPort struct {
	Port  uint32
	Proto uint32
}

// LbPortsEqual reports whether two service-tuple lists are identical, order included. The edge
// treats a port-set change as a VIP re-registration (the dataplane's create_lb rejects a duplicate
// id), so this is the equality that decides whether that teardown is needed.
func LbPortsEqual(a, b []LbPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
