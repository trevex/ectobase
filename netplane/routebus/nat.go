package routebus

// NatBlock is a deterministic egress SNAT block shared by the agent (which
// ANNOUNCES the blocks scheduled to its node) and the reflector (which stores
// and fans them out): overlay SourceIP (in Vni) is SNATed onto
// NatIP:[PortMin,PortMax) and owned by the node at OwnerUnderlay. NAT blocks are
// GLOBAL (not per-VNI): every node learns every block so a return packet that
// lands on the wrong node can re-route to the owner.
type NatBlock struct {
	Vni           uint32
	SourceIP      string
	NatIP         string
	PortMin       uint32
	PortMax       uint32
	OwnerUnderlay string
}
