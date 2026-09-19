package routebus

// NatBlock is a deterministic egress SNAT block shared by the agent (which
// ANNOUNCES the blocks scheduled to its node) and the reflector (which stores
// and fans them out): overlay SourceIP (in Vni) is SNATed onto
// NatIP:[PortMin,PortMax) and owned by the node at OwnerUnderlay. Blocks travel on the GLOBAL
// channel (not per-VNI): every session that TAKES that feed learns every block, so a return packet
// landing on it can re-route to the owner. Only WAN edges take it; every node still announces its
// own blocks.
type NatBlock struct {
	Vni           uint32
	SourceIP      string
	NatIP         string
	PortMin       uint32
	PortMax       uint32
	OwnerUnderlay string
}
