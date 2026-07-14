// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package allocator implements the deterministic (public-IP, port-block) egress
// SNAT allocator. Each source is handed a disjoint, fixed-size port block on one
// of the gateway's public IPs. Assignments are stable (an existing source always
// gets the same block) and spill across the public-IP pool as blocks are used up.
// This determinism is the control-plane fact that makes the datapath drain-safe:
// any gateway can recompute a source's block without shared state.
package allocator

// firstUsablePort is the lowest port a block may start at. Ports below 1024 are
// reserved (well-known) and never handed out to a source.
const firstUsablePort = 1024

// lastUsablePort is the highest port a block may cover.
const lastUsablePort = 65535

// Block is a deterministic (public-IP, port-range) SNAT assignment for a source.
type Block struct {
	PublicIP string
	PortMin  int32
	PortMax  int32
}

// Allocator hands out disjoint, stable port blocks across a pool of public IPs.
//
// The block space is a flat, monotonically-increasing sequence: block index N
// maps to public IP N/blocksPerIP and, within that IP, the (N%blocksPerIP)'th
// port block starting at firstUsablePort. A cursor tracks the next free index;
// a source→Block map keeps existing assignments stable.
type Allocator struct {
	ips         []string
	size        int32
	blocksPerIP int32
	cursor      int32
	assigned    map[string]Block
}

// New builds an allocator over the given ordered public-IP pool, handing each
// source a block of `size` ports. Blocks start at firstUsablePort on each IP.
func New(ips []string, size int32) *Allocator {
	var blocksPerIP int32
	if size > 0 {
		blocksPerIP = (lastUsablePort - firstUsablePort + 1) / size
	}
	return &Allocator{
		ips:         ips,
		size:        size,
		blocksPerIP: blocksPerIP,
		assigned:    make(map[string]Block),
	}
}

// Assign returns the deterministic block for a source. An already-assigned
// source always returns its existing block (stable). A new source is handed the
// next free block, spilling to the next public IP when the current one's blocks
// are exhausted. When the whole pool is exhausted the last block is reused as an
// overflow fallback (callers relying on strict disjointness should size the pool
// for the expected source count).
func (a *Allocator) Assign(source string) Block {
	if b, ok := a.assigned[source]; ok {
		return b
	}

	idx := a.cursor
	total := int32(len(a.ips)) * a.blocksPerIP
	if a.blocksPerIP == 0 || total == 0 {
		// No usable capacity; return a zero-value block on the first IP (if any).
		var ip string
		if len(a.ips) > 0 {
			ip = a.ips[0]
		}
		return Block{PublicIP: ip}
	}
	if idx >= total {
		// Pool exhausted: reuse the last block as an overflow fallback.
		idx = total - 1
	} else {
		a.cursor++
	}

	ipIdx := idx / a.blocksPerIP
	blockInIP := idx % a.blocksPerIP
	portMin := firstUsablePort + blockInIP*a.size
	b := Block{
		PublicIP: a.ips[ipIdx],
		PortMin:  portMin,
		PortMax:  portMin + a.size - 1,
	}
	a.assigned[source] = b
	return b
}
