// Copyright 2026 ectobase contributors
// SPDX-License-Identifier: Apache-2.0

// Package allocator implements the (public-IP, port-block) egress SNAT allocator.
// Each source is handed a disjoint, fixed-size port block on one of the gateway's
// public IPs.
//
// Stability is the control-plane fact that makes the datapath drain-safe: an
// existing source must ALWAYS keep its block so its live flows are never re-NATed.
// The previous positional scheme (assign in sorted order, block = rank×size) broke
// this — inserting a lower-sorting source shifted every later source's block. Now
// the allocator is seeded from the persisted NATGateway.Status (Preassign): existing
// sources keep their block regardless of what else is added or removed, and only NEW
// sources are handed the lowest free block. The Status is the source of truth (we no
// longer require stateless recomputation / metalnet-style determinism).
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
// The block space is a flat sequence: block index N maps to public IP
// N/blocksPerIP and, within that IP, the (N%blocksPerIP)'th port block starting
// at firstUsablePort. `used` tracks occupied indices; `assigned` keeps every
// source's block. Seed existing sources with Preassign (from the persisted
// Status) BEFORE assigning new ones, so existing blocks are never disturbed.
type Allocator struct {
	ips         []string
	size        int32
	blocksPerIP int32
	used        map[int32]bool
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
		used:        make(map[int32]bool),
		assigned:    make(map[string]Block),
	}
}

// total is the number of blocks across the whole pool.
func (a *Allocator) total() int32 { return int32(len(a.ips)) * a.blocksPerIP }

// blockToIndex reverse-maps a (publicIP, portMin) block to its flat index, or
// false if the IP is no longer in the pool or the port is unaligned/out of range
// (e.g. the pool shrank or the block size changed — the source is then treated as
// new and re-allocated).
func (a *Allocator) blockToIndex(b Block) (int32, bool) {
	if a.blocksPerIP == 0 || a.size == 0 {
		return 0, false
	}
	ipIdx := int32(-1)
	for i, ip := range a.ips {
		if ip == b.PublicIP {
			ipIdx = int32(i)
			break
		}
	}
	if ipIdx < 0 {
		return 0, false
	}
	off := b.PortMin - firstUsablePort
	if off < 0 || off%a.size != 0 {
		return 0, false
	}
	blockInIP := off / a.size
	if blockInIP >= a.blocksPerIP {
		return 0, false
	}
	return ipIdx*a.blocksPerIP + blockInIP, true
}

// blockAt materializes the Block for a flat index.
func (a *Allocator) blockAt(idx int32) Block {
	portMin := firstUsablePort + (idx%a.blocksPerIP)*a.size
	return Block{
		PublicIP: a.ips[idx/a.blocksPerIP],
		PortMin:  portMin,
		PortMax:  portMin + a.size - 1,
	}
}

// Preassign seeds an existing source's block (read from NATGateway.Status) so a
// subsequent Assign returns it unchanged and no new source can take its slot.
// Invalid blocks (IP dropped from the pool, unaligned port, or a slot already
// taken by an earlier Preassign) are ignored; that source is then treated as new.
func (a *Allocator) Preassign(source string, b Block) {
	idx, ok := a.blockToIndex(b)
	if !ok || a.used[idx] {
		return
	}
	a.used[idx] = true
	a.assigned[source] = a.blockAt(idx)
}

// Assign returns the block for a source. An already-assigned source (incl. one
// seeded via Preassign) always returns its existing block — stable regardless of
// what other sources are added or removed. A new source is handed the LOWEST free
// block. When the whole pool is exhausted the last block is reused as an overflow
// fallback (size the pool for the expected source count to avoid this).
func (a *Allocator) Assign(source string) Block {
	if b, ok := a.assigned[source]; ok {
		return b
	}
	total := a.total()
	if total == 0 {
		var ip string
		if len(a.ips) > 0 {
			ip = a.ips[0]
		}
		return Block{PublicIP: ip}
	}
	idx := int32(-1)
	for i := range total {
		if !a.used[i] {
			idx = i
			break
		}
	}
	if idx < 0 {
		idx = total - 1 // pool exhausted: overflow fallback (do not mark used)
		return a.blockAt(idx)
	}
	a.used[idx] = true
	b := a.blockAt(idx)
	a.assigned[source] = b
	return b
}
