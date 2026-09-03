// Package frr holds the per-role template contexts for the fabric FRR configs
// (edge + switch). Unlike VyOS, FRR consumes frr.conf verbatim, so there is no
// offline compile step — Render writes the rendered frr.conf straight to the build
// tree and clab bind-mounts it at /etc/frr/frr.conf.
package frr

import "github.com/trevex/ectobase/test/lab/internal/fabric"

// EdgeCtx / SwitchCtx embed the shared fabric view (const accessors + .Nodes) and
// add the node ordinal.
type EdgeCtx struct {
	*fabric.View
	Edge int // 1 or 2
}

type SwitchCtx struct {
	*fabric.View
	SW int // 1 or 2
}
