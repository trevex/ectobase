// Package vyos holds the per-role template contexts for the fabric VyOS
// configs (edge + switch) and the wrapper that turns the rendered `set ...`
// commands into the vbash bootup script the VyOS clab image executes.
//
// Unlike FRR (which consumes frr.conf verbatim), the revived VyOS clab image
// (test/images/vyos) boots a real VyOS rootfs: config.boot itself is loaded
// via the native curly-brace hierarchical grammar, but
// /opt/vyatta/etc/config/scripts/vyos-postconfig-bootup.script runs on every
// boot as a vbash script — source the CLI's script-template, `configure`,
// apply flat `set ...` commands, `commit`. Binding our rendered .set file at
// that path (see templates/fabric.clab.yml.tmpl) applies the whole role's
// config live on every boot; config.boot stays the image's stock default.
package vyos

import "github.com/trevex/ectobase/test/lab/internal/fabric"

// EdgeCtx / SwitchCtx embed the shared fabric view (const accessors + .Nodes)
// and add the node ordinal, mirroring internal/frr's EdgeCtx/SwitchCtx.
type EdgeCtx struct {
	*fabric.View
	Edge int // 1 or 2
}

type SwitchCtx struct {
	*fabric.View
	SW int // 1 or 2
	// Resolver1/2 are the two edge-loopback DNS64 resolvers (== the Talos
	// ResolverConfig / cluster-patch .Resolver1/.Resolver2), announced as RDNSS on
	// the switch's node-facing router-advert links so a node's egress DNS survives
	// on the RA path alone, independent of the static ResolverConfig doc.
	Resolver1, Resolver2 string
}

// Wrap turns a rendered body of `set ...` commands (blank lines and `#`
// comments allowed — vbash is a real shell) into the vbash postconfig-bootup
// script the VyOS clab image runs at boot. Verified against the image's real
// boot process (test/images/vyos, VyOS rolling/"sagitta"): a script at
// /opt/vyatta/etc/config/scripts/vyos-postconfig-bootup.script survives the
// container's own tmpfs remount of /opt/vyatta/etc/config and runs on every
// boot; `exit` here is script-template's alias that tears down the config
// session, not a process exit.
func Wrap(body string) string {
	return "#!/bin/vbash\n" +
		"source /opt/vyatta/etc/functions/script-template\n" +
		"configure\n" +
		body +
		"commit\n" +
		"exit\n"
}
