package exec

import (
	"context"
	"os"
	"os/exec"
)

// Sudo runs a command as root: directly when the process is already root (e.g. a
// CI shell runner), else via non-interactive sudo (`sudo -n`), so a missing sudo
// timestamp fails fast with a clear *ExecError instead of blocking on a password
// prompt mid-deploy. Preflight verifies `sudo -n true` up front (skipped when
// already root); this is the belt-and-suspenders so no call can ever hang.
func Sudo(ctx context.Context, args ...string) error {
	if os.Geteuid() == 0 {
		return Run(ctx, args[0], args[1:]...)
	}
	return Run(ctx, "sudo", append([]string{"-n"}, args...)...)
}

// SudoCmd builds (does not run) an *exec.Cmd that runs args as root — directly when
// already root, else via `sudo -n` — so callers can Start/Wait a long-lived process
// (e.g. a background packet sniff). Mirrors Sudo's privilege handling.
func SudoCmd(ctx context.Context, args ...string) *exec.Cmd {
	if os.Geteuid() == 0 {
		return exec.CommandContext(ctx, args[0], args[1:]...)
	}
	return exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...)
}

// SudoStdin is Sudo feeding stdin (for `nft -f -`).
func SudoStdin(ctx context.Context, stdin string, args ...string) error {
	if os.Geteuid() == 0 {
		return runStdin(ctx, stdin, args[0], args[1:]...)
	}
	return runStdin(ctx, stdin, "sudo", append([]string{"-n"}, args...)...)
}

// SudoOutput is Sudo returning stdout (for `nsenter … ip -j …`).
func SudoOutput(ctx context.Context, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return Output(ctx, args[0], args[1:]...)
	}
	return Output(ctx, "sudo", append([]string{"-n"}, args...)...)
}
