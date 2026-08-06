// Package vyos renders VyOS edge/switch `set`-command configs and converts them
// to config.boot offline via the clab image's vyos-commands-to-config entrypoint.
package vyos

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/trevex/ectobase/test/lab/internal/fabric"
)

// EdgeCtx / SwitchCtx are the per-node template contexts: they embed the shared
// fabric view (for the const accessors + .Nodes) and add the node's ordinal.
type EdgeCtx struct {
	*fabric.View
	Edge int // 1 or 2
}

type SwitchCtx struct {
	*fabric.View
	SW int // 1 or 2
}

// RenderBoot converts a flat `set`-command config into a VyOS config.boot via the
// image's offline vyos-commands-to-config entrypoint (no running node). It runs:
//
//	docker run --rm -i --entrypoint vyos-commands-to-config <image>   (set on stdin)
func RenderBoot(ctx context.Context, image string, set []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--entrypoint", "vyos-commands-to-config", image)
	cmd.Stdin = bytes.NewReader(set)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("vyos-commands-to-config: %w: %s", err, errb.String())
	}
	return out.Bytes(), nil
}
