package clab

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// Clab wraps `containerlab` against a single topology file. containerlab needs
// root for netns/veth work, so calls go through `sudo -E containerlab` unless the
// process is already root (e.g. a CI shell runner); override with the CLAB env
// var (space-separated, e.g. "containerlab").
type Clab struct{ TopoFile string }

// ContainerName is the containerlab container name of a lab node (clab-<lab>-<node>).
func ContainerName(labName, node string) string { return "clab-" + labName + "-" + node }

func clabCmd() []string {
	if v := os.Getenv("CLAB"); v != "" {
		return strings.Fields(v)
	}
	if os.Geteuid() == 0 {
		return []string{"containerlab"}
	}
	return []string{"sudo", "-n", "-E", "containerlab"}
}

func (c Clab) args(action string, extra ...string) []string {
	return append([]string{action, "-t", c.TopoFile}, extra...)
}

func (c Clab) run(ctx context.Context, action string, extra ...string) error {
	cmd := clabCmd()
	return exec.Run(ctx, cmd[0], append(cmd[1:], c.args(action, extra...)...)...)
}

func (c Clab) Deploy(ctx context.Context) error  { return c.run(ctx, "deploy") }
func (c Clab) Destroy(ctx context.Context) error { return c.run(ctx, "destroy", "--cleanup") }
func (c Clab) Inspect(ctx context.Context) error { return c.run(ctx, "inspect") }
func (c Clab) Graph(ctx context.Context) error   { return c.run(ctx, "graph") }

// MgmtIP returns a container's IPv4 address on the named clab mgmt docker network
// (clab's mgmt.network is `<lab>-mgmt`). The Talos compute nodes keep clab-mgmt on
// eth0, so talosctl reaches the Talos API here during bring-up — decoupled from the
// anycast API VIP + GoBGP, which have not converged at bootstrap time. clab's mgmt
// bridge always assigns IPv4, and Talos auto-adds the node's runtime addresses to
// the apid cert SANs, so an IPv4 mgmt endpoint validates.
func MgmtIP(ctx context.Context, container, mgmtNet string) (string, error) {
	out, err := exec.Output(ctx, "docker", "inspect", container,
		"--format", fmt.Sprintf("{{ (index .NetworkSettings.Networks %q).IPAddress }}", mgmtNet))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return "", fmt.Errorf("no IPv4 address on mgmt network %q for container %s", mgmtNet, container)
	}
	return ip, nil
}
