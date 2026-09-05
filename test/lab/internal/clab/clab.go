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

// ContainerPID resolves a container's host PID via `docker inspect`, for reaching it
// with `nsenter -t <pid> -n` — used to run a command inside a node's own network
// namespace (immune to fabric-routing flaps) instead of over the fabric from the
// host netns. The Talos compute nodes have no clab-mgmt interface (network-mode:
// none), so this is their only host-side reachability path besides the fabric itself.
func ContainerPID(ctx context.Context, container string) (string, error) {
	out, err := exec.Output(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", container)
	if err != nil {
		return "", err
	}
	pid := strings.TrimSpace(string(out))
	if pid == "" || pid == "0" {
		return "", fmt.Errorf("no running pid for container %s", container)
	}
	return pid, nil
}
