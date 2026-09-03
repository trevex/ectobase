package clab

import (
	"context"
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

// MgmtIP returns the containerlab management IP of a node (clab-<labName>-<node>),
// via docker inspect. Used for interactive SSH access.
func MgmtIP(ctx context.Context, labName, node string) (string, error) {
	out, err := exec.Output(ctx, "docker", "inspect", ContainerName(labName, node),
		"--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// KindNodeIP6 returns the first non-empty global IPv6 address of a kind node
// container (named directly, e.g. "dispatch-control-plane", NOT clab-prefixed —
// clab's k8s-kind containers are created by kind on the kind docker network).
// kubeadm advertises the API server on this address, so it is Cilium's
// k8sServiceHost with kube-proxy replacement (no ClusterIP to bootstrap against).
func KindNodeIP6(ctx context.Context, container string) (string, error) {
	out, err := exec.Output(ctx, "docker", "inspect", container,
		"--format", "{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}} {{end}}")
	if err != nil {
		return "", err
	}
	for _, f := range strings.Fields(string(out)) {
		if f != "" {
			return f, nil
		}
	}
	return "", nil
}
