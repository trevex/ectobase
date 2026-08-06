// Package registry manages the lab's local image mirror: a persistent pull-through
// + push-local registry backed by a host directory under build/<name>/ that
// survives down/up. The registry container is wired into the topology at `lab up`
// (T16); this package owns the cache-dir lifecycle and the push-local step. A host
// directory (not a named docker volume) is used because clab binds cannot name
// docker volumes — the clab template binds `registry-cache:/var/lib/registry`
// relative to the topology file, so the dir name must match CacheDirName.
package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// CacheDirName is the registry cache directory, relative to build/<name>/. It
// matches the clab template bind `registry-cache:/var/lib/registry`. The dir
// survives `down` and is only removed by `down --purge` (PurgeCache).
const CacheDirName = "registry-cache"

// LocalRepo is the ghcr namespace the lab's :dev images live under.
const LocalRepo = "ghcr.io/trevex/ectobase"

// Runner runs a command; injectable so tests can capture the docker argv.
type Runner func(ctx context.Context, name string, args ...string) error

// Registry pushes local :dev images into (and manages the cache for) the in-fabric
// mirror reachable at Host (e.g. "[fd00:29::5]:5000").
type Registry struct {
	Host string
	Run  Runner
}

// New returns a Registry driving the real docker CLI via exec.Run.
func New(host string) *Registry { return &Registry{Host: host, Run: exec.Run} }

// EnsureCache creates the persistent cache directory under buildDir (idempotent).
func EnsureCache(ctx context.Context, buildDir string) error {
	return os.MkdirAll(filepath.Join(buildDir, CacheDirName), 0o755)
}

// PurgeCache removes the cache directory under buildDir (for `lab down --purge`).
func PurgeCache(buildDir string) error {
	return os.RemoveAll(filepath.Join(buildDir, CacheDirName))
}

// PushLocal tags each ghcr.io/trevex/ectobase/<name>:dev to the in-fabric mirror
// and pushes it, so nodes pull the local images from the fabric.
func (r *Registry) PushLocal(ctx context.Context, names []string) error {
	for _, n := range names {
		src := fmt.Sprintf("%s/%s:dev", LocalRepo, n)
		dst := fmt.Sprintf("%s/%s:dev", r.Host, n)
		if err := r.Run(ctx, "docker", "tag", src, dst); err != nil {
			return fmt.Errorf("tag %s: %w", n, err)
		}
		if err := r.Run(ctx, "docker", "push", dst); err != nil {
			return fmt.Errorf("push %s: %w", n, err)
		}
	}
	return nil
}
