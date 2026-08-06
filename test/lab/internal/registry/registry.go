// Package registry manages the lab's local image mirror: a persistent pull-through
// + push-local registry backed by a named docker volume that survives down/up.
// The registry container itself is wired into the topology at `lab up` (T16); this
// package owns the cache-volume lifecycle and the push-local step.
package registry

import (
	"context"
	"fmt"

	"github.com/trevex/ectobase/test/lab/internal/exec"
)

// CacheVolume is the persistent pull-through cache; it survives `down` and is only
// removed by `down --purge`.
const CacheVolume = "ectobase-lab-registry-cache"

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

// EnsureCache creates the persistent cache volume (idempotent — `docker volume
// create` is a no-op if it already exists).
func (r *Registry) EnsureCache(ctx context.Context) error {
	return r.Run(ctx, "docker", "volume", "create", CacheVolume)
}

// Purge removes the cache volume (for `lab down --purge`).
func (r *Registry) Purge(ctx context.Context) error {
	return r.Run(ctx, "docker", "volume", "rm", CacheVolume)
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
