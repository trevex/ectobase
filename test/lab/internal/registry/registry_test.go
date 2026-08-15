package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/trevex/ectobase/test/lab/internal/render"
)

// recorder is a fake Runner that records each invocation's argv and can be armed
// to fail on the Nth call.
type recorder struct {
	calls  [][]string
	failAt int // 1-based; 0 = never fail
	err    error
}

func (r *recorder) run(ctx context.Context, name string, args ...string) error {
	r.calls = append(r.calls, append([]string{name}, args...))
	if r.failAt != 0 && len(r.calls) == r.failAt {
		return r.err
	}
	return nil
}

func TestEnsureCache(t *testing.T) {
	build := t.TempDir()
	if err := EnsureCache(context.Background(), build); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(build, CacheDirName)
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("cache dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", dir)
	}
	// Idempotent: a second call must not error.
	if err := EnsureCache(context.Background(), build); err != nil {
		t.Fatalf("second EnsureCache: %v", err)
	}
}

func TestPurgeCache(t *testing.T) {
	build := t.TempDir()
	dir := filepath.Join(build, CacheDirName)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PurgeCache(build); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cache dir still present after purge: %v", err)
	}
	// Idempotent: purging an absent dir is not an error.
	if err := PurgeCache(build); err != nil {
		t.Fatalf("second PurgeCache: %v", err)
	}
}

func TestPushLocal(t *testing.T) {
	rec := &recorder{}
	reg := &Registry{Host: "[fd00:29::5]:5000", Run: rec.run}
	if err := reg.PushLocal(context.Background(), []string{"flowplane", "mesh"}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"docker", "tag", "ghcr.io/trevex/ectobase/flowplane:dev", "[fd00:29::5]:5000/trevex/ectobase/flowplane:dev"},
		{"docker", "push", "[fd00:29::5]:5000/trevex/ectobase/flowplane:dev"},
		{"docker", "tag", "ghcr.io/trevex/ectobase/mesh:dev", "[fd00:29::5]:5000/trevex/ectobase/mesh:dev"},
		{"docker", "push", "[fd00:29::5]:5000/trevex/ectobase/mesh:dev"},
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("got %v\nwant %v", rec.calls, want)
	}
	// The pushed repo path must carry the MirrorPath segment so it matches the
	// full path the Talos mirror forwards (a bare <name> repo would 404 on pull).
	for _, c := range rec.calls {
		if !strings.Contains(c[len(c)-1], "/trevex/ectobase/") {
			t.Fatalf("push ref missing mirror path segment: %v", c)
		}
	}
}

func TestPushLocalTagErrorAborts(t *testing.T) {
	sentinel := errors.New("boom")
	rec := &recorder{failAt: 1, err: sentinel}
	reg := &Registry{Host: "[fd00:29::5]:5000", Run: rec.run}
	err := reg.PushLocal(context.Background(), []string{"flowplane", "mesh"})
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
	// Only the first tag ran; push (and the second image) must not have been called.
	want := [][]string{
		{"docker", "tag", "ghcr.io/trevex/ectobase/flowplane:dev", "[fd00:29::5]:5000/trevex/ectobase/flowplane:dev"},
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("expected abort after first tag, got %v", rec.calls)
	}
}

// TestConfigTemplateRenders is the Part D smoke: the config template renders (with
// nil data) to a registry:2 config with the expected storage root + listen addr.
func TestConfigTemplateRenders(t *testing.T) {
	src, err := os.ReadFile("../../templates/registry/config.yml.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	out, err := render.String(string(src), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rootdirectory: /var/lib/registry", "addr: :5000"} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, out)
		}
	}
}
