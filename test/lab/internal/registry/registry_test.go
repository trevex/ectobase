package registry

import (
	"context"
	"errors"
	"os"
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
	rec := &recorder{}
	reg := &Registry{Host: "[fd00:29::5]:5000", Run: rec.run}
	if err := reg.EnsureCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"docker", "volume", "create", CacheVolume}}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("got %v want %v", rec.calls, want)
	}
}

func TestPurge(t *testing.T) {
	rec := &recorder{}
	reg := &Registry{Host: "[fd00:29::5]:5000", Run: rec.run}
	if err := reg.Purge(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"docker", "volume", "rm", CacheVolume}}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("got %v want %v", rec.calls, want)
	}
}

func TestPushLocal(t *testing.T) {
	rec := &recorder{}
	reg := &Registry{Host: "[fd00:29::5]:5000", Run: rec.run}
	if err := reg.PushLocal(context.Background(), []string{"flowplane", "netplane"}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"docker", "tag", "ghcr.io/trevex/ectobase/flowplane:dev", "[fd00:29::5]:5000/flowplane:dev"},
		{"docker", "push", "[fd00:29::5]:5000/flowplane:dev"},
		{"docker", "tag", "ghcr.io/trevex/ectobase/netplane:dev", "[fd00:29::5]:5000/netplane:dev"},
		{"docker", "push", "[fd00:29::5]:5000/netplane:dev"},
	}
	if !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("got %v\nwant %v", rec.calls, want)
	}
}

func TestPushLocalTagErrorAborts(t *testing.T) {
	sentinel := errors.New("boom")
	rec := &recorder{failAt: 1, err: sentinel}
	reg := &Registry{Host: "[fd00:29::5]:5000", Run: rec.run}
	err := reg.PushLocal(context.Background(), []string{"flowplane", "netplane"})
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
	// Only the first tag ran; push (and the second image) must not have been called.
	want := [][]string{
		{"docker", "tag", "ghcr.io/trevex/ectobase/flowplane:dev", "[fd00:29::5]:5000/flowplane:dev"},
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
