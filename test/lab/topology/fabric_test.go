package topology

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepoRootFindsGoWork(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte("go 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A nested config dir (mirrors test/lab) with no go.work of its own.
	nested := filepath.Join(root, "test", "lab")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Chdir(nested)
	got, err := repoRoot()
	if err != nil {
		t.Fatalf("repoRoot: %v", err)
	}
	// macOS /tmp is a symlink; compare via EvalSymlinks so the assertion is stable.
	wantEval, _ := filepath.EvalSymlinks(root)
	gotEval, _ := filepath.EvalSymlinks(got)
	if gotEval != wantEval {
		t.Fatalf("repoRoot = %q, want %q", gotEval, wantEval)
	}
}

func TestRepoRootErrorsWithoutGoWork(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "no", "gowork", "here")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Guard: if the temp tree happens to be under a real go.work (it won't in a
	// hermetic tmp), skip rather than falsely fail.
	if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
		t.Skip("temp dir unexpectedly under a go.work")
	}
	t.Chdir(sub)
	if _, err := repoRoot(); err == nil {
		t.Fatal("expected error when no go.work exists up-tree")
	}
}
