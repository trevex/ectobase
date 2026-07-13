package routebus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerTLSMissingFilesErrors(t *testing.T) {
	_, err := ServerTLS("/nope/ca.pem", "/nope/srv.pem", "/nope/srv-key.pem")
	if err == nil {
		t.Fatal("want error for missing cert files")
	}
}

func TestLoadClientTLSRequiresAllThree(t *testing.T) {
	dir := t.TempDir()
	// Empty (invalid) files still exercise the "all three required" plumbing.
	for _, f := range []string{"ca.pem", "cli.pem", "cli-key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ClientTLS(filepath.Join(dir, "ca.pem"), "", filepath.Join(dir, "cli-key.pem")); err == nil {
		t.Fatal("want error when cert path is empty")
	}
}
