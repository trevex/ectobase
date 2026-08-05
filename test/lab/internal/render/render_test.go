package render

import (
	"strings"
	"testing"
)

func TestRenderString(t *testing.T) {
	out, err := String("{{ .Name | upper }}-{{ add 1 2 }}", map[string]any{"Name": "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "LAB-3" {
		t.Fatalf("got %q", out)
	}
}
