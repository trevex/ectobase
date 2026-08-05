// Package render expands sprig templates to strings/files under build/<name>/.
package render

import (
	"bytes"
	"os"
	"path/filepath"
	"text/template"

	"github.com/Masterminds/sprig/v3"
)

func String(tmpl string, data any) (string, error) {
	t, err := template.New("t").Funcs(sprig.TxtFuncMap()).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// File renders templatePath into outPath (creating parent dirs).
func File(templatePath, outPath string, data any) error {
	src, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	out, err := String(string(src), data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(out), 0o644)
}

// BuildDir returns build/<name>.
func BuildDir(name string) string { return filepath.Join("build", name) }
