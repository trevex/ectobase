// Package render expands sprig templates to strings/files under build/<name>/.
package render

import (
	"bytes"
	"io/fs"
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

// StringFS renders a named template read from fsys to a string.
func StringFS(fsys fs.FS, templatePath string, data any) (string, error) {
	src, err := fs.ReadFile(fsys, templatePath)
	if err != nil {
		return "", err
	}
	return String(string(src), data)
}

// FileFS renders a template read from fsys into outPath (creating parent dirs).
// It lets the compiled binary render from embedded templates independent of cwd.
func FileFS(fsys fs.FS, templatePath, outPath string, data any) error {
	out, err := StringFS(fsys, templatePath, data)
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
