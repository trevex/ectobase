package cmd

import (
	"os"
	"path/filepath"
)

// defaultConfigPath resolves $LAB_CONFIG, else ./test/lab/lab.yaml, else ./lab.yaml.
func defaultConfigPath() string {
	if v := os.Getenv("LAB_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat("test/lab/lab.yaml"); err == nil {
		return "test/lab/lab.yaml"
	}
	return "lab.yaml"
}

func absConfig(p string) (string, error) { return filepath.Abs(p) }
