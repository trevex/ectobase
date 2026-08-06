// Package docstrip removes documents from a multi-document YAML stream by their
// top-level kind, preserving the remaining documents.
package docstrip

import (
	"bytes"
	"errors"
	"io"

	"gopkg.in/yaml.v3"
)

// Strip removes every YAML document whose top-level `kind` matches one of drop,
// preserving the remaining documents (re-encoded with 2-space indent).
func Strip(in []byte, drop ...string) ([]byte, error) {
	dropSet := map[string]bool{}
	for _, d := range drop {
		dropSet[d] = true
	}
	dec := yaml.NewDecoder(bytes.NewReader(in))
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	wrote := false
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if k := kindOf(&node); k != "" && dropSet[k] {
			continue
		}
		if err := enc.Encode(&node); err != nil {
			return nil, err
		}
		wrote = true
	}
	if wrote {
		if err := enc.Close(); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func kindOf(doc *yaml.Node) string {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "kind" {
			return n.Content[i+1].Value
		}
	}
	return ""
}
