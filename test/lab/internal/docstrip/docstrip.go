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

// RemoveKeys deletes the given top-level keys from every YAML document whose
// top-level `kind` matches, leaving all other documents and keys untouched
// (re-encoded with 2-space indent). Used to drop the control-plane NoSchedule
// taint from the generated KubeNodeConfig doc: Talos 1.14 treats KubeNodeConfig.
// taints as the declarative source of node taints, and `talosctl machineconfig
// patch` cannot delete a map key (a null value or {} both merge as no-ops, and
// JSON6902 is rejected for multi-doc configs), so the field must be excised from
// the rendered config instead. The deprecated cluster.allowSchedulingOnControlPlanes
// does NOT clear this taint on 1.14 (it conflicts with it: "already set"), so this
// is the only way to keep control-plane-only clusters schedulable for good.
func RemoveKeys(in []byte, kind string, keys ...string) ([]byte, error) {
	keySet := map[string]bool{}
	for _, k := range keys {
		keySet[k] = true
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
		if kindOf(&node) == kind {
			if m := mappingOf(&node); m != nil {
				filtered := m.Content[:0]
				for i := 0; i+1 < len(m.Content); i += 2 {
					if keySet[m.Content[i].Value] {
						continue
					}
					filtered = append(filtered, m.Content[i], m.Content[i+1])
				}
				m.Content = filtered
			}
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

// mappingOf returns the top-level mapping node of a document (unwrapping the
// DocumentNode), or nil if the document is not a mapping.
func mappingOf(doc *yaml.Node) *yaml.Node {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	return n
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
