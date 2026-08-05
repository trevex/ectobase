// Package config loads and validates the lab.yaml, and derives per-cluster IPv6
// prefixes so parallel clusters on one fabric never collide.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Name    string            `yaml:"name"`
	Images  map[string]string `yaml:"images"`
	Fabric  Fabric            `yaml:"fabric"`
	Derived Derived           `yaml:"-"`
}

type Fabric struct {
	AS          ASConfig  `yaml:"as"`
	NAT64Prefix string    `yaml:"nat64Prefix"`
	Registry    Registry  `yaml:"registry"`
	Clusters    []Cluster `yaml:"clusters"`
}

type ASConfig struct {
	Edge   int `yaml:"edge"`
	Switch int `yaml:"switch"`
	Host   int `yaml:"host"`
}

type Registry struct {
	Upstreams []string `yaml:"upstreams"`
	Push      []string `yaml:"push"`
}

type Cluster struct {
	Name  string `yaml:"name"`
	Nodes int    `yaml:"nodes"`
}

// TotalNodes is the sum of node counts across all clusters (switch host-port count).
func (c *Config) TotalNodes() int {
	n := 0
	for _, cl := range c.Fabric.Clusters {
		n += cl.Nodes
	}
	return n
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return LoadBytes(b)
}

func LoadBytes(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true) // reject typos in the envelope
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse lab.yaml: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.derive()
	return &c, nil
}
