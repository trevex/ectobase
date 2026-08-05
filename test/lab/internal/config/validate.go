package config

import (
	"fmt"
	"net/netip"
)

func (c *Config) validate() error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}
	for label, as := range map[string]int{"edge": c.Fabric.AS.Edge, "switch": c.Fabric.AS.Switch, "host": c.Fabric.AS.Host} {
		if as <= 0 {
			return fmt.Errorf("fabric.as.%s must be > 0", label)
		}
	}
	if c.Fabric.NAT64Prefix != "" {
		if _, err := netip.ParsePrefix(c.Fabric.NAT64Prefix); err != nil {
			return fmt.Errorf("fabric.nat64Prefix: %w", err)
		}
	}
	if len(c.Fabric.Clusters) == 0 {
		return fmt.Errorf("at least one cluster is required")
	}
	seen := map[string]bool{}
	for _, cl := range c.Fabric.Clusters {
		if cl.Name == "" {
			return fmt.Errorf("cluster name is required")
		}
		if seen[cl.Name] {
			return fmt.Errorf("duplicate cluster name %q", cl.Name)
		}
		seen[cl.Name] = true
		if cl.Nodes < 1 || cl.Nodes > 15 {
			return fmt.Errorf("cluster %q: nodes must be 1..15 (got %d)", cl.Name, cl.Nodes)
		}
	}
	return nil
}
