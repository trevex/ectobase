// Package templates embeds the lab's render templates so the compiled `lab`
// binary carries them (runnable from any cwd).
package templates

import "embed"

//go:embed fabric.clab.yml.tmpl frr/* k8s/*.tmpl registry/*.tmpl ceph/*
var FS embed.FS
