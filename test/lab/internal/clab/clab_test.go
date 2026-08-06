package clab

import (
	"reflect"
	"testing"
)

func TestContainerName(t *testing.T) {
	if got := ContainerName("lab", "sw1"); got != "clab-lab-sw1" {
		t.Fatalf("ContainerName = %q, want clab-lab-sw1", got)
	}
}

func TestClabCmdEnvOverride(t *testing.T) {
	t.Setenv("CLAB", "containerlab")
	got := clabCmd()
	if !reflect.DeepEqual(got, []string{"containerlab"}) {
		t.Fatalf("clabCmd = %v, want [containerlab]", got)
	}
}

func TestArgs(t *testing.T) {
	c := Clab{TopoFile: "t.yml"}
	got := c.args("deploy", "-x")
	want := []string{"deploy", "-t", "t.yml", "-x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}
}
