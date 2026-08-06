package deploy

import "testing"

func TestReadyNodes(t *testing.T) {
	out := []byte(`node-a   Ready      control-plane   5m    v1.31.0
node-b   NotReady   <none>          3m    v1.31.0
node-c   Ready      <none>          4m    v1.31.0
`)
	if got := ReadyNodes(out); got != 2 {
		t.Fatalf("ReadyNodes = %d, want 2", got)
	}
}

func TestReadyNodesEmpty(t *testing.T) {
	if got := ReadyNodes(nil); got != 0 {
		t.Fatalf("ReadyNodes(nil) = %d, want 0", got)
	}
	if got := ReadyNodes([]byte("")); got != 0 {
		t.Fatalf("ReadyNodes(empty) = %d, want 0", got)
	}
}
