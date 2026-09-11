package main

// RBAC for the flowplane CNI plugin. Rules generated into
// charts/ectobase-pool/files/flowplane-cni/role.yaml by `make generate`.

//+kubebuilder:rbac:groups="",resources=pods,verbs=get
// `list` is required, not just `get`: a KubeVirt virt-launcher pod carries no
// net.ectobase.dev/network-interface annotation, so the only key tying its interface back to a
// NetworkInterface is the pinned MAC — and finding it means listing the namespace's CompiledNICs
// (resolveCompiledNICByMAC). Without list, CNI ADD fails and the VM never attaches to the overlay.
//+kubebuilder:rbac:groups=compiled.ectobase.dev,resources=compilednics,verbs=get;list
