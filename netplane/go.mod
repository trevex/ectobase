module github.com/trevex/xdp-dp/netplane

go 1.26.0

replace github.com/trevex/xdp-dp/api => ../api

replace github.com/trevex/xdp-dp/cni => ../cni

require (
	google.golang.org/grpc v1.82.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)
