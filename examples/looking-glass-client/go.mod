module github.com/datum-cloud/galactic/examples/looking-glass-client

go 1.26.4

// The client is built against the service API in this checkout. It imports
// only go.datum.net/galactic/api/fabric/service/v1 and api/fabric/v1: its
// module path is outside go.datum.net/galactic, so the compiler refuses any
// import of the core's internal packages.
replace go.datum.net/galactic => ../..

require (
	go.datum.net/galactic v0.0.0-00010101000000-000000000000
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261026165753-2ffab32bce7e
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)
