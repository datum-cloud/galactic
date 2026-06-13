# Plan: Embed GoBGP and Publish BGPProvider

## Background

Cosmos reconciles BGP CRDs (`BGPInstance`, `BGPPeer`, `BGPAdvertisement`, `BGPRoutePolicy`) by
calling into provider implementations that satisfy the `cosmos/internal/provider.Provider`
interface. The cosmos gobgp provider (`cosmos/internal/provider/gobgp/provider.go`) already exists
and dials a GoBGP gRPC endpoint to configure the daemon.

Currently galactic-agent starts up and does nothing. This plan makes it:

1. Embed and run a GoBGP server in-process.
2. Publish a `BGPProvider` Kubernetes resource at startup so cosmos can discover and drive it.
3. Delete the `BGPProvider` on clean shutdown so cosmos does not attempt stale configuration
   on the next start.

Cosmos's existing gobgp provider implementation requires no changes — it dials `localhost:50051`
and calls `ConfigureSpeaker`, `AddOrUpdatePeer`, etc. Galactic only needs to run the server it
dials into and declare itself via the CRD.

Nothing is enabled by default. If the agent starts with no providers enabled it logs a warning
so operators know the process is running but not doing anything useful.

## Architecture

```
galactic-agent (node)
├── embedded GoBGP server  ←── listens on localhost:50051 (gRPC API)
│
├── bootstrap at startup
│       └── CreateOrUpdate BGPProvider CRD
│               spec.type = GoBGP
│               spec.gobgp.endpoint = localhost:50051
│               labels: node=<nodeName>, plane=overlay
│
└── shutdown
        └── Delete BGPProvider CRD

cosmos operator (cluster)
└── BGPProvider reconciler
        └── instantiates cosmos/provider/gobgp.Provider
                └── dials localhost:50051
                        └── calls ConfigureSpeaker, AddOrUpdatePeer, etc.
```

## Changes

### 1. Embedded GoBGP server — `internal/gobgp/server.go`

Use `github.com/osrg/gobgp/v4/pkg/server.BgpServer` to run GoBGP in-process.

Provide a thin lifecycle wrapper:

```go
type Server struct { ... }

func New(cfg Config) *Server
func (s *Server) Start(ctx context.Context) error  // blocks until ctx cancelled
func (s *Server) Addr() string                     // returns "localhost:<port>"
```

`Config` fields:
- `GRPCPort int` — port the GoBGP gRPC API listens on; default `50051`
- `LogLevel string` — GoBGP internal log level; default `panic`

`Start` creates and starts `server.BgpServer` with the configured gRPC port, then blocks until
`ctx` is cancelled, at which point it calls `server.Stop`.

The GoBGP gRPC API port and the BGP protocol listen port (179 / custom) are separate concerns.
The gRPC API port is what cosmos dials; the BGP protocol listen port is set later by cosmos via
`ConfigureSpeaker` when it reconciles a `BGPInstance`. Galactic does not configure BGP speaker
parameters — that is cosmos's responsibility.

### 2. BGPProvider bootstrap — `internal/bootstrap/bootstrap.go`

A focused package that handles `BGPProvider` creation and deletion.

```go
func EnsureGoBGPProvider(ctx context.Context, c client.Client, nodeName, endpoint string) error
func DeleteGoBGPProvider(ctx context.Context, c client.Client, nodeName string) error
```

`EnsureGoBGPProvider` creates or updates:

```yaml
metadata:
  name: galactic-gobgp-<nodeName>
  labels:
    bgp.miloapis.com/node: <nodeName>
    galactic.io/managed-by: galactic-agent
    galactic.io/plane: overlay
    galactic.io/daemon: gobgp
spec:
  type: GoBGP
  gobgp:
    endpoint: localhost:50051
```

`DeleteGoBGPProvider` deletes the resource on clean shutdown, ignoring NotFound errors.

Both functions are only called when `--gobgp-enabled` is set.

### 3. Scheme — `internal/agent/agent.go`

Add `providersv1alpha1` to the scheme so the bootstrap client can create and delete `BGPProvider`
resources. The `bgpv1alpha1` scheme is not needed — galactic does not watch BGP CRDs.

### 4. CLI options — `cmd/galactic-agent/main.go` and `internal/agent/agent.go`

Add to `Options`:

| Flag | Type | Default | Description |
|---|---|---|---|
| `--gobgp-enabled` | bool | `false` | Enable embedded GoBGP and publish BGPProvider |
| `--gobgp-api-port` | int | `50051` | Port for GoBGP gRPC API (cosmos dials this) |
| `--gobgp-log-level` | string | `panic` | GoBGP internal log level |

### 5. Agent startup wiring — `internal/agent/agent.go`

Startup sequence when `--gobgp-enabled=true`:

1. Signal handling, node name, metrics, logger
2. Load k8s rest config
3. Create controller-runtime manager
4. Start embedded GoBGP server in a goroutine (runs until ctx cancelled)
5. Bootstrap `BGPProvider` via direct k8s client (non-cached, hits API server directly)
6. Register readyz check — probes `localhost:<gobgp-api-port>` via gRPC; pod stays not-ready
   until GoBGP is accepting connections
7. Register healthz ping check
8. Start manager (blocks until ctx cancelled)
9. On shutdown: call `DeleteGoBGPProvider` before returning

When `--gobgp-enabled=false` (the default), steps 4–5 and 9 are skipped and a warning is logged:

```
no providers enabled; agent is running but will not configure any BGP daemons
```

## What is NOT in scope

- FRR embedding — separate plan
- Reconciling any BGP CRDs — cosmos owns that
- SRv6 route management changes
- BGP speaker configuration — cosmos drives this via `BGPInstance` after discovering the `BGPProvider`

## File layout after implementation

```
internal/
  agent/
    agent.go               # updated: Options, startup wiring, shutdown
  gobgp/
    server.go              # new: embedded BgpServer lifecycle wrapper
    server_test.go         # new: unit tests
  bootstrap/
    bootstrap.go           # new: EnsureGoBGPProvider, DeleteGoBGPProvider
    bootstrap_test.go      # new: unit tests
cmd/
  galactic-agent/
    main.go                # updated: new flags
```
