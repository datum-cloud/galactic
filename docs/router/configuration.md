# Router Configuration

`galactic-router` supports configuration via environment variables, CLI flags,
or a combination of both. CLI flags take precedence over environment variables.

## Quick Reference

| Option | Environment Variable | CLI Flag | Default |
|---|---|---|---|
| Node name | `GALACTIC_ROUTER_NODE_NAME` | `--node-name` | _(required)_ |
| Router role | `GALACTIC_ROUTER_ROUTER_ROLE` | `--router-role` | _(required)_ |
| BGP listen port | `GALACTIC_ROUTER_BGP_LISTEN_PORT` | `--bgp-listen-port` | `179` |
| BGP local address | `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` | `--bgp-local-address` | `""` |
| GoBGP gRPC server | `GALACTIC_ROUTER_GOBGP_GRPC_SERVER_ENABLED` | `--gobgp-grpc-server-enabled` | `false` |
| GoBGP gRPC port | `GALACTIC_ROUTER_GOBGP_GRPC_PORT` | `--gobgp-grpc-port` | `50051` |
| Metrics port | `GALACTIC_ROUTER_METRICS_PORT` | `--metrics-port` | `8080` |
| gRPC health port | `GALACTIC_ROUTER_GRPC_HEALTH_PORT` | `--grpc-health-port` | `5000` |

## Required Options

The following options are **required**. If unset, `galactic-router` exits with
an error:

- `--node-name` (`GALACTIC_ROUTER_NODE_NAME`) — Kubernetes node name where the router runs.
- `--router-role` (`GALACTIC_ROUTER_ROUTER_ROLE`) — Router role: `tenant` or `fabric`.

## Option Details

### `--node-name` / `GALACTIC_ROUTER_NODE_NAME`

The Kubernetes node name where `galactic-router` is deployed. This value is
used to scope BGP configuration to the correct node.

**Type:** string
**Required:** yes

### `--router-role` / `GALACTIC_ROUTER_ROUTER_ROLE`

The routing role of this instance. Determines which BGP backend is used:

- `tenant` — uses GoBGP for EVPN path distribution (production role).
- `fabric` — uses the FRR stub backend (not yet implemented).

**Type:** string
**Required:** yes
**Valid values:** `tenant`, `fabric`

### `--bgp-listen-port` / `GALACTIC_ROUTER_BGP_LISTEN_PORT`

TCP port that GoBGP binds for inbound BGP peer connections. Set to `-1` to
run in outbound-only mode (no inbound BGP listener).

**Type:** integer
**Default:** `179`
**Valid values:** `-1`, `1`–`65535`

### `--bgp-local-address` / `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS`

Source IP address used for outgoing BGP TCP connections. When empty, the kernel
selects the default source address.

**Type:** string
**Default:** `""` (empty)

### `--gobgp-grpc-server-enabled` / `GALACTIC_ROUTER_GOBGP_GRPC_SERVER_ENABLED`

Enable the embedded GoBGP gRPC API server. When enabled, the gRPC server
listens on the port specified by `--gobgp-grpc-port`.

**Type:** boolean
**Default:** `false`

### `--gobgp-grpc-port` / `GALACTIC_ROUTER_GOBGP_GRPC_PORT`

TCP port for the GoBGP gRPC API server. Only used when
`--gobgp-grpc-server-enabled` is `true`.

**Type:** integer
**Default:** `50051`
**Valid values:** `1`–`65535`

### `--metrics-port` / `GALACTIC_ROUTER_METRICS_PORT`

TCP port for the controller-runtime metrics HTTP server. Exposes Prometheus
metrics for monitoring.

**Type:** integer
**Default:** `8080`
**Valid values:** `1`–`65535`

### `--grpc-health-port` / `GALACTIC_ROUTER_GRPC_HEALTH_PORT`

TCP port for the gRPC health check server. Used by Kubernetes liveness and
readiness probes.

**Type:** integer
**Default:** `5000`
**Valid values:** `1`–`65535`

## Configuration Precedence

Values are resolved in the following order (highest to lowest priority):

1. **CLI flag** — e.g. `--metrics-port 9090`
2. **Environment variable** — e.g. `GALACTIC_ROUTER_METRICS_PORT=9090`
3. **Default** — compiled-in default value

## Examples

### Environment variable configuration (current DaemonSet)

```yaml
env:
  - name: GALACTIC_ROUTER_NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: status.nodeName
  - name: GALACTIC_ROUTER_ROUTER_ROLE
    value: tenant
```

All other options use their defaults.

### CLI flag configuration

```yaml
command:
  - /galactic-router
args:
  - --node-name=$(GALACTIC_ROUTER_NODE_NAME)
  - --router-role=tenant
  - --metrics-port=9090
  - --gobgp-grpc-server-enabled=true
  - --gobgp-grpc-port=50051
env:
  - name: GALACTIC_ROUTER_NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: status.nodeName
```

### Mixed configuration

Environment variables provide defaults; CLI flags override specific values:

```yaml
env:
  - name: GALACTIC_ROUTER_NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: status.nodeName
  - name: GALACTIC_ROUTER_ROUTER_ROLE
    value: tenant
  - name: GALACTIC_ROUTER_METRICS_PORT
    value: "9090"
command:
  - /galactic-router
args:
  - --node-name=$(GALACTIC_ROUTER_NODE_NAME)
  - --router-role=tenant
  - --metrics-port=9100   # overrides GALACTIC_ROUTER_METRICS_PORT env var
```
