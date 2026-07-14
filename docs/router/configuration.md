# Router Configuration

`galactic-router` supports configuration via environment variables, CLI flags,
or a combination of both. CLI flags take precedence over environment variables.

## Quick Reference

| Option | Environment Variable | CLI Flag | Default |
|---|---|---|---|
| Node name | `GALACTIC_ROUTER_NODE_NAME` | `--node-name` | _(required)_ |
| Router mode | `GALACTIC_ROUTER_ROUTER_MODE` | `--mode` | _(required)_ |
| Route reflector | `GALACTIC_ROUTER_REFLECTOR` | `--reflector` | `false` |
| BGP listen port | `GALACTIC_ROUTER_BGP_LISTEN_PORT` | `--bgp-listen-port` | `179` |
| BGP local address | `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS` | `--bgp-local-address` | _(auto-detected from `lo`)_ |
| Metrics port | `GALACTIC_ROUTER_METRICS_PORT` | `--metrics-port` | `8080` |
| gRPC health port | `GALACTIC_ROUTER_GRPC_HEALTH_PORT` | `--grpc-health-port` | `5000` |
| Orphan-cleanup namespace | `GALACTIC_ROUTER_GC_NAMESPACE` | `--gc-namespace` | `galactic-system` |
| Orphan-cleanup interval | `GALACTIC_ROUTER_GC_INTERVAL` | `--gc-interval` | `5m` |

## Required Options

The following options are **required**. If unset, `galactic-router` exits with
an error:

- `--node-name` (`GALACTIC_ROUTER_NODE_NAME`) — Kubernetes node name where the router runs.
- `--mode` (`GALACTIC_ROUTER_ROUTER_MODE`) — Router mode: `transit`, `fabric`, or `tenant`.

## Option Details

### `--node-name` / `GALACTIC_ROUTER_NODE_NAME`

The Kubernetes node name where `galactic-router` is deployed. This value is
used to scope BGP configuration to the correct node.

**Type:** string
**Required:** yes

### `--mode` / `GALACTIC_ROUTER_ROUTER_MODE`

The operating mode of this instance. Determines which BGP backend is used:

- `tenant` — uses GoBGP for EVPN path distribution (production mode).
- `fabric` — uses the FRR stub backend (not yet implemented).
- `transit` — reserved for future transit mode (not yet implemented).

### `--reflector` / `GALACTIC_ROUTER_REFLECTOR`

Enable route reflector mode. Only valid when `--mode=fabric` or `--mode=tenant`.

**Type:** boolean
**Default:** `false`

### `--bgp-listen-port` / `GALACTIC_ROUTER_BGP_LISTEN_PORT`

TCP port that GoBGP binds for inbound BGP peer connections. Set to `-1` to
run in outbound-only mode (no inbound BGP listener).

**Type:** integer
**Default:** `179`
**Valid values:** `-1`, `1`–`65535`

### `--bgp-local-address` / `GALACTIC_ROUTER_BGP_LOCAL_ADDRESS`

Source IP address used for outgoing BGP TCP connections and, when set, the
EVPN next-hop advertised for this node's paths. When empty, `galactic-router`
reads the first global-unicast IPv6 address assigned to the host's `lo`
interface (skipping `::1` and link-local `fe80::/10` addresses) and uses
that. This requires `hostNetwork: true` and an address already assigned to
`lo` — typically by an underlay/fabric BGP daemon (e.g. FRR) that runs
before `galactic-router` starts. Startup fails with an error if no explicit
value is set and no such address is found on `lo`.

**Type:** string
**Default:** _(auto-detected from `lo`)_

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

> **Talos:** `/sbin/dashboard` permanently binds `127.0.0.1:5000` on every
> Talos node. Since `galactic-router` runs with `hostNetwork: true`, the
> default `5000` always collides on Talos-based clusters. The shipped
> `config/router/base/daemonset.yaml` sets this to `5179` for exactly this
> reason; if you run `galactic-router` outside those manifests on Talos, set
> it to something other than `5000` yourself.

### `--gc-namespace` / `GALACTIC_ROUTER_GC_NAMESPACE`

Namespace the GC controller scans for orphaned `BGPAdvertisement` and
`BGPVRFInstance` CRDs (and their corresponding stale kernel VRFs) left behind
when a pod's `cmdDel` never fires or races with a concurrent `cmdAdd`. The
production DaemonSet sets this explicitly to `galactic-system`.

**Type:** string
**Default:** `galactic-system`

### `--gc-interval` / `GALACTIC_ROUTER_GC_INTERVAL`

How often the GC controller runs its cleanup pass, after an initial pass once
the informer caches sync at startup.

**Type:** duration
**Default:** `5m`

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
        fieldPath: spec.nodeName
  - name: GALACTIC_ROUTER_ROUTER_MODE
    value: tenant
  - name: GALACTIC_ROUTER_GC_NAMESPACE
    value: galactic-system
```

All other options use their defaults.

### CLI flag configuration

```yaml
command:
  - /galactic-router
args:
  - --node-name=$(GALACTIC_ROUTER_NODE_NAME)
  - --mode=tenant
  - --metrics-port=9090
env:
  - name: GALACTIC_ROUTER_NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
```

### Mixed configuration

Environment variables provide defaults; CLI flags override specific values:

```yaml
env:
  - name: GALACTIC_ROUTER_NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
  - name: GALACTIC_ROUTER_ROUTER_MODE
    value: tenant
  - name: GALACTIC_ROUTER_METRICS_PORT
    value: "9090"
command:
  - /galactic-router
args:
  - --node-name=$(GALACTIC_ROUTER_NODE_NAME)
  - --mode=tenant
  - --metrics-port=9100   # overrides GALACTIC_ROUTER_METRICS_PORT env var
```
