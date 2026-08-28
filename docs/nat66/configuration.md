# NAT66 Configuration

This is the reference doc for configuring the sharded, stateful NAT66
egress tier — the `galactic-nat66` binary, the `NAT66Shard` CRD, and the
CNI-side settings that point tenant nodes at it. For a hands-on walkthrough
of standing this up from nothing, see
[docs/nat66/getting-started.md](getting-started.md); this document only
covers the "what", not the "why" or the step-by-step.

> Last verified: 2026-08-25 against the current working tree of
> `internal/config/nat66.go`, `internal/config/cni.go`,
> `cmd/galactic-nat66/`, `config/galactic-nat66/`,
> `internal/controller/nat66shard_controller.go`, and
> `deploy/containerlab/resources/galactic-nat66/`.

## `galactic-nat66` configuration (`internal/config/nat66.go`)

`galactic-nat66` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_NAT66` env prefix — the same three-tier precedence pattern
`galactic-router` and `galactic-gateway` use (see
[docs/router/configuration.md](../router/configuration.md)).

| Option             | Environment Variable              | CLI Flag                   | Default | Required |
| ------------------ | --------------------------------- | -------------------------- | ------- | -------- |
| Node name          | `GALACTIC_NAT66_NODE_NAME`        | `--node-name`              | —       | Yes      |
| Uplink interface   | `GALACTIC_NAT66_UPLINK_INTERFACE` | `--nat66-uplink-interface` | —       | Yes      |
| Shard SID          | `GALACTIC_NAT66_SHARD_SID`        | `--nat66-shard-sid`        | —       | Yes      |
| Shard public addr. | `GALACTIC_NAT66_SHARD_PUB_ADDR`   | `--nat66-shard-pub-addr`   | —       | Yes      |
| Metrics port       | `GALACTIC_NAT66_METRICS_PORT`     | `--metrics-port`           | `9182`  | No       |
| gRPC health port   | `GALACTIC_NAT66_GRPC_HEALTH_PORT` | `--grpc-health-port`       | `5182`  | No       |

All four required fields are enforced by `NAT66Config.Validate` at
startup — a shard node deployed without them crash-loops immediately with
an actionable message rather than running degraded. `9182`/`5182` are
chosen to avoid every other `hostNetwork: true` galactic process already
running on a compute node (`fabric-router`'s `179`, `galactic-router`'s
`9179`/`5179`, `galactic-cni`'s `9180`/`5180`, `galactic-gateway`'s
`8081`/`5181`).

### Option details

**`--nat66-uplink-interface` / `GALACTIC_NAT66_UPLINK_INTERFACE`**
Name of this shard's single fabric-facing uplink interface —
`internal/plumbing/ebpf/nat66prog`'s XDP program attaches here. Required:
`galactic-nat66` only ever runs as a dedicated shard, so there's no
"not this role, skip the datapath" case to fall back to.

**`--nat66-shard-sid` / `GALACTIC_NAT66_SHARD_SID`**
This shard's own SRv6 uSID (`NAT66ShardStatus.ShardSID`) — the outer
destination a tenant's egress packet is encapsulated toward. Must be a
native IPv6 address (`NAT66Config.Validate` rejects IPv4 and 4-in-6).
Operator-supplied today; nothing in this repo derives it automatically —
the same gap `BGPRouter.Spec.SRv6Locator`/`NodeID` assignment and
`GALACTIC_GATEWAY_SRV6_ADDRESS` both have.

> **Node-ID collision hazard.** The datapath's `locator_matches` check
> (`internal/plumbing/ebpf/nat66prog/nat66.c`) only compares the top 64
> bits (Block + Node-ID) of a packet's outer destination against this
> value — it does **not** check that the Node-ID is actually reserved for
> the shard. Reusing the physical node's own real `BGPRouter.Spec.NodeID`
> here means the shard's XDP program hijacks that node's own ordinary
> tenant ingress traffic before `usid_ingress` ever gets to it. Reserve a
> distinct Node-ID on the shard's locator for this purpose alone — see
> `deploy/containerlab/resources/galactic-nat66/dfw/node-patch.yaml`'s
> comment for the exact encoding the lab uses.

**`--nat66-shard-pub-addr` / `GALACTIC_NAT66_SHARD_PUB_ADDR`**
This shard's own dedicated, publicly-routable IPv6 address
(`NAT66ShardStatus.ShardAddress`) — every flow this shard NATs is SNAT'd
to an address:port within it. Must also be a native IPv6 address. Must be
unique per shard: a flow's reply is routed back to the correct shard by
ordinary unicast routing on this address alone, with no hashing on the
return path — two shards sharing an address would make replies
undeliverable or misdelivered.

### Capabilities and host requirements

`galactic-nat66` runs `hostNetwork: true` and needs:

| Capability  | Why                                                                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NET_ADMIN` | netlink XDP attach                                                                                                                                                         |
| `BPF`       | eBPF program/map creation                                                                                                                                                  |
| `PERFMON`   | the verifier only allows pointer+scalar arithmetic on packet data (the SNAT/un-SNAT header rewrites) when the loading process is `perfmon_capable()`, even running as root |

It also needs a real bpffs already mounted at `/sys/fs/bpf` on the host
(`type: Directory`, not `DirectoryOrCreate` — a missing mount must fail
loudly, not silently pin maps to a plain directory). Every map is pinned
under `/sys/fs/bpf/galactic-nat66`.

## `NAT66Shard` CRD (`network.datumapis.com/v1alpha1`)

One object per shard node, in the `galactic-system` namespace.

| Field                 | Required | Type     | Description                                                                                   |
| --------------------- | -------- | -------- | --------------------------------------------------------------------------------------------- |
| `spec.targetRef.name` | Yes      | `string` | Kubernetes node name this shard's `galactic-nat66` process runs on.                           |
| `status.shardSID`     | —        | `string` | This shard's uSID, published by the reconciler from `GALACTIC_NAT66_SHARD_SID`; not user-set. |
| `status.shardAddress` | —        | `string` | This shard's public masquerade address, published from `GALACTIC_NAT66_SHARD_PUB_ADDR`.       |
| `status.conditions`   | —        | —        | `Ready` condition, reason `DatapathAttached` or `DatapathNotAttached`.                        |

Leave `status` empty when creating the object — `NAT66ShardReconciler`
(running inside that node's own `galactic-nat66` pod) fills it in from the
pod's own resolved config at startup and publishes a `/128`
`BGPAdvertisement` for each of `shardSID`/`shardAddress` (the same
RT-less, no-`VRFID`/`Function` shape `NetworkGatewayReconciler` uses for
its own VIP advertisements), so every other node in the mesh learns a
real kernel route to it.

Example:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: NAT66Shard
metadata:
  name: dfw-worker-nat66
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: dfw-worker
```

### RBAC

`config/galactic-nat66/rbac.yaml` grants the `galactic-nat66`
ServiceAccount exactly: `get`/`list`/`watch`/`update`/`patch` on
`nat66shards` (+`/status`), full CRUD on `bgpadvertisements`, and
read-only `get`/`list`/`watch` on `bgprouters` — nothing more. It
deliberately does **not** grant `networkegresspolicies`; that CRD belongs
to an earlier, superseded design this sharded-NAT66 tier replaced.

## NAT66 shard membership (`galactic-cni` side)

A tenant's compute node needs to know the fabric-wide list of live shard
SIDs to install its own tenant VRFs' default egress route. This is
separate from anything on the shard nodes themselves.

| Option                    | Environment Variable            | Set on                                            | Default                         | Required |
| ------------------------- | ------------------------------- | ------------------------------------------------- | ------------------------------- | -------- |
| Live NAT66 shard SID list | `GALACTIC_CNI_NAT66_SHARD_SIDS` | `galactic-cni`'s `install-cni` **init** container | _(empty — no shard configured)_ | No       |

`GALACTIC_CNI_NAT66_SHARD_SIDS` is a comma-separated list of every live
shard's `Status.ShardSID`, resolved with env > conflist > default
precedence by `internal/config.CNIConfig`, written into the static
conflist by `internal/installer.Bootstrap`, and read back by
`internal/cnibgp` on every CNI ADD. An empty value means "no NAT66
configured for this fabric" — not an error; pods simply get no egress
default route toward any shard. Example (containerlab lab value, three
shards):

```yaml
- name: GALACTIC_CNI_NAT66_SHARD_SIDS
  value: "2001:db8:ff01:9:e001::,2001:db8:ff02:9:e001::,2001:db8:ff03:9:e001::"
```

**Must be set on the init container specifically, not the long-running
`credential-refresh` container** — env vars don't propagate across
containers in the same pod, and only the init container runs
`internal/installer.Bootstrap`, which is what actually writes this value
into the conflist that per-pod CNI invocations read.

**Rollout note:** deploy shard nodes, and confirm their `BGPAdvertisement`
is actually present in the mesh, *before* any tenant pod that needs
egress is scheduled — `internal/plumbing/srv6.EgressDefaultRouteAdd`
(called from a pod's own CNI ADD) fails outright if none of the
configured shard SIDs are yet resolvable.

## Verifying

```sh
kubectl get nat66shard -n galactic-system -o wide
kubectl get bgpadvertisement -n galactic-system | grep nat66
```

Metrics, exposed on `GALACTIC_NAT66_METRICS_PORT` (`9182` by default):

| Metric                       | Type    | Labels   | Meaning                                                                                                                                                                    |
| ---------------------------- | ------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_nat66_conns`       | Gauge   | —        | Current row count in this shard's `nat66_conn_table` — a point-in-time snapshot of an LRU, so it can fluctuate independently of actual live traffic under memory pressure. |
| `galactic_nat66_drops_total` | Counter | `reason` | Packets dropped by the `nat66_ingress` program, by reason.                                                                                                                 |

Drop reasons currently defined (`internal/plumbing/ebpf/nat66prog/dropreason.go`):
`no_return_conn`, `malformed_return`, `pat_exhausted`,
`malformed_forward`, `fib_no_neigh`, `fib_unreachable`,
`fib_frag_needed`, `fib_lookup_failed`, `adjust_head_failed`. Note that
NAT66 is TCP/UDP only by design — an ICMP-based reachability test (plain
`ping`) will surface as `malformed_forward`/`malformed_return`, not as a
bug.

```sh
kubectl exec -n galactic-system <galactic-nat66-pod> -- \
  wget -qO- http://localhost:9182/metrics | grep galactic_nat66_
```

Confirm the eBPF program is actually attached — `Ready`'s condition
reason on the `NAT66Shard` object should read `DatapathAttached`, not
`DatapathNotAttached`:

```sh
kubectl get nat66shard <name> -n galactic-system -o jsonpath='{.status.conditions}'
```

## Known constraints

Verified against the current working tree as of this writing — worth
knowing before you rely on this component in production:

- **Not load-balanced across shards.** `EgressDefaultRouteAdd`
  (`internal/plumbing/srv6/egress.go`) installs only the **first
  resolvable** SID from `GALACTIC_CNI_NAT66_SHARD_SIDS` as a tenant VRF's
  default egress route — every other configured shard sits as cold
  standby, not sharing load. An earlier version of this mechanism did
  spread load across all shards via ECMP; that capability was dropped
  during a later datapath migration and has not been reintroduced.
- **No mechanism announces a shard's public address to the actual
  internet border.** `Status.ShardAddress` is reachable fabric-wide via
  BGP/EVPN, but nothing in this repo redistributes it out to a real
  internet-facing edge — only a hardcoded, single-address FRR
  configuration exists, in the containerlab lab only. A production
  deployment needs its own redistribution/border design for this.
- **IPv4 is out of scope.** `nat66.c` rejects non-IPv6 inner packets
  outright; there is no IPv4 masquerade path.
- **No anti-spoofing / trust boundary on ingress to a shard.** The
  datapath trusts fabric-internal traffic; this deserves its own security
  pass before carrying untrusted traffic.
- **`ShardSID`/`ShardPubAddr` are entirely operator-chosen.** There is no
  in-cluster allocator for either value, and no automatic check that a
  chosen SID's Node-ID doesn't collide with a real node's own — see the
  "Node-ID collision hazard" callout above.

## See also

- [docs/nat66/getting-started.md](getting-started.md) — a hands-on
  walkthrough for standing this up from nothing.
- [docs/node-labels.md](../node-labels.md) — the node-labeling strategy
  shared across every Galactic component.
- [docs/router/configuration.md](../router/configuration.md) — the
  `GALACTIC_ROUTER_*` environment variables a NAT66 shard node's
  co-located `galactic-router` process also needs.
- [docs/cni/configuration.md](../cni/configuration.md) — the full
  `galactic-cni` conflist/runtime configuration surface
  `GALACTIC_CNI_NAT66_SHARD_SIDS` is one part of.
