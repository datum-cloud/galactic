# Egress Translation Configuration

This is the reference doc for configuring the sharded, stateful egress
translation tier — NAT66 (IPv6 to IPv6) and NAT64 (IPv6 to IPv4, RFC 6146)
over one binary and one session table. It covers the `galactic-nat`
binary, the `EgressShard` CRD, and the
CNI-side settings that point tenant nodes at it. For a hands-on walkthrough
of standing this up from nothing, see
[docs/nat/getting-started.md](getting-started.md); this document only
covers the "what", not the "why" or the step-by-step.

> Last verified: 2026-09-11 against the current working tree of
> `internal/config/nat.go`, `internal/config/cni.go`,
> `cmd/galactic-nat/`, `config/galactic-nat/`,
> `internal/controller/egressshard_controller.go`, and
> `deploy/containerlab/resources/galactic-nat/`.

## `galactic-nat` configuration (`internal/config/nat.go`)

`galactic-nat` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_NAT` env prefix — the same three-tier precedence pattern
`galactic-router` and `galactic-gateway` use (see
[docs/router/configuration.md](../router/configuration.md)).

| Option              | Environment Variable             | CLI Flag                  | Default | Required          |
| ------------------- | -------------------------------- | ------------------------- | ------- | ----------------- |
| Node name           | `GALACTIC_NAT_NODE_NAME`         | `--node-name`             | —       | Yes               |
| Uplink interface    | `GALACTIC_NAT_UPLINK_INTERFACE`  | `--nat-uplink-interface`  | —       | Yes               |
| Shard SID           | `GALACTIC_NAT_SHARD_SID`         | `--nat-shard-sid`         | —       | Yes               |
| IPv6 masquerade src | `GALACTIC_NAT_SHARD_PUB_ADDR6`    | `--nat-shard-pub-addr6`    | —       | Enables NAT66     |
| IPv4 masquerade src | `GALACTIC_NAT_SHARD_PUB_ADDR4`   | `--nat-shard-pub-addr4`   | —       | Enables NAT64     |
| NAT64 prefix        | `GALACTIC_NAT_NAT64_PREFIX`      | `--nat64-prefix`          | —       | With the above    |
| Metrics port        | `GALACTIC_NAT_METRICS_PORT`      | `--metrics-port`          | `9182`  | No                |
| gRPC health port    | `GALACTIC_NAT_GRPC_HEALTH_PORT`  | `--grpc-health-port`      | `5182`  | No                |

`NATConfig.Validate` enforces all of this at startup — a shard node
deployed wrong crash-loops immediately with an actionable message rather
than running degraded. Specifically:

- The node name, uplink, and shard SID are always required.
- **At least one address family must be turned on.** A shard serving
  neither loads a datapath that claims no packet at all, which presents as
  a silent blackhole rather than as the misconfiguration it is.
- **The NAT64 pair is all-or-nothing.** An IPv4 address with no prefix has
  nothing to translate for; a prefix with no IPv4 address has nothing to
  translate into. Either alone would drop every NAT64 packet sent to it, so
  both are rejected up front rather than at the first packet.

A shard may serve NAT66 only (the shape every shard had before NAT64
existed), NAT64 only, or both. `9182`/`5182` are
chosen to avoid every other `hostNetwork: true` galactic process already
running on a compute node (`fabric-router`'s `179`, `galactic-router`'s
`9179`/`5179`, `galactic-cni`'s `9180`/`5180`, `galactic-gateway`'s
`8081`/`5181`).

### Option details

**`--nat-uplink-interface` / `GALACTIC_NAT_UPLINK_INTERFACE`**
Name of this shard's single fabric-facing uplink interface —
`internal/plumbing/ebpf/natprog`'s XDP program attaches here. Required:
`galactic-nat` only ever runs as a dedicated shard, so there's no
"not this role, skip the datapath" case to fall back to.

**`--nat-shard-sid` / `GALACTIC_NAT_SHARD_SID`**
This shard's own SRv6 uSID (`EgressShardStatus.ShardSID`) — the outer
destination a tenant's egress packet is encapsulated toward. One SID
serves both address families: the datapath decides which translation a
packet gets from its inner destination, so enabling NAT64 needs no second
SID and no second route on any tenant VRF. Must be a
native IPv6 address (`NATConfig.Validate` rejects IPv4 and 4-in-6).
Operator-supplied today; nothing in this repo derives it automatically —
the same gap `BGPRouter.Spec.SRv6Locator`/`NodeID` assignment and
`GALACTIC_GATEWAY_SRV6_ADDRESS` both have.

> **Node-ID collision hazard.** The datapath's `locator_matches` check
> (`internal/plumbing/ebpf/natprog/nat.c`) only compares the top 64
> bits (Block + Node-ID) of a packet's outer destination against this
> value — it does **not** check that the Node-ID is actually reserved for
> the shard. Reusing the physical node's own real `BGPRouter.Spec.NodeID`
> here means the shard's XDP program hijacks that node's own ordinary
> tenant ingress traffic before `usid_ingress` ever gets to it. Reserve a
> distinct Node-ID on the shard's locator for this purpose alone — see
> `deploy/containerlab/resources/galactic-nat/dfw/node-patch.yaml`'s
> comment for the exact encoding the lab uses.

**`--nat-shard-pub-addr6` / `GALACTIC_NAT_SHARD_PUB_ADDR6`**
This shard's own dedicated, publicly-routable IPv6 address
(`EgressShardStatus.ShardAddressIPv6`) — every flow this shard NATs is SNAT'd
to an address:port within it. Must also be a native IPv6 address. Must be
unique per shard: a flow's reply is routed back to the correct shard by
ordinary unicast routing on this address alone, with no hashing on the
return path — two shards sharing an address would make replies
undeliverable or misdelivered.

### Capabilities and host requirements

`galactic-nat` runs `hostNetwork: true` and needs:

| Capability  | Why                                                                                                                                                                        |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NET_ADMIN` | netlink XDP attach                                                                                                                                                         |
| `BPF`       | eBPF program/map creation                                                                                                                                                  |
| `PERFMON`   | the verifier only allows pointer+scalar arithmetic on packet data (the SNAT/un-SNAT and NAT64 header rewrites) when the loading process is `perfmon_capable()`, even running as root |

It also needs a real bpffs already mounted at `/sys/fs/bpf` on the host
(`type: Directory`, not `DirectoryOrCreate` — a missing mount must fail
loudly, not silently pin maps to a plain directory). Every map is pinned
under `/sys/fs/bpf/galactic-nat`.

## `EgressShard` CRD (`network.datumapis.com/v1alpha1`)

One object per shard node, in the `galactic-system` namespace.

| Field                 | Required | Type     | Description                                                                                   |
| --------------------- | -------- | -------- | --------------------------------------------------------------------------------------------- |
| `spec.targetRef.name` | Yes      | `string` | Kubernetes node name this shard's `galactic-nat` process runs on.                           |
| `status.shardSID`         | —        | `string` | This shard's uSID, published by the reconciler from `GALACTIC_NAT_SHARD_SID`; not user-set. |
| `status.shardAddressIPv6` | —        | `string` | This shard's IPv6 masquerade address, from `GALACTIC_NAT_SHARD_PUB_ADDR6`. Empty means no NAT66. |
| `status.shardAddressIPv4` | —        | `string` | This shard's IPv4 masquerade address, from `GALACTIC_NAT_SHARD_PUB_ADDR4`. Empty means no NAT64. |
| `status.nat64Prefix`      | —        | `string` | The `/96` this shard translates for, from `GALACTIC_NAT_NAT64_PREFIX`.                        |
| `status.conditions`       | —        | —        | `Ready` condition, reason `DatapathAttached` or `DatapathNotAttached`.                        |

Leave `status` empty when creating the object — `EgressShardReconciler`
(running inside that node's own `galactic-nat` pod) fills it in from the
pod's own resolved config at startup and publishes a `/128`
`BGPAdvertisement` for each of `shardSID`/`shardAddressIPv6` (the same
RT-less, no-`VRFID`/`Function` shape `NetworkGatewayReconciler` uses for
its own VIP advertisements), so every other node in the mesh learns a
real kernel route to it.

`shardAddressIPv4` is deliberately **not** advertised. A NAT64 reply
arrives from the IPv4 internet rather than across this fabric, so a
`BGPAdvertisement` into the EVPN mesh would not make it reachable by the
party that needs to reach it — the underlay or an upstream announcement
has to attract that address to the node. Publishing it in status is what
makes that prerequisite checkable rather than implicit; a shard whose
`shardAddressIPv4` is set but unreachable translates outbound traffic
correctly and never sees a single reply.

`nat64Prefix` is echoed here for the same class of reason: it is the one
value DNS64 synthesis has to agree with, and a shard translating for a
different prefix than the resolver hands out is a blackhole with no
symptom on either side.

Example:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: EgressShard
metadata:
  name: dfw-worker-egress
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: dfw-worker
```

### RBAC

`config/galactic-nat/rbac.yaml` grants the `galactic-nat`
ServiceAccount exactly: `get`/`list`/`watch`/`update`/`patch` on
`egressshards` (+`/status`), full CRUD on `bgpadvertisements`, and
read-only `get`/`list`/`watch` on `bgprouters` — nothing more. It
deliberately does **not** grant `networkegresspolicies`; that CRD belongs
to an earlier, superseded design this sharded egress tier replaced.

## Shard membership (`galactic-cni` side)

A tenant's compute node needs to know the fabric-wide list of live shard
SIDs to install its own tenant VRFs' egress routes, and the NAT64 prefix to
install a route toward IPv4 reachability. Both are separate from anything
on the shard nodes themselves.

| Option               | Environment Variable              | Set on                                            | Default                         | Required |
| -------------------- | --------------------------------- | ------------------------------------------------- | ------------------------------- | -------- |
| Live shard SID list  | `GALACTIC_CNI_EGRESS_SHARD_SIDS`  | `galactic-cni`'s `install-cni` **init** container | _(empty — no shard configured)_ | No       |
| NAT64 prefix         | `GALACTIC_CNI_NAT64_PREFIX`       | `galactic-cni`'s `install-cni` **init** container | _(empty — no NAT64)_            | No       |

One SID per shard covers both address families, so enabling NAT64 adds no
entry to the SID list — only the prefix.

`GALACTIC_CNI_NAT64_PREFIX` must be the same `/96` the shards are
configured with and the same one DNS64 synthesizes into. All three have to
agree; any disagreement is a blackhole rather than an error. Setting it
gives each tenant VRF a more-specific route for that prefix alongside the
`::/0` default. Both point at the same shard SID, so the second route
exists to make the prefix reachable where no default route covers it — a
fabric may offer NAT64 without NAT66, and then there is no default for that
traffic to fall into.

`GALACTIC_CNI_EGRESS_SHARD_SIDS` is a comma-separated list of every live
shard's `Status.ShardSID`, resolved with env > conflist > default
precedence by `internal/config.CNIConfig`, written into the static
conflist by `internal/installer.Bootstrap`, and read back by
`internal/cnibgp` on every CNI ADD. An empty value means "no NAT66
configured for this fabric" — not an error; pods simply get no egress
default route toward any shard. Example (containerlab lab value, three
shards):

```yaml
- name: GALACTIC_CNI_EGRESS_SHARD_SIDS
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
kubectl get egressshard -n galactic-system -o wide
kubectl get bgpadvertisement -n galactic-system | grep nat66
```

Metrics, exposed on `GALACTIC_NAT_METRICS_PORT` (`9182` by default):

| Metric                       | Type    | Labels   | Meaning                                                                                                                                                                    |
| ---------------------------- | ------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_nat_conns`       | Gauge   | —        | Current row count in this shard's `nat_conn_table` — a point-in-time snapshot of an LRU, so it can fluctuate independently of actual live traffic under memory pressure. |
| `galactic_nat_drops_total` | Counter | `reason` | Packets dropped by the `nat_ingress` program, by reason.                                                                                                                 |

Drop reasons currently defined (`internal/plumbing/ebpf/natprog/dropreason.go`):
`no_return_conn`, `malformed_return`, `pat_exhausted`,
`malformed_forward`, `fib_no_neigh`, `fib_unreachable`,
`fib_frag_needed`, `fib_lookup_failed`, `adjust_head_failed`. Note that
NAT66 is TCP/UDP only by design — an ICMP-based reachability test (plain
`ping`) will surface as `malformed_forward`/`malformed_return`, not as a
bug.

```sh
kubectl exec -n galactic-system <galactic-nat-pod> -- \
  wget -qO- http://localhost:9182/metrics | grep galactic_nat_
```

Confirm the eBPF program is actually attached — `Ready`'s condition
reason on the `EgressShard` object should read `DatapathAttached`, not
`DatapathNotAttached`:

```sh
kubectl get egressshard <name> -n galactic-system -o jsonpath='{.status.conditions}'
```

## Known constraints

Verified against the current working tree as of this writing — worth
knowing before you rely on this component in production:

- **Not load-balanced across shards.** `EgressDefaultRouteAdd`
  (`internal/plumbing/srv6/egress.go`) installs only the **first
  resolvable** SID from `GALACTIC_CNI_EGRESS_SHARD_SIDS` as a tenant VRF's
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
- **IPv4 is out of scope.** `nat.c` rejects non-IPv6 inner packets
  outright; there is no IPv4 masquerade path.
- **No anti-spoofing / trust boundary on ingress to a shard.** The
  datapath trusts fabric-internal traffic; this deserves its own security
  pass before carrying untrusted traffic.
- **`ShardSID`/`ShardPubAddr6` are entirely operator-chosen.** There is no
  in-cluster allocator for either value, and no automatic check that a
  chosen SID's Node-ID doesn't collide with a real node's own — see the
  "Node-ID collision hazard" callout above.

## See also

- [docs/nat/getting-started.md](getting-started.md) — a hands-on
  walkthrough for standing this up from nothing.
- [docs/node-labels.md](../node-labels.md) — the node-labeling strategy
  shared across every Galactic component.
- [docs/router/configuration.md](../router/configuration.md) — the
  `GALACTIC_ROUTER_*` environment variables a NAT66 shard node's
  co-located `galactic-router` process also needs.
- [docs/cni/configuration.md](../cni/configuration.md) — the full
  `galactic-cni` conflist/runtime configuration surface
  `GALACTIC_CNI_EGRESS_SHARD_SIDS` is one part of.
