# Egress Translation Configuration

This is the reference doc for configuring the sharded, stateful egress
translation tier — NAT66 (IPv6 to IPv6) and NAT64 (IPv6 to IPv4, RFC 6146)
over one binary and one session table. It covers the `galactic-nat`
binary, the `EgressShard` CRD, and the
CNI-side settings that point tenant nodes at it. For a hands-on walkthrough
of standing this up from nothing, see
[docs/nat/getting-started.md](getting-started.md); this document only
covers the "what", not the "why" or the step-by-step.

> Last verified: 2026-09-25 against the current working tree of
> `internal/config/nat.go`, `internal/config/cni.go`,
> `cmd/galactic-nat/`, `config/galactic-nat/`,
> `internal/plumbing/ebpf/natattach/`,
> `internal/controller/egressshard_controller.go`, and
> `deploy/containerlab/resources/galactic-nat/`.

## Placement

`galactic-nat` runs on every `galactic.datumapis.com/node: edge` node that
also carries `galactic.datumapis.com/nat: enabled`, one DaemonSet per
cluster, alongside `galactic-vrf` and, on nodes that opt into it,
`galactic-gateway` (see [docs/node-labels.md](../node-labels.md)). An edge
node without `nat=enabled`, a compute node, an unlabeled node and a
control-plane node never run a shard. A shard there is one hop from the
transit its masquerade addresses are originated into. Compute nodes run no
shard: each compute node's tenant egress is SRv6-encapsulated toward its own
site's edge shards (`GALACTIC_CNI_EGRESS_SHARD_SIDS`, [below](#shard-membership-galactic-cni-side)).

`galactic-nat` used to run on compute nodes, one shard each. It moved because
an edge node is where both a masquerade address and its replies belong; the
move is also why it now shares that node's XDP hook with the gateway (see
`GALACTIC_NAT_XDP_ATTACH`, under Option details below).

## `galactic-nat` configuration (`internal/config/nat.go`)

`galactic-nat` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_NAT` env prefix — the same three-tier precedence pattern
`galactic-router` and `galactic-gateway` use (see
[docs/router/configuration.md](../router/configuration.md)).

| Option             | Environment Variable             | CLI Flag                  | Default       | Required |
| ------------------ | -------------------------------- | ------------------------- | ------------- | -------- |
| Node name          | `GALACTIC_NAT_NODE_NAME`         | `--node-name`             | —             | Yes      |
| Uplink interfaces  | `GALACTIC_NAT_UPLINK_INTERFACES` | `--nat-uplink-interfaces` | auto-detected | No       |
| XDP attach mode    | `GALACTIC_NAT_XDP_ATTACH`        | `--nat-xdp-attach`        | `direct`      | No       |
| Datapath enabled   | `GALACTIC_NAT_DATAPATH_ENABLED`  | `--nat-datapath-enabled`  | `true`        | No       |
| Echo responder     | `GALACTIC_NAT_ECHO_RESPONDER`    | `--nat-echo-responder`    | `false`       | No       |
| Procfs sysctl root | `GALACTIC_NAT_PROC_SYS_PATH`     | `--nat-proc-sys-path`     | `/proc/sys`   | No       |
| Metrics port       | `GALACTIC_NAT_METRICS_PORT`      | `--metrics-port`          | `9182`        | No       |
| gRPC health port   | `GALACTIC_NAT_GRPC_HEALTH_PORT`  | `--grpc-health-port`      | `5182`        | No       |

`config/galactic-nat/base/daemonset.yaml` leaves `GALACTIC_NAT_XDP_ATTACH`
at the binary's default, `direct`. `dispatch` is the mode to move to: it is
what lets a shard restart without bouncing its uplinks, and what lets it share
them with `galactic-gateway`, which runs from the same dispatcher by default.

That is the whole process configuration. The shard's identity — its SID,
masquerade addresses and NAT64 prefix — is not process configuration: it
comes from the spec of the `EgressShard` targeting this node (see
[below](#egressshard-crd-networkdatumapiscomv1alpha1)). The process attaches
its datapath at startup with no identity and programs one on reconcile, so a
node without an `EgressShard` runs attached but claims no packet rather than
crash-looping.

`9182`/`5182` are chosen to avoid every other `hostNetwork: true` galactic
process already running on an edge node (`fabric-router`'s `179`, `9342` and
`9343`, `galactic-router`'s `9179`/`5179`, `galactic-cni`'s `9180`/`5180`,
`galactic-gateway`'s `8081`/`5181`).

### Option details

**`--nat-uplink-interfaces` / `GALACTIC_NAT_UPLINK_INTERFACES`**
Comma-separated override for this shard's fabric-facing uplink interfaces —
`internal/plumbing/ebpf/natprog`'s XDP program attaches to every one of
them. Unset, they are auto-detected with the same derivation
`galactic-cni`'s SRv6 datapath uses: every interface carrying the IPv6
default route or a BGP-learned route, skipping tunnels, VRF slaves and
loopback (`attach.DetectUplinks`). Either way a bonding master resolves to
its slaves, never to itself, since native XDP on a master is unreliable
(`natattach.ResolveUplinks`).

Set it on a node where detection is ambiguous — typically one whose
management NIC carries the IPv6 default route, as Kind's `eth0` does in the
containerlab lab. Detection would attach there too.

> **Name every fabric uplink, not just the primary.** The datapath claims
> a packet only on an interface its program is attached to. An
> SRv6-encapsulated tenant packet arriving on an uplink with no program
> reaches no translation at all and is forwarded untranslated and
> uncounted. A shard covers only the uplinks it resolves, so an uplink the
> override leaves out is one its `Ready` condition and every counter it
> exports never see. On a
> multi-homed shard node, naming one uplink therefore makes the shard role
> last only as long as that uplink does.

A bonding master can be named in place of its members. It is expanded to
its slaves at startup and the program attached to each of them, never to
the master itself, the same way `galactic-gateway` treats a bonded public
interface. As with the gateway, every resolved interface is checked for
native XDP support before any is touched, and the slaves are attached one
at a time, each waited back into its LACP aggregate before the next, so a
NIC whose driver drops carrier to attach a native XDP program bounces one
member of the bond at a time rather than all of them at once. A slave that
does not rejoin within 45 seconds fails the shard's startup with the
remaining slaves left untouched. Neither guard helps a bond with `miimon`
at 0, which never notices a bounced slave coming back.

The startup attach is all-or-nothing: a shard that cannot attach to every
interface it resolves at startup fails to start, rather than coming up
with a hole in its coverage. A shard that resolves no uplink at all, with
auto-detection on a node that has not learned a fabric route yet, waits
for one instead, within the startup probe's window.

After startup the shard keeps its uplinks current. Every netlink link or
route change, and every 30 seconds without one, resolves them again, and
an uplink that appears — routing converging over a second link, a bond
gaining or replacing a member — is attached through the same checks, one
at a time. A bond member that is the only one carrying traffic is not
attached until a sibling is, since the bounce would take the bond down. An
uplink that stops resolving keeps its program for as long as the interface
exists, because detaching bounces the link just as attaching does. While
any resolved uplink lacks the program, the `EgressShard`'s `Ready`
condition reads `False` with reason `UplinksMissing`, naming them, and the
pod's `readiness` gRPC health service, which the readinessProbe checks,
reports not serving. Liveness is unaffected, so the pod is not restarted.

In dispatch mode the shard attaches nothing of its own, so the uplinks are
used for the forwarding sysctls and to check coverage. An uplink
whose traffic does not reach the shard's program is reported missing the
same way.

**`--nat-xdp-attach` / `GALACTIC_NAT_XDP_ATTACH`**
How the datapath reaches its uplinks' XDP hook: `direct` or `dispatch`. The
retired `chain` is read as `dispatch`, with a warning. Any other value fails
validation at startup. A node that ran `chain` upgrades the gateway and the
shard together: a shard on this release cannot share an uplink with a gateway
that still holds the hook directly, and reports those uplinks missing until
the gateway joins the dispatcher.

- **`direct`** (the binary's default) attaches `nat_ingress` to every
  resolved uplink in native driver mode, as described above. The attachment
  is not pinned, so it detaches when the process exits, and every restart
  bounces each uplink, once on the detach and again on the attach. On a
  node where an earlier `dispatch`-mode shard left the node's XDP
  dispatcher on the uplinks, direct mode detaches it
  first, if no other datapath's slot is live there. If one is, direct mode
  fails to start and names the uplink, since detaching the dispatcher would
  cut that datapath's traffic. Only the uplinks resolved at startup are
  released: an uplink found later that still carries the dispatcher is
  reported missing until `hack/xdp-dispatch-release.sh` frees it.
- **`dispatch`** puts the node's shared XDP dispatcher on every resolved
  uplink and runs `nat_ingress` from the dispatcher's egress slot. The
  dispatcher is one small root program, `xdp_dispatch`, that holds the hook
  for every datapath on the node and hands each packet to the slots its
  interface's roles allow: the gateway's load balancer and return program,
  then the shard. Its state is pinned under `/sys/fs/bpf/galactic-xdp`: the
  maps and root under `v1/`, one link per interface under `links/`.

  Because the links are pinned, the root stays attached when the shard's
  process exits. The next process swaps its program into the slot, which the
  kernel does atomically, so a restart neither bounces an uplink nor misses a
  packet. The shard renews its slot's lease every 10s; a slot whose lease is
  more than 120s old is skipped, so a shard that was removed, or that has been
  down that long, stops claiming packets instead of translating with state
  nothing maintains.

  Nothing in dispatch mode is all-or-nothing. An uplink the dispatcher cannot
  hold yet, because another XDP program is attached there, the driver has no
  native XDP, or attaching would take a bond down, is reported missing and
  retried on the next link or route change. The first attach to each bond
  member, and the wait for it to rejoin its bond, run under a node-wide lock,
  so two datapaths sharing the dispatcher never bounce two members of one bond
  at once.

  The dispatcher stays attached after the shard is removed from a node.
  `hack/xdp-dispatch-release.sh` detaches it. Run it before rolling back to
  an image that predates dispatch mode, which would otherwise fail to attach
  with `EBUSY`.
**`--nat-datapath-enabled` / `GALACTIC_NAT_DATAPATH_ENABLED`**
Whether the shard runs its datapath. On by default. Off, the process stays
up and its pod ready, but it attaches nothing, empties its dispatcher slot if
an earlier process filled one, and keeps the node's `EgressShard`
unprogrammed: `Ready` and `Programmed` both read `False` with reason
`DatapathDisabled`, no identity is published, and its `BGPAdvertisement` is
withdrawn, so the fabric stops sending egress traffic to the node. Any other
datapath on the node, and the dispatcher itself, are left alone. Turning it
back on takes a pod restart, which in dispatch mode bounces nothing.

**`--nat-echo-responder` / `GALACTIC_NAT_ECHO_RESPONDER`**
Whether the shard answers an ICMP or ICMPv6 Echo Request addressed to one of
its own masquerade addresses. Off by default, and set explicitly to `false` in
`config/galactic-nat/base/daemonset.yaml`: the datapath drops such a request
and counts it as `icmp_unsolicited`. Turn it on to check from the internet that
a masquerade address reaches its shard — the reply comes from the datapath on
that shard, so an answer proves the underlay delivers the address there.

Replies come out of a token bucket per CPU (see Known constraints); a refused
reply counts as `icmp_rate_limited`. The setting is written into the datapath
whenever the shard programs its identity, so changing it takes a pod restart
and nothing else.

**`--nat-proc-sys-path` / `GALACTIC_NAT_PROC_SYS_PATH`**
The procfs root the datapath writes its forwarding sysctls under:
`net.ipv6.conf.<iface>.forwarding` and `net.ipv6.conf.all.forwarding`, plus
the IPv4 ones once the shard serves NAT64. `bpf_fib_lookup` refuses every
lookup on an interface with forwarding off, so a sysctl that does not read
`1` after the write stops the shard at startup, and leaves an uplink found
later uncovered until it does. A pod that is not privileged gets `/proc/sys`
read-only, so `config/galactic-nat/base/daemonset.yaml` mounts the host's
`/proc/sys/net` at `/host/proc/sys/net` and sets this to `/host/proc/sys`. A
node where something else already turned forwarding on passes with the
default too. SELinux policy on an enforcing node can still refuse the write,
and the shard then says so at startup.

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
under `/sys/fs/bpf/galactic-nat`. In dispatch mode it also pins the node's
XDP dispatcher under `/sys/fs/bpf/galactic-xdp`, which the same `/sys/fs/bpf`
mount covers.

## `EgressShard` CRD (`network.datumapis.com/v1alpha1`)

One object per shard node, in the `galactic-system` namespace. The spec
assigns the shard's identity; the `galactic-nat` process on the target node
programs its datapath from it and reports what it is actually programmed
with in status.

| Field                              | Required | Type     | Description                                                                                            |
| ---------------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------------ |
| `spec.targetRef.name`              | Yes      | `string` | Kubernetes node name this shard's `galactic-nat` process runs on.                                      |
| `spec.shardSID`                    | No       | `string` | This shard's SRv6 uSID. Write-once.                                                                    |
| `spec.shardAddressIPv6`            | No       | `string` | IPv6 masquerade source. Setting it enables NAT66. Write-once.                                          |
| `spec.shardAddressIPv4`            | No       | `string` | IPv4 masquerade source. Setting it, with `nat64Prefix`, enables NAT64. Write-once.                     |
| `spec.nat64Prefix`                 | No       | `string` | The fabric-wide `/96` this shard translates to IPv4. Set together with `shardAddressIPv4`. Write-once. |
| `spec.translateWellKnownPrefix`    | No       | `bool`   | Also translate the RFC 6052 Well-Known Prefix `64:ff9b::/96`. Requires `nat64Prefix`. Mutable.         |
| `status.shardSID`                  | —        | `string` | The SID the datapath is programmed with.                                                               |
| `status.shardAddressIPv6`          | —        | `string` | The IPv6 masquerade source the datapath is programmed with. Empty means no NAT66.                      |
| `status.shardAddressIPv4`          | —        | `string` | The IPv4 masquerade source the datapath is programmed with. Empty means no NAT64.                      |
| `status.nat64Prefix`               | —        | `string` | The `/96` the datapath is programmed to translate.                                                     |
| `status.translatesWellKnownPrefix` | —        | `bool`   | Whether the datapath is programmed to translate `64:ff9b::/96` too.                                    |
| `status.conditions`                | —        | —        | `Ready` (datapath on every uplink) and `Programmed` (datapath translating with the spec's identity).   |

Every identity field except `translateWellKnownPrefix` is optional and
write-once. A shard can exist before its identity is assigned, and gains it
later with a spec update; once assigned, a value cannot change or be
cleared, because the datapath claims return traffic by exact match on it and
a change strands every established flow. A shard holding the wrong identity is deleted and recreated instead.

The datapath needs a SID and at least one family before it translates
anything:

| `Programmed` reason   | Meaning                                                                                                                      |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `AddressesProgrammed` | The datapath translates with the identity the spec assigns.                                                                  |
| `AddressUnassigned`   | The spec assigns no SID, or no masquerade address for either family. The datapath is cleared and claims nothing.             |
| `LocatorConflict`     | The SID's Block and Node-ID equal a `BGPRouter`'s. The datapath is cleared and claims nothing. The message names the router. |
| `ProgrammingFailed`   | The datapath rejected the identity, for example a NAT64 prefix that is not a `/96`. The message says why.                    |
| `ShardConflict`       | More than one `EgressShard` targets this node. None is programmed until only one does.                                       |

`EgressShardReconciler` (running inside that node's own `galactic-nat` pod)
publishes one `BGPAdvertisement` per shard, built from status rather than
spec so the fabric only learns an identity the node actually translates
with: the SID's covering `/64` and `shardAddressIPv6` as a `/128`, in the
same RT-less, no-`VRFID`/`Function` shape `NetworkGatewayReconciler` uses
for its own VIP advertisements. Every other node in the mesh learns a real
kernel route to both. Deleting the shard, or leaving it with no usable
identity, clears the datapath and withdraws the advertisement.

> **Node-ID collision hazard.** The datapath's `locator_matches` check
> (`internal/plumbing/ebpf/natprog/nat.c`) only compares the top 64
> bits (Block + Node-ID) of a packet's outer destination against
> `shardSID`. A shard reusing a `BGPRouter`'s `srv6Locator` and `nodeID`
> would capture that router's tenant ingress before `usid_ingress` ever
> gets to it, so `EgressShardReconciler` checks the SID against every
> `BGPRouter` in the cluster and refuses one that matches, with
> `Programmed=False` reason `LocatorConflict`. Reserve a distinct Node-ID
> on the shard's locator for this purpose alone — see
> `deploy/containerlab/resources/galactic-nat/dfw/egressshard.yaml` for
> the exact encoding the lab uses.

`shardAddressIPv6` must be unique per shard: a flow's reply is routed back
to the correct shard by ordinary unicast routing on this address alone, with
no hashing on the return path — two shards sharing an address would make
replies undeliverable or misdelivered.

`shardAddressIPv4` is deliberately **not** advertised. A NAT64 reply
arrives from the IPv4 internet rather than across this fabric, so a
`BGPAdvertisement` into the EVPN mesh would not make it reachable by the
party that needs to reach it — the underlay or an upstream announcement
has to attract that address to the node. Publishing it in status is what
makes that prerequisite checkable rather than implicit; a shard whose
`shardAddressIPv4` is set but unreachable translates outbound traffic
correctly and never sees a single reply.

> **The underlay has to carry both masquerade addresses, and nothing in
> this repo puts them there.** The EVPN Type 5 path for
> `shardAddressIPv6` makes it reachable from other nodes on the fabric and
> from nowhere else — the plain-unicast underlay carries no EVPN, and a
> masqueraded flow's reply comes back from a host that is not on the
> fabric at all. Unless the underlay holds a route attracting each address
> to *this* node, that reply is forwarded on whatever default the first
> router holding no route for it has, and the flow is one-way while every
> forward-path counter stays green (#549).
>
> Origination has to come from the shard's own node, not from an
> aggregate elsewhere: the address must reach the node whose datapath
> holds that flow's connection state. The lab does it by having each
> shard node — an edge node — originate its own two addresses (a `/64`
> and a `/32`) through its `fabric-router`, along with its SID's covering
> `/64` — see
> `deploy/containerlab/resources/fabric-router/dfw/frr.conf.dfw-worker2`,
> and `task -d deploy/containerlab verify:nat-return-route` for the check
> that proves it. Where those addresses come from in the first place is
> #409.

`nat64Prefix` has to agree with DNS64 synthesis: a shard translating for a
different prefix than the resolver hands out is a blackhole with no symptom
on either side.

A shard translates only to globally reachable IPv4 destinations, whatever
the prefix. An address under `nat64Prefix` that embeds a special-purpose
IPv4 address the IANA registry marks not globally reachable (RFC 6890:
private, shared, loopback, link-local, documentation, benchmarking and
the like), or a multicast or reserved one, is dropped and counted as
`nat64_non_global_dest`, the rule RFC 6052 section 3.1 sets for the
Well-Known Prefix.

`translateWellKnownPrefix: true` translates `64:ff9b::/96` alongside
`nat64Prefix`, to the same `shardAddressIPv4`, so tenants whose resolver is
a public DNS64 service reach IPv4-only destinations. A reply returns from
the address the tenant sent to, under whichever prefix it used. An ICMPv4
error about a Well-Known Prefix flow from a non-global router is dropped as
`icmp_untranslatable`, since RFC 6052 forbids synthesizing that source.
Toggling it reprograms the running shard. Turning it off sends every
`64:ff9b::/96` packet, open flows included, down the NAT66 path, which
blackholes destinations tenants already resolved until their DNS TTLs
expire. Tenants reach the prefix only once
`GALACTIC_CNI_NAT64_PREFIX` lists it alongside the NSP (see
[below](#shard-membership-galactic-cni-side)).

Example:

```yaml
apiVersion: network.datumapis.com/v1alpha1
kind: EgressShard
metadata:
  name: dfw-worker2-egress
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: dfw-worker2
  shardSID: "2001:db8:ff01:2002:e001::"
  shardAddressIPv6: "2001:db8:9966:1::1"
  shardAddressIPv4: "192.0.2.1"
  nat64Prefix: "2001:db8:64::/96"
  translateWellKnownPrefix: true
```

### RBAC

`config/galactic-nat/rbac.yaml` grants the `galactic-nat`
ServiceAccount exactly: `get`/`list`/`watch`/`update`/`patch` on
`egressshards` (+`/status`), full CRUD on `bgpadvertisements`, and
read-only `get`/`list`/`watch` on `bgprouters` — nothing more. It
deliberately does **not** grant `networkegresspolicies`; that CRD belongs
to an earlier, superseded design this sharded egress tier replaced.

## Shard membership (`galactic-cni` side)

A tenant's compute node needs to know which shard SIDs to install its own
tenant VRFs' egress routes toward — in practice its own site's edge shards, and the NAT64 prefix to
install a route toward IPv4 reachability. Both are separate from anything
on the shard nodes themselves.

| Option               | Environment Variable              | Set on                                            | Default                         | Required |
| -------------------- | --------------------------------- | ------------------------------------------------- | ------------------------------- | -------- |
| Live shard SID list  | `GALACTIC_CNI_EGRESS_SHARD_SIDS`  | `galactic-cni`'s `install-cni` **init** container | _(empty — no shard configured)_ | No       |
| NAT64 prefixes       | `GALACTIC_CNI_NAT64_PREFIX`       | `galactic-cni`'s `install-cni` **init** container | _(empty — no NAT64)_            | No       |

One SID per shard covers both address families, so enabling NAT64 adds no
entry to the SID list — only the prefixes.

`GALACTIC_CNI_NAT64_PREFIX` is a comma-separated list of IPv6 `/96`
prefixes, for example `2001:db8:64::/96,64:ff9b::/96` to serve a
Network-Specific Prefix alongside the RFC 6052 Well-Known Prefix that public
DNS64 resolvers synthesize into. A single prefix is a one-entry list. An
entry that does not parse, is not IPv6, is not a `/96`, or repeats another
fails every attachment ADD. Each prefix must be one the shards translate and
one DNS64 synthesizes into; any disagreement is a blackhole rather than an
error. Setting it gives each tenant VRF a more-specific route per prefix
alongside the `::/0` default. Both point at the same shard SID, so the second route
exists to make the prefix reachable where no default route covers it — a
fabric may offer NAT64 without NAT66, and then there is no default for that
traffic to fall into.

`GALACTIC_CNI_EGRESS_SHARD_SIDS` is a comma-separated list of every live
shard's `status.shardSID`, resolved with env > conflist > default
precedence by `internal/config.CNIConfig`, written into the static
conflist by `internal/installer.Bootstrap`, and read back by
`internal/cnibgp` on every CNI ADD. An empty value means "no NAT66
configured for this fabric" — not an error; pods simply get no egress
default route toward any shard.

Set it per site, to that site's own edge shards only. The first SID that
resolves at CNI ADD wins, so the list is ordered: the first entry is the
active shard and any later one is taken only by an attachment made while the
earlier ones cannot be resolved. With no other site's shard in the list, a
site whose shards are all unreachable fails the attachment instead of
sending its egress out through another site's edge. In hashed mode
([Active/active egress](#active-active-egress)) the cluster's `EgressShard`s
decide placement instead, and this list only matters when switching back.
Example (containerlab
lab, dfw's two edge shards; sjc and iad list their single edge shard):

```yaml
- name: GALACTIC_CNI_EGRESS_SHARD_SIDS
  value: "2001:db8:ff01:2002:e001::,2001:db8:ff01:2003:e001::"
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

## Active/active egress

By default a compute node sends each tenant VRF to one shard: the first entry
of `GALACTIC_CNI_EGRESS_SHARD_SIDS` that resolves, with every later entry
standing by. Hashed mode spreads tenants across every healthy shard in the
cluster instead, so each shard carries a share of the metro's egress and
losing one costs only the sessions it held. Staging and production rollout,
and rollback, follow
[active-active-rollout.md](active-active-rollout.md).

| Option                | Environment Variable                  | Set on                                          | Default   |
| --------------------- | ------------------------------------- | ----------------------------------------------- | --------- |
| Egress mode           | `GALACTIC_CNI_EGRESS_MODE`            | `galactic-cni`'s `credential-refresh` container | `ordered` |
| Hash                  | `GALACTIC_CNI_EGRESS_HASH`            | `galactic-cni`'s `credential-refresh` container | `source`  |
| Pin idle timeout      | `GALACTIC_CNI_EGRESS_PIN_IDLE`        | `galactic-cni`'s `credential-refresh` container | `2h4m`    |
| Pool minimum (alerts) | `GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE` | `galactic-cni`'s `credential-refresh` container | `1`       |

Unlike the shard list, these are read by `galactic-cni run`, the long-running
container, not by the init container. A value that does not parse stops the
container at startup rather than falling back to ordered mode, and so does
hashed mode with more than three NAT64 prefixes in
`GALACTIC_CNI_NAT64_PREFIX`.

### Prerequisites

- **The `EgressShard` CRD with `spec.drain`.** `galactic-cni` is built
  against the `network` API version that adds it, but a Go dependency does
  not change a cluster's schema: install the CRD from that `network` release
  in every cluster first. Without it the API server prunes `spec.drain` and
  a drain silently does nothing. Check by writing the field and reading it
  back:
  `kubectl patch egressshard <name> -n galactic-system --type=merge -p '{"spec":{"drain":false}}'`
  then `kubectl get egressshard <name> -n galactic-system -o jsonpath='{.spec.drain}'`
  must print `false`.
- **`galactic-cni` may watch `EgressShard`s.** `config/galactic-cni/rbac.yaml`
  grants `get`, `list` and `watch` on `egressshards`;
  `kubectl auth can-i watch egressshards.network.datumapis.com -n galactic-system --as=system:serviceaccount:galactic-system:galactic-cni`
  must answer `yes`.
- **Every shard has its own identity and return route.** Each shard needs a
  distinct `shardSID` locator, a distinct `shardAddressIPv6` and, for NAT64,
  a distinct `shardAddressIPv4`, each originated from that shard's own node.
  In ordered mode only the first shard carried traffic, so a second shard's
  addresses may never have been tested: check that a reply to each of them
  reaches that shard before tenants are spread onto it.

### How a shard is chosen

- **One group per translation class.** A compute node needs `::/0` for
  NAT66 and one route per entry of `GALACTIC_CNI_NAT64_PREFIX` for NAT64.
  Each route names the group for its class, and a group holds only the shards
  that can translate that class: NAT66 needs a `shardAddressIPv6`; NAT64
  toward a prefix needs a `shardAddressIPv4` and that prefix as the shard's
  `nat64Prefix`, or, for the Well-Known Prefix `64:ff9b::/96`,
  `translatesWellKnownPrefix`. A NAT66-only shard therefore never receives
  NAT64 traffic, and a shard translating another NAT64 prefix never receives
  this one's. A shard that is ready but cannot serve a class is counted as
  `ineligible` for it and logged. A class no shard can serve gets no route,
  as an empty shard list gives none, and `GalacticEgressClassUnserved`
  fires. A cluster whose shards all serve one family is a legitimate
  single-family deployment.
- **The pool is the cluster.** One metro is one cluster, so a class's pool is
  every eligible `EgressShard` in `galactic-cni`'s namespace. A shard is a
  candidate once its status carries a `shardSID` and both `Programmed` and
  `Ready` are `True`, and it is not being deleted.
  `GALACTIC_CNI_EGRESS_SHARD_SIDS` is not used for placement in hashed mode.
- **A shard counts only while it is reachable.** A dead node's `EgressShard`
  status goes stale, but its BGP session drops and the route to its SID is
  withdrawn. A candidate takes tenants only while its SID resolves to a
  neighbor on an SRv6 uplink. `galactic-cni` rebuilds the groups on every
  route or neighbor change that can affect a candidate, and every 30 seconds
  as a backstop, so failover takes as long as BGP takes to withdraw the
  route, plus a fraction of a second.
- **The datapath picks per packet.** `usid_egress` hashes the packet and looks
  the hash up in the group's 1021-slot Maglev table. When a shard joins or
  leaves, about `1/N` of tenant addresses move.
- **Placement is per node.** The hash includes the VRF's Linux routing table
  ID, which each compute node allocates for itself. Every node builds the same
  Maglev table, but the same tenant address on two nodes may land on two
  shards. Nothing depends on it doing otherwise: a tenant's NAT sessions,
  its pins and the source SID a shard replies to are all specific to the node
  it runs on, so a workload that moves to another node starts new sessions
  wherever it lands.
- **`source` hashes the tenant's address.** Every connection from one tenant
  address uses one shard per class and so one public address per family,
  which RFC 4787 REQ-2 asks for and which sites that tie a login to the
  client address rely on. One heavy tenant address can never use more than
  one shard. `flow` hashes the 5-tuple and spreads that address over every
  shard, but gives up the single public address. Placement balances
  addresses (or flows), not bytes: shards serving a few heavy tenants carry
  more traffic than their count suggests.
- **Fragments.** In `flow` mode every fragment of a datagram, the first
  included, hashes on its addresses and protocol only, so the fragments of
  one datagram reach one shard. That keeps the shard choice consistent; it
  says nothing about whether the shard translates fragments, which the NAT
  datapath does not fully support (see Known constraints).
- **Pins hold sessions in place.** The first packet from a tenant address
  (in `flow` mode, from a flow) records the shard it went to. Later packets
  follow that pin while the shard is reachable, even after a new shard joins
  or the pinned shard starts draining. A pin expires after
  `GALACTIC_CNI_EGRESS_PIN_IDLE` without a packet, which matches the shard's
  longest idle timeout, so a pin never outlives the session it protects. Pins
  live in a 65536-entry LRU on each compute node and are not shared between
  nodes. One evicted under pressure falls back to the Maglev table, which
  gives the same shard unless the membership changed since it was made. `0`
  turns pins off.
- **Sessions are not replicated.** A session lives on one shard. When a shard
  fails, its sessions break and their tenants are placed elsewhere; only
  sessions on surviving shards continue.

### Draining and removing a shard

Removing a shard without breaking its sessions takes three steps:

1. Set `spec.drain: true`:

   ```sh
   kubectl patch egressshard <name> -n galactic-system --type=merge -p '{"spec":{"drain":true}}'
   ```

   A draining shard takes no new tenant address, and every pinned one keeps
   reaching it until it goes idle. The shard itself changes nothing: it keeps
   translating, advertising its SID and receiving replies.
2. Wait for its sessions to end: `galactic_nat_sessions` on its node falls to
   zero, or to a level you accept losing. A tenant address that keeps
   sending refreshes its pin forever and keeps the shard busy; drain cannot
   move it without breaking its sessions, so decide how long to wait.
3. Delete the `EgressShard` (and remove the node's `nat=enabled` label).

Deleting an `EgressShard` is not a drain. Deletion withdraws the shard's
advertisement and clears its datapath at once, every session on it breaks,
and `galactic-cni` drops it from every group as soon as it sees the deletion.
With pins turned off (`GALACTIC_CNI_EGRESS_PIN_IDLE=0`) there is nothing to
hold a tenant on a draining shard, so draining moves every one of its tenant
addresses at once and breaks their sessions just as a failure would.

### When nothing is reachable

There is no spill-over to another metro. When no shard of a class is
reachable, a new attachment fails its ADD, as it does in ordered mode, and an
existing VRF's packets of that class are dropped and counted as `group_empty`
rather than sent untranslated into the node's main table. A cluster with no
`EgressShard` at all gives VRFs no egress route, which is not an error.

### How the groups are published

A group is one immutable snapshot: its Maglev table and every member's SID,
next hop, drain state and slot generation in a single value. `galactic-cni`
writes a new one-entry inner map for every change and swaps it into
`egress_shard_groups`, an `ARRAY_OF_MAPS`, in one update. A packet therefore
sees the old snapshot or the new one, never a mix of the two; an earlier
design that updated ordinary array values in place let a packet read one
shard's SID with another's MAC addresses while a slot was rewritten.

Every member slot carries a generation that identifies the shard's tenure of
it; a pin is honoured only while its slot still carries the generation it
recorded. Generations come from a counter published in the snapshot
(`next_slot_generation`) and a high-water mark in the running process that
also covers snapshots it built but failed to publish. Neither goes down:
disabling a group keeps the counter, and a restarted `galactic-cni` resumes
from the published value. A generation only an unpublished snapshot held was
never visible to a packet, so no pin can hold it. The counter is 32 bits and
skips 0; wrapping takes four billion slot assignments, far longer than any
pin lives.

### Turning it on and off

Follow [active-active-rollout.md](active-active-rollout.md). In short: install
the prerequisites, set `GALACTIC_CNI_EGRESS_MODE=hashed` and roll
`galactic-cni`. Within one sweep of starting, each node builds the groups and
moves every VRF route that pointed at a shard onto its class's group. The
move breaks sessions whose new shard differs from the one they were on,
roughly `(N-1)/N` of them, once.

To go back, set `GALACTIC_CNI_EGRESS_MODE=ordered` and roll `galactic-cni`
again, with `GALACTIC_CNI_EGRESS_SHARD_SIDS` still set on the init container.
Each node first marks its groups closing, so no CNI ADD writes a new route
naming one while they keep forwarding; then moves every route back to the
first reachable shard of the static list; and disables the groups only after
a sweep that read and rewrote every route without an error and found none
left. A sweep that fails leaves the groups forwarding and is retried. A CNI
ADD that read the groups open checks again after writing its routes and
rewrites them in ordered mode if the groups closed meanwhile.
`galactic_cni_egress_group_routes` reaching `0` on every node is the signal
that no route names a group any more. **Do not roll back to a release that
predates hashed mode until it does.** An older `usid_egress` reads a group
route as a redirect to a nonexistent interface and drops the traffic.

### Observability

| Metric                                                     | Meaning                                                                                                                              |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `galactic_cni_egress_mode{mode}`                           | 1 for the configured mode. Always present, so a node configured for hashed mode that never published a group still says so.          |
| `galactic_cni_egress_shard_watch_synced`                   | 1 once the `EgressShard` watch has listed the cluster.                                                                               |
| `galactic_cni_egress_group_routes{class}`                  | Routes naming each class's group after the last successful sweep. Must be 0 before rolling back to an older release.                 |
| `galactic_cni_egress_sweep_errors_total{stage}`            | Sweep failures: `apply`, `refresh`, `watch`, `close`, `disable`.                                                                     |
| `galactic_cni_egress_pool_members{class,state}`            | Each class's shards: `active`, `draining`, `unreachable`, and `ineligible` (cannot translate the class).                             |
| `galactic_cni_egress_pool_enabled{class}`                  | 1 while the class's group takes new routes; 0 while it is being retired.                                                             |
| `galactic_cni_egress_pool_min_active`                      | `GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE`.                                                                                               |
| `galactic_cni_egress_shard_packets_total{shard_sid,class}` | Tenant packets this node sent to each shard for each class, since the shard took its slot. `..._bytes_total` is the same in bytes.   |
| `galactic_cni_egress_shard_selections_total{result}`       | How each packet was placed: `maglev`, `pin_hit`, `pin_stale` (re-placed), or dropped as `group_empty`, `shard_dead`, `parse_failed`. |

A node that never published a group exports no `pool_*` series. That is not
a healthy empty pool: read it together with `galactic_cni_egress_mode` and
`galactic_cni_egress_shard_watch_synced`. `config/monitoring/` alerts on these
(`GalacticEgressPoolEmpty`, `GalacticEgressPoolBelowMinimum`,
`GalacticEgressClassUnserved`, `GalacticEgressShardGroupDropping`,
`GalacticEgressShardWatchNotSynced`, `GalacticEgressSweepFailing`,
`GalacticCNIMetricsDown`). That file is the tested source of the rules, not
where they run: on Datum's infra the rules are evaluated centrally from
infra's own copy, so they take effect only once infra installs them there.
To compare shards' load from their own side, compare `galactic_nat_sessions`
across the cluster's shard nodes.

## Session table

Every session is two rows in `nat_conn_table`, a 65536-entry LRU hash: a
forward row keyed by the tenant's tuple and a reverse row keyed by the peer's
tuple against the masquerade address and port. A session expires once it has
gone idle for its protocol's timeout, compile-time constants in `nat.c`:

| Session                          | Idle timeout | Basis                                                                 |
| -------------------------------- | ------------ | --------------------------------------------------------------------- |
| UDP                              | 2 min        | RFC 4787 REQ-5 floor (RFC 6146 `UDP_MIN`)                             |
| UDP to port 53                   | 30 s         | RFC 4787 REQ-5a; one query and answer, retried within a few seconds   |
| TCP, peer has answered           | 2 h 4 min    | RFC 5382 REQ-5 (RFC 6146 `TCP_EST`)                                   |
| TCP, unanswered or after FIN/RST | 4 min        | RFC 5382 REQ-5 (RFC 6146 `TCP_TRANS`)                                 |
| ICMP Echo                        | 60 s         | RFC 5508 REQ-2 (RFC 6146 `ICMP_TIMEOUT`)                              |

- **Refresh.** A translated packet in either direction refreshes the session.
  ICMP errors neither refresh it nor reach an expired one.
- **Expiry without a sweeper.** Nothing walks the table. A reply to an expired
  session drops as `no_return_conn`, the tenant's next packet claims a fresh
  port, and a port claim that collides with an expired session releases both
  its rows and takes the port. Expired rows hold table capacity until then,
  so `galactic_nat_conns` counts them and `galactic_nat_sessions` does not.
- **A full table is normal.** On any steadily used shard, expired rows fill
  `nat_conn_table` toward its capacity and stay there, because nothing
  removes them early. Only evicting a live session is harmful, and the LRU
  does that only once rows turn over faster than the longest timeout,
  2 h 4 min. `galactic_nat_conn_table_oldest_row_age_seconds` shows how
  fast rows turn over; see the alert under [Verifying](#verifying).
- **Split sessions.** The LRU evicts rows one at a time. A forward row whose
  reverse row is gone is replaced on its next packet; a reverse row whose
  forward row is gone keeps translating replies, and the flow's next packet
  adopts it.
- **Upgrade.** A restart reuses the pinned table and keeps every session. A
  release that changes the row layout recreates it instead, so that one
  restart drops every session on the shard.

## Verifying

```sh
kubectl get egressshard -n galactic-system -o wide
kubectl get bgpadvertisement -n galactic-system | grep nat66
```

Metrics, exposed on `GALACTIC_NAT_METRICS_PORT` (`9182` by default):

| Metric                                           | Type    | Labels                         | Meaning                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------ | ------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_nat_conns`                             | Gauge   | `family`                       | Rows in this shard's `nat_conn_table`, expired sessions included. A session holds two rows. Expect it near capacity on a busy shard; see [Session table](#session-table).                                                                                                                                                                                                              |
| `galactic_nat_sessions`                          | Gauge   | `family`, `proto`              | Live sessions, one per session within its idle timeout. `proto` is `tcp`, `udp` or `icmp`. Every series is reported, at zero when empty.                                                                                                                                                                                                                                               |
| `galactic_nat_conn_table_oldest_row_age_seconds` | Gauge   | —                              | Seconds since the least recently seen session in the table, expired ones included, last translated a packet. On a near-full table it approximates how long an idle session lasts before the LRU evicts it; on a table with room it only grows. Absent while the table holds no sessions.                                                                                               |
| `galactic_nat_conn_table_max_entries`            | Gauge   | —                              | Capacity of `nat_conn_table` in rows, read from the loaded map.                                                                                                                                                                                                                                                                                                                        |
| `galactic_nat_drops_total`                       | Counter | `reason`                       | Packets dropped by the `nat_ingress` program, by reason. Cumulative for the life of the *node*, not the process: the counters live in a map pinned under `natattach.PinDir`, which a restarting shard reuses as-is. Always read it as a delta — an absolute value includes every transient the node has ever seen, and zeroing it takes `bpftool map update` against the pin directly. |
| `galactic_nat_uplink_rx_queue_packets_total`     | Counter | `interface`, `driver`, `queue` | Packets one NIC receive queue of an uplink received, from the driver's `ethtool -S` statistics. Exported for `bnxt_en`, `ixgbe`, `ice`, `i40e` and `mlx5_core`; any other driver exports nothing.                                                                                                                                                                                      |
| `galactic_nat_uplink_rx_queue_discards_total`    | Counter | `interface`, `driver`, `queue` | Packets one NIC receive queue of an uplink discarded before the datapath saw them, so `galactic_nat_drops_total` never counts them. Only drivers that count discards per queue report it: `bnxt_en` today.                                                                                                                                                                             |

`config/monitoring/podmonitor-galactic-nat.yaml` scrapes every shard as
`job="galactic-nat"` with a `node` label.

A full table alone is not a problem. The table is evicting live sessions
when it is full and its oldest row is younger than the longest session
timeout, 7440 s: idle established TCP sessions are then evicted before they
expire. `GalacticNatSessionTableEvictingLive` in
`config/monitoring/prometheusrule.yaml` fires on this query after 15
minutes:

```promql
sum by (node) (galactic_nat_conns) / on (node) max by (node) (galactic_nat_conn_table_max_entries) > 0.9
  and on (node) max by (node) (galactic_nat_conn_table_oldest_row_age_seconds) < 7440
```

Drop reasons currently defined (`internal/plumbing/ebpf/natprog/dropreason.go`):

| Reason                                                                             | Meaning                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nat66_no_return_conn`, `nat64_no_return_conn`                                     | A TCP or UDP reply matched no live session.                                                                                                                                                                                                     |
| `nat66_malformed_return`, `nat64_malformed_return`                                 | A reply too short to parse, or not TCP or UDP.                                                                                                                                                                                                  |
| `nat66_malformed_forward`, `nat64_malformed_forward`                               | A tenant packet too short to parse, or of a protocol the family does not translate.                                                                                                                                                             |
| `nat66_pat_exhausted`, `nat64_pat_exhausted`                                       | Every port or Echo Identifier in the probe held by a live session. `GalacticNatPortExhausted` fires after 15 minutes of them.                                                                                                                   |
| `nat64_v4_fragment`, `nat64_v4_options`                                            | An IPv4 reply that was fragmented or carried options.                                                                                                                                                                                           |
| `nat64_shard_unavailable`                                                          | A NAT64 packet reached a shard with no IPv4 masquerade address.                                                                                                                                                                                 |
| `nat64_non_global_dest`                                                            | A tenant packet, Echo included, to a NAT64 address whose embedded IPv4 address is not globally reachable (RFC 6890 special-purpose, multicast or reserved).                                                                                     |
| `nat66_icmp_malformed`                                                             | An ICMPv6 message, or the packet an ICMPv6 error quotes, too short to parse.                                                                                                                                                                    |
| `nat66_icmp_no_conn`                                                               | An Echo Reply, or an ICMPv6 error, that matched no live session.                                                                                                                                                                                |
| `icmp_untranslatable`                                                              | A well-formed ICMP message the shard has no translation for: an ICMP type it does not handle, an ICMPv4 error RFC 7915 says to drop, a tenant sending anything but an Echo Request, or an error quoting a packet the shard could not have sent. |
| `icmp_unsolicited`                                                                 | An Echo Request addressed to a masquerade address itself, with the echo responder off.                                                                                                                                                          |
| `nat64_icmp_malformed`                                                             | An ICMPv4 message, or the packet an ICMPv4 error quotes, too short to parse; or a tenant's ICMPv6 bound for a NAT64 address that is.                                                                                                            |
| `nat64_icmp_no_conn`                                                               | An ICMPv4 Echo Reply, or an ICMPv4 error, that matched no live session.                                                                                                                                                                         |
| `icmp_rate_limited`                                                                | A reply the echo responder would have sent, refused by the per-CPU token bucket.                                                                                                                                                                |
| `fib_no_neigh`, `fib_unreachable`, `fib_frag_needed`, `fib_lookup_failed`          | The shard translated a packet and could not resolve where to send it.                                                                                                                                                                           |
| `adjust_head_failed`, `hop_limit_exceeded`, `no_egress_ifindex`, `redirect_failed` | The shard translated a packet and could not transmit it.                                                                                                                                                                                        |

A tenant can ping through NAT66: its Echo Request is translated like a UDP
datagram, the Echo Identifier masqueraded in the port's place, and the
ICMPv6 errors the internet sends back about its flows — Destination
Unreachable, Packet Too Big, Time Exceeded, Parameter Problem — reach it
rewritten to describe the packet it sent. A ping to a NAT64-synthesized
address works too: the shard translates ICMPv6 Echo to ICMPv4 Echo and back.
A reply that fits the internet path but not the fabric once the shard
re-encapsulates it — 40 bytes bigger over NAT66, 60 over NAT64 — is still
dropped and counted as `fib_frag_needed`, but its sender now hears why: the
shard sends it a Packet Too Big, or a Fragmentation Needed over NAT64, from
the masquerade address, carrying the fabric route's MTU less those bytes.
TCP rarely needs this, since the fabric's MSS clamp keeps its segments small
enough; UDP and ICMP do.

ICMPv4 errors about a tenant's NAT64 flows reach it as the ICMPv6 errors RFC
7915 section 4.2 maps them to, quoted packet translated too, from the
reporting router's address synthesized into the prefix the flow used — so
traceroute names each IPv4 hop, and a Fragmentation Needed arrives as a
Packet Too Big for 20 bytes more than the IPv4 MTU. The quote is carried
whole unless the ICMPv6 packet would exceed 1280 bytes or the message
carries RFC 4884 extensions; then it is cut to the first 8 bytes of the
quoted transport header, which is all the kernel matches an error on.

The `fib_*` reasons and the three after them all mean the same class of
thing: the shard translated a packet and then could not get rid of it.
Every leg of this datapath resolves its own next hop and transmits from
the driver, forward and return alike — see the constraint below — so the
kernel's output path is doing none of that work and none of its failures
are the kernel's to report.

```sh
kubectl exec -n galactic-system <galactic-nat-pod> -- \
  wget -qO- http://localhost:9182/metrics | grep galactic_nat_
```

Confirm the eBPF program is attached (in dispatch mode, in the dispatcher's
egress slot) and
translating. On the `EgressShard` object, `Ready` should read
`DatapathAttached` and `Programmed` should read `AddressesProgrammed`. `Ready` reading `UplinksMissing` names the uplinks
whose traffic the shard is not translating:

```sh
kubectl get egressshard <name> -n galactic-system -o jsonpath='{.status.conditions}'
```

## Known constraints

Verified against the current working tree as of this writing — worth
knowing before you rely on this component in production:

- **Ordered mode is active/standby.** With the default
  `GALACTIC_CNI_EGRESS_MODE=ordered`, every tenant VRF uses the first
  resolvable SID of `GALACTIC_CNI_EGRESS_SHARD_SIDS`, and every other shard
  stands by. `galactic-cni run` re-checks the choice every 30 seconds and
  moves a VRF to an earlier shard that becomes reachable, or off one that
  stops being reachable, which strands that VRF's sessions. Hashed mode
  ([above](#active-active-egress)) spreads tenants across every shard.
- **Hashed mode cannot balance one heavy tenant address** under the default
  `source` hash: all of its connections use one shard. A metro with a few
  large tenants and N shards balances unevenly. `flow` mode fixes that at
  the cost of a single public address per tenant address.
- **Session state is not shared between shards.** A session belongs to one
  shard and dies with it. In hashed mode a failure costs only that shard's
  sessions.
- **Hashed placement balances addresses, not bytes, and is per node.** A few
  heavy tenants make shard load uneven however many addresses each carries,
  and the same tenant address on two compute nodes can land on two shards,
  since the hash includes each node's own VRF table ID.
- **A busy tenant can keep a draining shard busy indefinitely.** Its pin is
  refreshed by every packet, so it never moves while it keeps sending. Pins
  are bounded (65536 per compute node) and local to that node.
- **Fragments are not translated end to end.** The shard drops fragmented
  IPv4 replies (`nat64_v4_fragment`), and hashed mode's fragment handling only
  keeps a datagram's fragments on one shard; it adds no translation support.
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
- **A shard node's netfilter rules never see tenant egress.** Both
  directions are claimed in XDP and leave from the driver, so nothing a
  shard translates traverses `PREROUTING`, `FORWARD`, or connection
  tracking. That is deliberate and not adjustable: the return leg is
  re-encapsulated before netfilter runs and cannot be made visible without
  giving up the SRv6 encapsulation it exists to perform, and a forward leg
  visible on its own left conntrack holding every TCP flow in `SYN_SENT`
  and the node dropping the tenant's own ACK as `INVALID`
  ([#565](https://github.com/datum-cloud/galactic/issues/565)). The costs
  are real: no host firewall or accounting applies to this traffic, the
  routing is a `bpf_fib_lookup` against the main table rather than the
  kernel's full output path — so `ip rule` policy routing is not consulted
  — and the only ICMP error generated on the shard's behalf is the one the
  datapath builds itself, for a reply too big for the fabric (see below).
  Each of the rest surfaces as a named drop counter instead; a tenant
  packet whose hop limit expires at the shard, for one, is dropped as
  `hop_limit_exceeded` with no Time Exceeded, so traceroute shows the
  shard's hop as `*`.
- **ICMP sessions share the session table with TCP and UDP.** Echo
  sessions take rows from the same 65536-entry LRU `nat_conn_table`, so a
  burst of tenant pings to many destinations can evict live TCP and UDP
  sessions. Eviction looks like `nat66_no_return_conn` or
  `nat64_no_return_conn` rising in step with ICMP traffic rather than with
  any routing change — check
  `galactic_nat_conn_table_oldest_row_age_seconds` against the 7440 s TCP
  timeout when that happens. The table is shared deliberately, not by
  omission; the datapath's `nat_conn_table` comment gives the reasoning.
- **The ICMP rate limit is per CPU, not per shard or per peer.** Every
  reply the echo responder sends, and every Packet Too Big or Fragmentation
  Needed the shard sends a sender, comes out of a token bucket of 1000
  messages a second with a burst of 100, one bucket per CPU, compile-time
  constants in `nat.c`. The limit for a whole shard is that rate times the
  number of CPUs receiving traffic, so it grows with the uplinks' RSS
  queue count rather than being one number. One peer that drains a CPU's
  bucket also suppresses replies to every other peer hashed to that CPU
  until it refills. `icmp_rate_limited` counts each refusal; a per-peer or
  global limiter is the follow-up if that counter shows either problem.
- **A shard's identity is entirely operator-chosen.** Nothing in this repo
  allocates `spec.shardSID` or the masquerade addresses. A SID colliding
  with a `BGPRouter`'s Block and Node-ID is refused (see the "Node-ID
  collision hazard" callout above), but a collision with any other uSID
  identity, one no `BGPRouter` carries, is not detected.
- **One NIC receive queue on a `bnxt_en` uplink can stall.** The queue
  drops a steady share of its packets while the CPU sits idle, and every
  flow hashed to it fails on each retry: tenant egress times out per flow,
  and a BGP session on that queue expires its hold timer
  ([#673](https://github.com/datum-cloud/galactic/issues/673)). It has only
  been seen on `bnxt_en` uplinks with this datapath attached, never on
  `ixgbe` or on fabric links, which carry no XDP program. The trigger is not
  known. The NIC drops the packets before the datapath runs, so
  `galactic_nat_drops_total` stays flat; the signal is one queue standing out
  in `galactic_nat_uplink_rx_queue_discards_total`, and
  `GalacticNatUplinkRxQueueStalled` (`config/monitoring/`) alerts on it.
  `galactic_nat_uplink_queue_driver_stat_total` shows the ring's other
  counters, transmit among them, and `galactic_nat_uplink_info` its driver,
  firmware and kernel versions, the data needed to find the cause. To
  clear it, confirm the uplink's bond partner is up and carrying traffic, then
  bounce the affected member (`ip link set <member> down; ip link set
  <member> up`). The bond partner carries traffic meanwhile, and the queue's
  discards stop at once. Nothing bounces it automatically.
- **The dispatcher outlives the shard.** In dispatch mode the root stays on
  the uplinks after the shard is removed, passing every packet once the
  slot's lease lapses. `hack/xdp-dispatch-release.sh` detaches it.
- **In ordered mode the CNI's shard list is a second copy of every shard
  SID.** `GALACTIC_CNI_EGRESS_SHARD_SIDS` is set by hand and is not derived
  from `EgressShard` status, so the two can disagree. Hashed mode reads the
  `EgressShard`s instead, and uses the list only to move VRFs back when
  switching to ordered mode.

## See also

- [docs/nat/getting-started.md](getting-started.md) — a hands-on
  walkthrough for standing this up from nothing.
- [docs/node-labels.md](../node-labels.md) — the node-labeling strategy
  shared across every Galactic component.
- [docs/router/configuration.md](../router/configuration.md) — the
  `GALACTIC_ROUTER_*` environment variables a NAT66 shard node's
  co-located `galactic-router` process also needs.
- [docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) —
  the edge XDP programs that share the dispatcher with the shard.
- [docs/cni/configuration.md](../cni/configuration.md) — the full
  `galactic-cni` conflist/runtime configuration surface
  `GALACTIC_CNI_EGRESS_SHARD_SIDS` is one part of.
