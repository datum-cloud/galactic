# Egress translation configuration

`galactic-nat` provides sharded stateful NAT66 and NAT64. Use [deployment](deployment.md) for installation and verification, [active/active egress](active-active.md) for hashed shard selection, and [the rollout checklist](active-active-rollout.md) for qualification and rollback.

## `galactic-nat` configuration (`internal/config/nat.go`)

`galactic-nat` supports configuration via environment variables, CLI
flags, or a combination of both (CLI flags take precedence), with the
`GALACTIC_NAT` env prefix — the same three-tier precedence pattern
`galactic-router` and `galactic-gateway` use (see
[docs/router/configuration.md](../router/configuration.md)).

Logging takes `--log-level` (`LOG_LEVEL`), without the `GALACTIC_NAT` prefix and the standard `--zap-*` flags; see [Logging](../observability/logging.md).

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
[below](#egressshard-crd-galacticdatumapiscomv1alpha1)). The process attaches
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
interface. As with the gateway, the program is attached in the host's XDP
mode, generic on a host with a `bnxt_en` NIC and native elsewhere (see
[XDP attach mode](../operations/xdp-attach-mode.md)). In native mode every resolved
interface is checked for native XDP support before any is touched. In either
mode the slaves are attached one at a time, each waited back into its LACP
aggregate before the next, so a NIC whose driver drops carrier to attach an
XDP program bounces one
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
  resolved uplink in the host's XDP mode, as described above. The attachment
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
  native XDP in native mode, or attaching would take a bond down, is reported
  missing and
  retried on the next link or route change. The first attach to each bond
  member, and the wait for it to rejoin its bond, run under a node-wide lock,
  so two datapaths sharing the dispatcher never bounce two members of one bond
  at once.

  The dispatcher attaches in the host's XDP mode. A pinned link left in the
  other mode, such as a native link on a host that now selects generic mode,
  counts as uncovered until it is migrated, one bond member at a time under
  the same lock, keeping every slot, lease and role.

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

| Capability  | Why                                                                                                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `NET_ADMIN` | netlink XDP attach                                                                                                                                                                   |
| `BPF`       | eBPF program/map creation                                                                                                                                                            |
| `PERFMON`   | the verifier only allows pointer+scalar arithmetic on packet data (the SNAT/un-SNAT and NAT64 header rewrites) when the loading process is `perfmon_capable()`, even running as root |

It also needs a real bpffs already mounted at `/sys/fs/bpf` on the host
(`type: Directory`, not `DirectoryOrCreate` — a missing mount must fail
loudly, not silently pin maps to a plain directory). Every map is pinned
under `/sys/fs/bpf/galactic-nat`. In dispatch mode it also pins the node's
XDP dispatcher under `/sys/fs/bpf/galactic-xdp`, which the same `/sys/fs/bpf`
mount covers.

## `EgressShard` CRD (`galactic.datumapis.com/v1alpha1`)

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
apiVersion: galactic.datumapis.com/v1alpha1
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

<a id="active-active-egress"></a>
<a id="activeactive-egress"></a>

## Active/active egress

Shard selection, class isolation, pinning, draining and publication are described in [active/active egress](active-active.md).

<a id="prerequisites"></a>

See [Prerequisites](active-active.md#prerequisites).

<a id="how-a-shard-is-chosen"></a>

See [How a shard is chosen](active-active.md#how-a-shard-is-chosen).

<a id="draining-and-removing-a-shard"></a>

See [Draining and removing a shard](active-active.md#draining-and-removing-a-shard).

<a id="when-nothing-is-reachable"></a>

See [When nothing is reachable](active-active.md#when-nothing-is-reachable).

<a id="how-the-groups-are-published"></a>

See [How the groups are published](active-active.md#how-the-groups-are-published).

<a id="changing-the-nat64-prefix-list"></a>

See [Changing the NAT64 prefix list](active-active.md#changing-the-nat64-prefix-list).

<a id="turning-it-on-and-off"></a>

See [Turning it on and off](active-active.md#turning-it-on-and-off).

<a id="observability"></a>

See [Observability](active-active.md#observability).


<a id="placement"></a>
<a id="verifying"></a>

See [deployment and verification](deployment.md).
