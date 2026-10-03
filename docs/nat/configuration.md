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

`galactic-nat` runs on every `galactic.datumapis.com/node: edge` node, one
DaemonSet per cluster, alongside `galactic-gateway` (see
[docs/node-labels.md](../node-labels.md)). A shard there is one hop from the
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

| Option            | Environment Variable             | CLI Flag                  | Default       | Required |
| ----------------- | -------------------------------- | ------------------------- | ------------- | -------- |
| Node name         | `GALACTIC_NAT_NODE_NAME`         | `--node-name`             | —             | Yes      |
| Uplink interfaces | `GALACTIC_NAT_UPLINK_INTERFACES` | `--nat-uplink-interfaces` | auto-detected | No       |
| XDP attach mode   | `GALACTIC_NAT_XDP_ATTACH`        | `--nat-xdp-attach`        | `direct`      | No       |
| Echo responder    | `GALACTIC_NAT_ECHO_RESPONDER`    | `--nat-echo-responder`    | `false`       | No       |
| Metrics port      | `GALACTIC_NAT_METRICS_PORT`      | `--metrics-port`          | `9182`        | No       |
| gRPC health port  | `GALACTIC_NAT_GRPC_HEALTH_PORT`  | `--grpc-health-port`      | `5182`        | No       |

`config/galactic-nat/base/daemonset.yaml` sets `GALACTIC_NAT_XDP_ATTACH=chain`,
since every edge node runs `galactic-gateway`; the binary's own default is
`direct`.

That is the whole process configuration. The shard's identity — its SID,
masquerade addresses and NAT64 prefix — is not process configuration: it
comes from the spec of the `EgressShard` targeting this node (see
[below](#egressshard-crd-networkdatumapiscomv1alpha1)). The process attaches
its datapath at startup with no identity and programs one on reconcile, so a
node without an `EgressShard` runs attached but claims no packet rather than
crash-looping.

`9182`/`5182` are chosen to avoid every other `hostNetwork: true` galactic
process already running on an edge node (`fabric-router`'s `179`,
`galactic-router`'s `9179`/`5179`, `galactic-cni`'s `9180`/`5180`,
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

In chain mode nothing is attached, so the uplinks are used for the
forwarding sysctls and to check coverage: an uplink that carries no XDP
program is reported missing the same way, since traffic the gateway never
hooks is traffic the chained shard never sees.

**`--nat-xdp-attach` / `GALACTIC_NAT_XDP_ATTACH`**
How the datapath reaches its uplinks' XDP hook: `direct` or `chain`. Any
other value fails validation at startup.

- **`direct`** (the binary's default) attaches `nat_ingress` to every
  resolved uplink in native driver mode, as described above. Use it on a
  node with no `galactic-gateway`.
- **`chain`** attaches nothing. An interface takes one native XDP program,
  and on an edge node `galactic-gateway` already holds that hook on the
  interfaces the shard needs (a direct attach there fails outright). The
  gateway pins a one-slot program array, `xdp_chain`, at
  `/sys/fs/bpf/galactic-edge/xdp_chain`, and both of its programs
  (`edge_lb`, `edge_return`) tail-call into it with every packet they do not
  claim — non-IPv6 frames included, so NAT64 replies reach the shard. The
  shard installs `nat_ingress` in that slot (`natattach.AttachChain`). The
  two datapaths claim disjoint traffic — a VIP destination or source for the
  gateway, a shard SID or masquerade address for the shard — so the order
  they run in changes no verdict.

  At startup the shard waits for the map, retrying every 2s while it does
  not exist (the startup probe bounds the wait), and reports healthy once its
  program is in the slot. Any other install failure is fatal: the kernel
  refuses a program whose type, JIT state, frags support or expected attach
  type differ from the array owner's, with a bare `EINVAL`. After that it
  re-checks the slot every 10s and re-installs its program if the slot no
  longer holds it — a gateway restart normally reuses its pinned map, but one
  that had to recreate the map empties the slot. The slot keeps the program
  alive across a `galactic-nat` restart, and the next process replaces it in
  place, so a shard restart leaves no gap in translation.

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
under `/sys/fs/bpf/galactic-nat`. In chain mode it also opens the gateway's
`/sys/fs/bpf/galactic-edge/xdp_chain`, which the same `/sys/fs/bpf` mount
covers.

## `EgressShard` CRD (`network.datumapis.com/v1alpha1`)

One object per shard node, in the `galactic-system` namespace. The spec
assigns the shard's identity; the `galactic-nat` process on the target node
programs its datapath from it and reports what it is actually programmed
with in status.

| Field                     | Required | Type     | Description                                                                                            |
| ------------------------- | -------- | -------- | ------------------------------------------------------------------------------------------------------ |
| `spec.targetRef.name`     | Yes      | `string` | Kubernetes node name this shard's `galactic-nat` process runs on.                                      |
| `spec.shardSID`           | No       | `string` | This shard's SRv6 uSID. Write-once.                                                                    |
| `spec.shardAddressIPv6`   | No       | `string` | IPv6 masquerade source. Setting it enables NAT66. Write-once.                                          |
| `spec.shardAddressIPv4`   | No       | `string` | IPv4 masquerade source. Setting it, with `nat64Prefix`, enables NAT64. Write-once.                     |
| `spec.nat64Prefix`        | No       | `string` | The fabric-wide `/96` this shard translates to IPv4. Set together with `shardAddressIPv4`. Write-once. |
| `status.shardSID`         | —        | `string` | The SID the datapath is programmed with.                                                               |
| `status.shardAddressIPv6` | —        | `string` | The IPv6 masquerade source the datapath is programmed with. Empty means no NAT66.                      |
| `status.shardAddressIPv4` | —        | `string` | The IPv4 masquerade source the datapath is programmed with. Empty means no NAT64.                      |
| `status.nat64Prefix`      | —        | `string` | The `/96` the datapath is programmed to translate.                                                     |
| `status.conditions`       | —        | —        | `Ready` (datapath on every uplink) and `Programmed` (datapath translating with the spec's identity).   |

Every identity field is optional and write-once. A shard can exist before
its identity is assigned, and gains it later with a spec update; once
assigned, a value cannot change or be cleared, because the datapath claims
return traffic by exact match on it and a change strands every established
flow. A shard holding the wrong identity is deleted and recreated instead.

The datapath needs a SID and at least one family before it translates
anything:

| `Programmed` reason   | Meaning                                                                                                          |
| --------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `AddressesProgrammed` | The datapath translates with the identity the spec assigns.                                                      |
| `AddressUnassigned`   | The spec assigns no SID, or no masquerade address for either family. The datapath is cleared and claims nothing. |
| `ProgrammingFailed`   | The datapath rejected the identity, for example a NAT64 prefix that is not a `/96`. The message says why.        |
| `ShardConflict`       | More than one `EgressShard` targets this node. None is programmed until only one does.                           |

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
> `shardSID` — it does **not** check that the Node-ID is actually reserved
> for the shard. Reusing the physical node's own real `BGPRouter.Spec.NodeID`
> here means the shard's XDP program hijacks that node's own ordinary
> tenant ingress traffic before `usid_ingress` ever gets to it. Reserve a
> distinct Node-ID on the shard's locator for this purpose alone — see
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
sending its egress out through another site's edge. Example (containerlab
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

## Verifying

```sh
kubectl get egressshard -n galactic-system -o wide
kubectl get bgpadvertisement -n galactic-system | grep nat66
```

Metrics, exposed on `GALACTIC_NAT_METRICS_PORT` (`9182` by default):

| Metric                     | Type    | Labels   | Meaning                                                                                                                                                                                                                                                                             |
| -------------------------- | ------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `galactic_nat_conns`       | Gauge   | —        | Current row count in this shard's `nat_conn_table` — a point-in-time snapshot of an LRU, so it can fluctuate independently of actual live traffic under memory pressure.                                                                                                          |
| `galactic_nat_drops_total` | Counter | `reason` | Packets dropped by the `nat_ingress` program, by reason. Cumulative for the life of the *node*, not the process: the counters live in a map pinned under `natattach.PinDir`, which a restarting shard reuses as-is. Always read it as a delta — an absolute value includes every transient the node has ever seen, and zeroing it takes `bpftool map update` against the pin directly. |

Drop reasons currently defined (`internal/plumbing/ebpf/natprog/dropreason.go`):

| Reason                                                                             | Meaning                                                                                                                                                                                                                                         |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nat66_no_return_conn`, `nat64_no_return_conn`                                     | A TCP or UDP reply matched no session.                                                                                                                                                                                                          |
| `nat66_malformed_return`, `nat64_malformed_return`                                 | A reply too short to parse, or not TCP or UDP.                                                                                                                                                                                                  |
| `nat66_malformed_forward`, `nat64_malformed_forward`                               | A tenant packet too short to parse, or of a protocol the family does not translate.                                                                                                                                                             |
| `nat66_pat_exhausted`, `nat64_pat_exhausted`                                       | No free masquerade port or Echo Identifier within the probe limit.                                                                                                                                                                              |
| `nat64_v4_fragment`, `nat64_v4_options`                                            | An IPv4 reply that was fragmented or carried options.                                                                                                                                                                                           |
| `nat64_shard_unavailable`                                                          | A NAT64 packet reached a shard with no IPv4 masquerade address.                                                                                                                                                                                 |
| `nat66_icmp_malformed`                                                             | An ICMPv6 message, or the packet an ICMPv6 error quotes, too short to parse.                                                                                                                                                                    |
| `nat66_icmp_no_conn`                                                               | An Echo Reply, or an ICMPv6 error, that matched no session.                                                                                                                                                                                     |
| `icmp_untranslatable`                                                              | A well-formed ICMP message the shard has no translation for: an ICMP type it does not handle, an ICMPv4 error RFC 7915 says to drop, a tenant sending anything but an Echo Request, or an error quoting a packet the shard could not have sent. |
| `icmp_unsolicited`                                                                 | An Echo Request addressed to a masquerade address itself, with the echo responder off.                                                                                                                                                          |
| `nat64_icmp_malformed`                                                             | An ICMPv4 message, or the packet an ICMPv4 error quotes, too short to parse; or a tenant's ICMPv6 bound for a NAT64 address that is.                                                                                                            |
| `nat64_icmp_no_conn`                                                               | An ICMPv4 Echo Reply, or an ICMPv4 error, that matched no session.                                                                                                                                                                              |
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
reporting router's address synthesized into the NAT64 prefix — so
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

Confirm the eBPF program is attached (in chain mode, installed in the
gateway's `xdp_chain` slot) and translating — on the `EgressShard` object,
`Ready` should read `DatapathAttached` and `Programmed` should read
`AddressesProgrammed`. `Ready` reading `UplinksMissing` names the uplinks
whose traffic the shard is not translating:

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
  standby, not sharing load. Selection happens only at CNI ADD: a shard
  that becomes unreachable later is not replaced on attachments already
  made. An earlier version of this mechanism did
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
  any routing change — check `galactic_nat_conns` against the table's
  capacity when that happens. No row carries a timer, so RFC 6146's shorter
  ICMP query timeout has no counterpart here: LRU eviction is the only expiry
  a session gets. The table is shared deliberately, not by omission; the
  datapath's `nat_conn_table` comment gives the reasoning.
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
  allocates `spec.shardSID` or the masquerade addresses, and nothing checks
  that a chosen SID's Node-ID doesn't collide with a real node's own — see
  the "Node-ID collision hazard" callout above.
- **A chained shard depends on the gateway on its node.** In chain mode
  the shard sees only what `galactic-gateway`'s programs see, on exactly the
  interfaces the gateway attaches to, and waits at startup for a map only
  the gateway creates. With the gateway gone, the slot keeps the shard's
  program alive but nothing calls it.
- **The CNI's shard list is a second copy of every shard SID.**
  `GALACTIC_CNI_EGRESS_SHARD_SIDS` is set by hand and is not derived from
  `EgressShard` status, so the two can disagree.

## See also

- [docs/nat/getting-started.md](getting-started.md) — a hands-on
  walkthrough for standing this up from nothing.
- [docs/node-labels.md](../node-labels.md) — the node-labeling strategy
  shared across every Galactic component.
- [docs/router/configuration.md](../router/configuration.md) — the
  `GALACTIC_ROUTER_*` environment variables a NAT66 shard node's
  co-located `galactic-router` process also needs.
- [docs/agents/ARCHITECTURE-GATEWAY.md](../agents/ARCHITECTURE-GATEWAY.md) —
  the edge XDP programs the shard is chained behind.
- [docs/cni/configuration.md](../cni/configuration.md) — the full
  `galactic-cni` conflist/runtime configuration surface
  `GALACTIC_CNI_EGRESS_SHARD_SIDS` is one part of.
