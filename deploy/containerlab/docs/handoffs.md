# Local kernel handoffs

This page describes the scripted proof of the three Local handoffs the Worker
[qualification plan](../../../docs/worker/qualification.md#handoffs) lists
([#1444](https://github.com/datum-cloud/galactic/issues/1444)):

| Handoff                                                                                                         | Capability                          |
| --------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Public receive `XDP_PASS` into the tenant-side tc program, delivered to a tenant TAP                            | `local.tap`                         |
| tc on one end of the NAT internal veth pair, XDP on its peer, and the reverse tc receive                        | `local.veth_pair`                   |
| A VRF-bound (`SO_BINDTODEVICE`) socket in an Envoy pod reaching tenant guests through a pod-to-host routed link | `local.routed_link`, `local.socket` |

The checks run on `dfw-worker`, the compute node of the
[dedicated-placement baseline](baseline.md), against both of `ns80`'s VPCs.
Their results and what they changed in the Worker contract are in
[contract amendments](../../../docs/worker/contract.md#local-handoffs).

## Running

```bash
cd deploy/containerlab
task deploy:ns80        # if ns80 is not deployed
task handoff:twice      # fixture up, observe twice, measure, fixture down
task verify:ns80        # the baseline fixture is unchanged
```

`task handoff:twice` builds `bin/handoff-probe` from this checkout, deploys the
`ns80-tap` fixture, runs `scripts/handoff-observe.sh` twice and
`scripts/handoff-measure.sh` once, and removes the fixture. It fails unless both
observation runs pass, agree, and match
[`handoffs/expected-results.json`](../handoffs/expected-results.json). Output
lands in `bin/handoffs/<UTC timestamp>/` at the repository root, or in the
directory given after `--`.

Before it changes anything, each script checks that the lab runs, that `ns80`
is ready, that no earlier run left a rig, fixture or probe state behind, and
that the probe's programs load against the running datapath. When a check
fails, the script writes the reason to `precondition`, changes nothing and
exits 0. After the run it removes the rig, the probe and everything the probe
placed, and fails if `handoff-probe leftovers` finds any of it.

`task handoff:observe -- DIR` and `task handoff:measure -- DIR` run one script
against a fixture deployed with `task deploy:ns80-tap`, and
`HANDOFF_CELLS=plain-native,...` limits observation to some cells. Remove the
fixture afterwards with `task delete:ns80-tap`.

## Fixture

`ns80-tap` (`resources/tenants/ns80-tap/`) runs on `dfw-worker` only. Its pods
select `node=compute`, and the lab-only taint on `dfw-worker4`, dfw's second
compute node, keeps them off it:

| Pod             | Network                                                                             | Role                                                       |
| --------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `tap-guest-a`   | The cluster's primary network, plus `vpc-a-tap` (VPC 80) as a secondary attachment  | TAP guest `fd20:80:ff03::1:0:0`, VIP `2001:db8:4144:a::80` |
| `tap-guest-b`   | The cluster's primary network, plus `vpc-b-tap` (VPC 81) as a secondary attachment  | TAP guest `fd20:80:ff03::1:0:0`, VIP `2001:db8:4144:a::81` |
| `envoy-standin` | The cluster's primary network; the run adds a VRF per VPC and a routed link to each | Envoy's sockets                                            |

Both TAP guests use the same address, as `ns80`'s veth guests do. Their
attachments are bound to the `handoff` policy set
(`resources/tenants/policies/README.md`).

### The tenant TAP

`galactic-tap` creates the host TAP (`G000000080082H`, `G000000081082H`) in the
VPC's VRF and configures nothing inside the pod: a TAP's reader is a hypervisor,
not the pod's network namespace. Its CNI result names only that host TAP. In
[#1432](https://github.com/datum-cloud/galactic/issues/1432) the TAP guest used
`galactic-tap` as its default network, and the runtime, which needs a pod
interface from the default network, failed every sandbox with "failed to find
network info for sandbox".

Here the TAP is a secondary attachment
(`k8s.v1.cni.cncf.io/networks: vpc-a-tap`), so the sandbox starts on the
cluster's network and multus runs `galactic-tap` after it. The pod's `vmm`
container stands in for the hypervisor. With `hostPID`, it names the node's
network namespace (`ip netns attach host 1`), opens the host TAP through socat's
`netns=` option, and bridges it to `tap0` inside the pod, the guest's interface.
It configures `tap0` only after the bridge holds it; an address or route added
before is lost with the interface. The pod is ready once `tap0` has carrier,
which it has only while the bridge reads the host TAP.

`publish-attachments.sh` publishes an attachment named in a pod's
`k8s.v1.cni.cncf.io/networks` list as it does a default network, so the TAP
attachments get their `hostInterface` and their policy bindings.

The TAP capture points are the host TAP on the node and `tap0` in the pod.

### Cilium and the TAPs

The lab runs Cilium with kube-proxy replacement. `deploy-cni.sh` pins its
devices to `eth0` and the bonds, as deployed nodes pin them to their uplinks.
Before that pin Cilium auto-detected its devices and adopted each host TAP,
because the TAP carries a global address (the guest's gateway). Its tcx attach
deleted every legacy tc filter on the TAP, including galactic-cni's egress
chain and `tp_deliver`. Each run keeps the evidence that this does not happen
any more: `logs/tc-monitor.txt` (every tc change on the node),
`logs/cilium-status.txt` (Cilium's devices) and `logs/cilium-taps.log`. The
[contract](../../../docs/worker/contract.md#local-handoffs) states the rule.

## Rig

The checks never touch the node's shared hooks: the dispatcher, gateway and NAT
on the edge nodes, and the compute node's uplinks. They build a rig on
`dfw-worker` instead. A rig container (`handoff-rig`) runs the debug image in
the node's network and PID namespaces; it creates every interface, runs every
listener and capture, and takes them all with it when it is removed.
`handoff-probe` runs in the node itself, next to `galactic-cni`, whose pinned
maps it reads.

| Part                | Interfaces                                                                                                                                                       |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Receiving device    | `hp-dut0`, a veth; or `hp-bond` (802.3ad, `mkbond.sh`'s parameters) over `hp-dut0` and `hp-dut1`; or `hp-dut0.120`, a VLAN on `hp-dut0`. `2001:db8:4144:1::1/64` |
| Client              | The other ends, in the rig's `hp-client` namespace. `2001:db8:4144:1::2/64`                                                                                      |
| Internal veth pairs | `hpn80t` in VPC 80's VRF and `hpn80n` in the node's namespace; `hpn81t` and `hpn81n` for VPC 81                                                                  |
| Routed links        | `hpr80h` in VPC 80's VRF to `hpr80p` in the Envoy pod's `vrf80`; `hpr81h`, `hpr81p` and `vrf81` for VPC 81. Both use `fd20:80:ff04::/127`                        |

The client's ends stand in for the far side of a physical link, which delivers
complete checksums. They send with checksum offload off; see
[checksums](#checksum-offload) for what changes when it is on.

The addresses are documentation addresses under `2001:db8:4144::/48`, which no
other part of the lab uses and the node's FRR does not announce.

## Prototype programs

`tests/handoffs/probe/handoff.c` holds the prototypes. It includes the uSID
datapath source, so its policy decisions run the product's `tp_capture` and
`tp_decide` against the maps `galactic-cni` pinned. `handoff-probe` loads it with
every uSID map replaced by that pin, and refuses to load if a map it needs is
not pinned or does not match, so a run never creates or alters a product pin.
It places the programs with the product loaders:

| Program            | Hook                                                | Loader                                                         | Role                                                                                                                                                             |
| ------------------ | --------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hp_xdp_public`    | XDP of the receiving device                         | `xdpdispatch` slot `SlotGatewayLB`, on a private pin directory | A VIP packet gets metadata naming its TAP and `XDP_PASS`. A shard packet is translated back and redirected into the pair's NAT end.                              |
| `hp_tc_tenant_rx`  | tc ingress of the receiving device                  | `attach.Attach`                                                | Decides the TAP's ingress policy on the PublicService path, marks the packet decided, and delivers to the TAP with `bpf_redirect_neigh`.                         |
| `hp_tc_tap_rx`     | tc ingress of the TAP, after galactic-cni's filters | netlink, one priority after the last galactic-cni filter       | The VIP's reply leaves through the receiving device; any other flow to the client enters the pair. Each decides the TAP's egress policy.                         |
| `hp_xdp_pair_peer` | XDP of the pair's NAT end                           | `natattach.Attach`                                             | Stands in for the NAT shard: translates the guest's source to the shard address and forwards; toward a VLAN it pushes the tag and redirects to the lower device. |
| `hp_tc_pair_rx`    | tc ingress of the pair's tenant end                 | `attach.Attach`                                                | Decides the TAP's ingress policy on the PublicNAT path, marks it, and delivers to the TAP.                                                                       |
| `hp_tc_link_guard` | tc ingress of a routed link's host end              | `attach.Attach`                                                | Drops any source outside the link's `/127`.                                                                                                                      |

The probe also writes Local pass-through entries (`egressroutemap`, under its
own owner) for the client's prefix and the routed link in both VRFs, which is
what Worker programs for a Local destination; see
[contract amendments](../../../docs/worker/contract.md#local-handoffs).

## Cells

Each cell builds one receiving device, places the prototypes in one mode, and
runs the `local.tap` window (`h1/<cell>`) and the `local.veth_pair` window
(`h2/<cell>`). `local.routed_link` and `local.socket` use no XDP hook and run
once (`h3`).

| Cell                        | Receiving device | Dispatcher XDP    | Peer XDP | Peer forwards with                             | `local.tap` | `local.veth_pair`                       |
| --------------------------- | ---------------- | ----------------- | -------- | ---------------------------------------------- | ----------- | --------------------------------------- |
| `plain-native`              | veth             | native            | native   | `XDP_REDIRECT`                                 | delivers    | delivers                                |
| `plain-generic`             | veth             | generic           | generic  | `XDP_REDIRECT`                                 | delivers    | fails: the peer's XDP never runs        |
| `plain-generic-native-peer` | veth             | generic           | native   | `XDP_REDIRECT`                                 | delivers    | delivers                                |
| `bond-native`               | bond members     | native            | native   | `XDP_REDIRECT`                                 | delivers    | delivers                                |
| `bond-generic-native-peer`  | bond members     | generic           | native   | `XDP_REDIRECT`                                 | delivers    | delivers                                |
| `vlan-native`               | VLAN device      | native: no attach |          |                                                | unsupported | unsupported                             |
| `vlan-lower-native`         | VLAN's lower     | native            | native   | tag pushed, `XDP_REDIRECT` to the lower device | delivers    | delivers                                |
| `vlan-generic-native-peer`  | VLAN device      | generic           | native   | tag pushed, `XDP_REDIRECT` to the lower device | delivers    | delivers                                |
| `vlan-generic-redirect`     | VLAN device      | generic           | native   | `XDP_REDIRECT` to the VLAN device              | delivers    | fails: no XDP transmit on a VLAN device |

The two failing cells and `vlan-native` record the specified mechanism not
delivering; the cells after each are the alternatives the contract adopts.

## Checks

Each `local.tap` window sends 5 UDP requests to each VIP and one TCP request,
and checks:

- each VPC's TAP guest receives its own VIP's requests and none of the other's,
  and the client gets every answer, from the VIP, with no encapsulation;
- TCP to port 9 of a VIP reaches the receiving device and no guest, and a reply
  to the client's UDP port 9 leaves the guest and never reaches the client
  (the `handoff` set denies both on the PublicService path);
- a third VIP, whose tc program leaves the decision to `tp_deliver`, reaches no
  guest: `tp_deliver` decides on the Private path, which the `handoff` set
  grants only to the VPC's own addresses;
- the XDP metadata reached tc.

Each `local.veth_pair` window sends 5 UDP flows and one TCP flow from each TAP
guest to the client, and checks that the client sees each from its VPC's shard
address, never the guest's, that each guest gets only its own answers, and that
UDP port 9 out and TCP port 9 back are denied on the PublicNAT path.

The `h3` window checks that a socket bound to `vrf80` reads VPC 80's veth guest
and one bound to `vrf81` reads VPC 81's, at the same address; that each VPC's
guest reaches the socket listening in its own VRF; that port 9 is denied by the
guest's ingress policy; that an unbound socket reaches no guest; and that a
spoofed source crosses the link and is dropped by the guard.

Every window also captures the node's four physical bond members, which must
carry nothing of the probes, plain or encapsulated in SRv6 or IPv6-in-IPv6.

| Capture point                         | Interfaces                                 |
| ------------------------------------- | ------------------------------------------ |
| `client`                              | The client's ends of the receiving device  |
| `dut`                                 | The receiving device's members on the node |
| `tap80-host`, `tap81-host`            | The host TAPs                              |
| `tap80-guest`, `tap81-guest`          | `tap0` in each TAP guest                   |
| `pair80`, `pair81`                    | Both ends of each internal veth pair       |
| `veth80-guest`, `veth81-guest`        | `eth0` of `ns80`'s guests                  |
| `link80-host`, `link81-host`, `envoy` | Both ends of the routed links              |
| `physical`                            | `eth1` to `eth4` on `dfw-worker`           |

`scripts/handoff-pcap.py` counts the packets carrying each check's nonce.
`results.json` holds stable values only; the nonce and versions go to
`volatile.tsv`.

## Measurements

`scripts/handoff-measure.sh` records, for native XDP and for generic XDP with
a native peer:

- `mtu`: UDP to a VIP at 1200 and 1451 bytes at MTU 1500 (each line also
  carries a newline), at 1452 and 4000 bytes, which the client fragments, and
  the receiving device at MTU 9000 against a TAP at 1500;
- `bulk`: 1 MiB each way, through `local.tap` and `local.veth_pair`, with the
  client's checksum offload, and so TSO, off and on, with the largest frame XDP
  saw;
- `pod-veth`: NAT flows from `ns80`'s veth guest through an internal veth pair,
  with the guest's checksum offload on and off.

The interface features of every rig interface are kept in `logs/`.

Results, the same in every run so far:

| Measurement                                                             | Native              | Generic, native peer |
| ----------------------------------------------------------------------- | ------------------- | -------------------- |
| 1201- and 1452-byte UDP payloads to a VIP (MTU 1500)                    | answered            | answered             |
| 1453- and 4001-byte UDP payloads, fragmented by the client              | not answered        | not answered         |
| 1 MiB client to VIP, checksum offload off, then on                      | intact, intact      | intact, intact       |
| 1 MiB client to guest through the pair, checksum offload off, then on   | intact, corrupted   | intact, corrupted    |
| Largest frame XDP saw, offload on                                       | 1514                | 34358 (GSO)          |
| NAT flows from a veth pod, its offload off, then on                     | 3 of 3, 0 of 3      | 3 of 3, 0 of 3       |
| Receiving device at MTU 9000                                            | XDP does not attach | attaches             |
| Unfragmented 1453- to 8001-byte payloads at MTU 9000 into a TAP at 1500 |                     | delivered, answered  |

The last row shows the TAP's MTU is not enforced on a redirect: the lab's
bridge hands such frames to the guest, which a real guest's driver would drop.

### Checksum offload

An XDP program that rewrites an address updates the L4 checksum as a complete
one. A frame that a sender on the same host sent through a veth with checksum
offload on carries a partial checksum instead, and XDP cannot tell the two
apart. After the rewrite and an `XDP_REDIRECT`, the frame reaches its receiver
with a wrong checksum and is dropped. A physical NIC delivers complete
checksums, which is why the rig's client sends with offload off;
`handoff-measure.sh` records both.

## Updating the expected results

After a deliberate change to the fixture, the prototypes or an expectation,
rerun with `HANDOFF_WRITE_EXPECTED=1 task handoff:twice`. The file is replaced
only when both runs pass and agree. Commit it with the change that caused it.
