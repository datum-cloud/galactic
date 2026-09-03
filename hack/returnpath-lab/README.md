# returnpath-lab

Phase 0 proof harness for
[docs/plans/855-return-path-ingress-decap.md](../../docs/plans/855-return-path-ingress-decap.md).

A lab tool, not a shipped binary. It performs by hand — and reverses — exactly
what that plan's Pieces 1–3 would automate, so the plan's derived-but-unproven
kernel assumptions can be tested before production code is written against
them. It calls the same packages the real implementation will
(`internal/plumbing/ebpf/usidmap`, `intf`, `uformat`, `egressroutemap`), so
what it proves is proven about the real code paths.

## Running it

Needs the host root netns, `hostPID`, `privileged` (setns wants
`CAP_SYS_ADMIN` on top of `NET_ADMIN`/`BPF`/`NET_RAW`), and the host's bpffs.
`galactic-system` enforces `privileged` pod security, so a pod there works:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /tmp/returnpath-lab ./hack/returnpath-lab
kubectl -n galactic-system apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: returnpath-lab, namespace: galactic-system}
spec:
  nodeName: NODE            # the node hosting the Envoy Gateway pod
  hostNetwork: true
  hostPID: true             # pod-netns discovery walks /proc
  restartPolicy: Never
  containers:
    - name: lab
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext: {privileged: true, runAsUser: 0}
      volumeMounts: [{name: bpf-fs, mountPath: /sys/fs/bpf}]
  volumes:
    - name: bpf-fs
      hostPath: {path: /sys/fs/bpf, type: Directory}
EOF
kubectl -n galactic-system cp /tmp/returnpath-lab returnpath-lab:/work/returnpath-lab
```

Invoke through `sh -c` — under a bare `kubectl exec ... -- binary sub -flags`
the flags do not reach the process:

```bash
kubectl -n galactic-system exec returnpath-lab -- sh -c "/work/returnpath-lab status $FLAGS"
```

## The facts it needs

| Flag | Where it comes from |
| ----------- | ------------------------------------------------------------------------------- |
| `-locator` | `kubectl -n galactic-system get bgprouter <node> -o jsonpath='{.spec.srv6Locator}'` |
| `-node-id` | the same object's `.spec.nodeID` |
| `-vpc` | the base62 VPC id — the first segment of an `EndpointSlice`'s `galactic.datum.net/tenant-id` |
| `-argument` | `.spec.vrfID` of `BGPVRFInstance` `<vpcHex>-<node>` |
| `-gw-addr` | the `/128` in the sidecar's own `BGPAdvertisement` (`<vpcHex>-<ingressHex>-<node>`) |

Note that `-argument` (the CRD's `VRFID`) is **not** the pod-netns Linux VRF
table id, and the two routinely differ. The advertised SID encodes the CRD
value, so that is what `vrf_table` must be keyed on.

## Subcommands

| | |
| -------------- | ---------------------------------------------------------------------------- |
| `status` | read-only: every piece of state the return path needs, and whether it exists |
| `up` | install it (needs `-yes`; without it, prints the plan only) |
| `down` | remove it (`-purge-locator` also removes the locator/function entries) |
| `probe` | open a VRF-bound TCP connection from inside the Envoy pod's netns, as #856 configures Envoy. **Refused counts as success** — a RST has to traverse the whole return path |
| `inject` | send a real SRv6-encapsulated packet at a node's return SID, isolating decap from whether any tenant workload replies |
| `egress-route` | look one `/128` up in `egress_route_table` — run on a *backend* node against the gateway address to see whether it imported the advertisement |
| `filters` | list an interface's tc filter chain in evaluation order |
| `verify-maps` | check that the bpffs-pinned maps are the same objects the attached program reads |

Always run `probe` before `up` for a baseline. `-purge-locator` on teardown is
not optional on a node that also runs `galactic-gateway` — see below.

## What the first run established (2026-09-02, us-central-1-staging-lab)

Confirmed:

- **Gaps 1 and 2 are real.** `locator_table` and `function_table` were empty
  on the gateway node; `vrf_table` held only the sidecar's five synthetic
  `BlockMax` entries and nothing under the node's real locator.
- **Pod-netns discovery works**, which answers the plan's Open Question 1:
  walking `/proc/*/ns/net`, deduplicating by inode, and looking for
  `intf.GenerateInterfaceNameVRF(vpc)` finds the Envoy pod's namespace
  unambiguously. The VRF's name is the identifier — no annotation, CRI call
  or published inode is needed.
- **The sibling plan's advertisement path works end to end.** On the backend
  node, `egress_route_table` resolved the gateway address to
  `2607:ed40:8002:6:e001::`, decoding to exactly the expected block, Node-ID,
  Function and Argument.
- **Envoy's source-address selection is correct** — a VRF-bound socket in the
  Envoy pod sourced from the derived gateway address.
- **`up` installs cleanly**: veth across the netns boundary, enslavement into
  the pod-netns VRF, a `/128` into a bare routing table with no VRF device,
  a `NUD_PERMANENT` neighbor entry, and all three map entries.

Found, and not previously known:

- **The forward path drops packets on the backend node.** `vrf_table` for that
  VPC showed `pkts=54 drops=21` against `fib_no_neigh=21` — ~40% loss. The
  backend is a Kraftlet unikernel on a tap (`egress_kind=1`), and
  `hostgw.ConfigureHostGateway` installs its permanent neighbor entry only
  when `guestHWAddr != nil`, which its own doc comment says is "nil for tap
  attachments". So tap-backed workloads depend on dynamic NDP and lose
  traffic when it is not resolved. This is independent of the return path and
  is live today.
- **Seeding `locator_table` is not harmless on a `galactic-gateway` node.**
  That component's `GALACTIC_GATEWAY_SRV6_ADDRESS` shares this node's Block
  and Node-ID with Function `0x0`. `usid_ingress` step 2 matches on the top
  64 bits alone, so once a locator entry exists the gateway's own address is
  claimed and then dropped at step 4 as `UNKNOWN_FUNCTION` rather than passed
  through. Measured zero collateral in a short window here, but it is
  structural, and the plan's Piece 1 currently describes these writes as
  harmless.
- **`usid_egress` never sees host-originated traffic.** It attaches to the
  *ingress* hook of a tenant's tap/veth, where a workload's own outbound
  traffic arrives. A packet the host originates into a tenant VRF bypasses it
  entirely and leaves via that VRF's NAT66 default route.
- **The fabric carries only `/128` routes for advertised SIDs.** The
  containing `/48` is a `Null0` static, so an arbitrary address in a node's
  own locator space is unroutable — any design assuming locator-prefix
  reachability is wrong.
- **The Go drop-reason mirror is behind `usid.c`.** `prog.DropReasonCount` is
  16 while the C enum defines 29, and `metrics/collector.go` iterates only to
  the former, so the `TRACE_*` counters are never exported. Separately, a
  node whose bpffs `drop_reasons` pin predates a newly-added reason has a map
  too small to hold it and `count_drop` silently fails for that index, so two
  nodes on the identical image can expose different counters.

## Root cause, established (2026-09-02)

Phase 0's gate is **not** cleared, and the reason is upstream of everything the
plan describes. Inter-node SRv6 decap cannot work on this cluster at all:

1. **`usid_ingress` is not attached to the interface that carries the
   traffic.** `attach.ResolveInterfaces` picks the interfaces holding the IPv6
   default route and then deliberately skips WireGuard links
   (`attach/interfaces.go:166`, `excludedLinkType`) — a sensible guard, since a
   WireGuard mesh can install a default-ish route and
   `srv6.ResolveNodeSourceAddress` would otherwise bake its ULA in as the
   node's source address. But this is Talos with KubeSpan enabled, and
   `kubespan` is exactly what carries all inter-node IPv6 — the iBGP sessions
   included. Attached sets were `[lo bond0 eno2 enp3s0f1]` on the gateway node
   and `[lo bond0 ens2f1np1 ens1f1np1]` on the backend node; neither includes
   `kubespan`.

   Proven by capture: an injected return packet arrives correctly formed and on
   the wrong interface —

   ```
   kubespan In IP6 2600:9c01:0:c::2 > 2607:ed40:8002:6:e001:::
              IP6 fd20:0:2::3:0:0.44444 > fd30:e2e:3a5:...:9999: Flags [S]
   ```

   while `tcpdump` on `eno2`, `enp3s0f1` and `bond0`, filtered to that same
   destination, captured nothing.

2. **Attaching it there is not sufficient either.** `attach-iface` was used to
   attach the running program (id 2828) to `kubespan` via the production
   `attach.Attach` path, with Pieces 1–3 installed and every map entry
   verified. `vrf_table` `pkts` stayed at 0. `kubespan` reports `link-type RAW
   (Raw IP)` — there is no Ethernet header — and `usid_ingress` step 1
   unconditionally parses `struct usid_ethhdr` and tests `h_proto ==
   ETH_P_IPV6`. On an L3 interface it reads the inner IPv6 header's own bytes
   as an ethertype, mismatches, and returns `TC_ACT_UNSPEC` — silently, on the
   one path that is deliberately uncounted.

So the datapath structurally assumes an Ethernet-framed fabric. Over a
KubeSpan/WireGuard mesh it cannot decap, and the same applies to the forward
direction: the backend node's `vrf_table` hits (`pkts=54`) come from the Envoy
pod *on that same node*, whose encapsulated traffic loops back via `lo` — which
*is* in the attached set. Cross-node #855 ingress has therefore never worked
here, in either direction.

### What this means for the plan

Pieces 1–3 are still necessary and their key derivations are confirmed correct,
but they are not sufficient and are not the top blocker. Before any of that
work is worth doing, one of the following has to be settled:

- run the SRv6 fabric over an Ethernet-framed underlay on these nodes (i.e. do
  not carry it over KubeSpan), or
- teach `usid_ingress`/`usid_egress` to handle L3/RAW interfaces — detect the
  absence of a MAC header rather than assuming `ETH_HLEN`, and give step 9 a
  redirect path that does not depend on resolved L2 addressing.

Either is a materially larger change than this plan's Pieces 1–3, and the
choice belongs with whoever owns the underlay.

### Still unverified

The plan's assumption 2 — `bpf_redirect_peer` from root netns into a
VRF-enslaved pod-side veth delivering to a `SO_BINDTODEVICE`-bound socket —
remains untested, because no packet ever reached step 6. It needs an
environment where inter-node decap works at all.
