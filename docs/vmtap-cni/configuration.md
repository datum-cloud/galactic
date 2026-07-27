# vmtap-cni Configuration

`vmtap-cni` is a standalone CNI plugin, separate from `galactic-cni`, that gives a
Unikraft microVM managed by `kraftlet` access to the pod's real Cilium-assigned
identity. It has no VPC/VPCAttachment configuration and no Kubernetes API
dependency — it never creates a `BGPAdvertisement`, never touches a VRF, and
these pods have no `vpc`/`vpcattachment`. See
[.local/kraftlet-cilium-tap-plan.md](../../.local/kraftlet-cilium-tap-plan.md)
for the full design.

> This plugin has not yet been validated against a real Cilium-managed cluster
> — see [Open items / unvalidated caveats](#open-items--unvalidated-caveats) below
> before relying on it in production.

## How it works

`vmtap-cni` must be **chained** after Cilium's own CNI plugin inside the pod's
primary conflist (e.g. appended into whatever `/etc/cni/net.d/*cilium*.conflist`
Cilium installs) — it is not delivered via a Multus `NetworkAttachmentDefinition`,
and it does not run standalone. Because it runs as part of the same `cmdAdd`
invocation that creates the pod's `eth0`, it receives Cilium's `prevResult`
(interface name, MAC, MTU, IPs) directly.

On `ADD`, inside the pod's network namespace:

1. Reads `eth0`'s state from `prevResult` (MAC, link MTU) and the kernel's
   routing table (route MTU) — see [MTU handling](#mtu-handling) below.
   **`eth0` itself is never modified.**
2. Creates a tap device (default name `tap0`) with its MTU set to the
   resolved route MTU.
3. Installs a `clsact`-equivalent `ingress` qdisc and a `tc-mirred` redirect
   filter on both `eth0` and the tap in each direction, so every packet
   arriving on one is stolen and re-injected as egress on the other.
4. Returns a CNI result that copies `prevResult` forward (this plugin is the
   last one in the chain, so its result is what the runtime hands back) and
   appends the tap as a new interface entry, with `sandbox` set to
   `CNI_CONTAINERID` instead of a netns path — see
   [How kraftlet reads the result](#how-kraftlet-reads-the-result) below.

`DEL` removes the redirect filters and the tap device; both `DEL` and `CHECK`
are idempotent per the CNI spec. Opening the tap's fd, handing it to the VMM,
and configuring the Unikraft guest's network stack (no runtime DHCP by
default) are **not** this plugin's job — that is `kraftlet`'s responsibility
once it reads this plugin's `ADD` result.

## CNI Configuration JSON

All fields are optional; the plugin runs against sane defaults when the
config block is empty (`{"type": "vmtap-cni"}` is a valid entry).

| Field             | Type     | Default    | Description                                                                                                               |
| ----------------- | -------- | ---------- | --------------------------------------------------------------------------------------------------------------------------- |
| `enabled`         | `bool`   | `true`     | Set to `false` to no-op this conflist entry (passes `prevResult` through unchanged) without removing it from the chain.   |
| `tap_name`        | `string` | `"tap0"`   | Name of the tap device created inside the pod netns.                                                                       |
| `owner_uid`       | `int`    | `0` (root) | Tap device owner uid, so a non-root VMM process can open its fd without `CAP_NET_ADMIN`.                                  |
| `owner_gid`       | `int`    | `0` (root) | Tap device owner gid.                                                                                                      |
| `filter_priority` | `int`    | `1`        | tc filter priority for the mirred redirect filters. Override if it collides with Cilium's own hooks — see the caveat below. |

Standard CNI fields (`cniVersion`, `name`, `prevResult`) are inherited from the
conflist envelope, as for any chained plugin.

### Example conflist entry

```json
{
  "cniVersion": "1.0.0",
  "name": "cilium",
  "plugins": [
    { "type": "cilium-cni" },
    { "type": "vmtap-cni" }
  ]
}
```

## MTU handling

Cilium adjusts the pod's *route* MTU for overlay/tunnel overhead, which can
differ from `eth0`'s *link* MTU. `vmtap-cni` reads the actual route MTU from
the kernel routing table (the route's `MTU` metric, via netlink `RouteList`)
rather than copying the link MTU, and sets the tap's own MTU to that
resolved value — so the tap's `mtu` field in the CNI result already carries
the corrected number kraftlet needs, without a separate schema field. If no
route carries an explicit MTU metric, it falls back to `eth0`'s link MTU.

## How kraftlet reads the result

`vmtap-cni`'s `cmdAdd` runs at pod-sandbox-creation time, invoked by whatever
calls the chained conflist (typically containerd's CNI integration) — not by
`kraftlet` directly. `kraftlet`'s own VM-start code runs later, as a separate
step, and needs to read the same CNI result back out.

This plugin's convention: the tap's interface entry in the CNI result sets
`sandbox` to `CNI_CONTAINERID` (the CRI sandbox ID) rather than a netns path,
since there is no netns for the VM the way there is for a container.
**This convention has not been confirmed against the actual kraftlet/CRI
integration** — see the open item below.

## Cilium-specific caveats (unvalidated)

These are called out explicitly because they are correctness risks this
plugin's code cannot self-verify — they require a real Cilium-managed
cluster to confirm:

- **tc/bpf hook ordering**: the default `filter_priority` (`1`) has not been
  checked against any specific Cilium version/datapath mode (veth vs.
  netkit, tunnel vs. native routing) for a collision with Cilium's own
  `clsact` bpf programs on `eth0`.
- **socketLB / kube-proxy replacement**: Cilium's socket-level load balancing
  intercepts `connect()`/`sendmsg()` in the *host* kernel, which the guest's
  own kernel never reaches. This needs a **cluster-wide** Cilium config
  change (`socketLB.hostNamespaceOnly=true`), not anything this plugin can
  set per-pod.
- **Envoy sidecar interaction**: unverified whether Envoy/Cilium's own
  interception of traffic on `eth0` still works correctly once that traffic
  is also being mirrored to/from the tap.
- **NetworkPolicy, Service routing, Hubble attribution**: all assumed to
  keep working because `eth0`'s identity is untouched, but not yet tested
  end-to-end.

## Open items

- **Conflist chaining.** `vmtap-cni` ships with a `patch-conflist` subcommand
  (`internal/vmtap.RunPatchLoop`, wired into
  [`config/vmtap/daemonset.yaml`](../../config/vmtap/daemonset.yaml)) that
  polls for a `*cilium*.conflist` file and appends a `{"type": "vmtap-cni"}`
  entry to it if missing. This is a best-effort convergence loop, **not** a
  verified solution — it does not guarantee the patch lands before Cilium
  starts servicing `ADD` calls on a freshly booted node, and it does not
  remove its own entry on uninstall (manually edit Cilium's conflist back
  out if needed).
- **Pod-level trigger signal.** Which pods get this conflist entry at all
  (RuntimeClass vs. annotation) is not decided; `config/vmtap/daemonset.yaml`
  currently gates the whole DaemonSet on a placeholder node label
  (`galactic.datumapis.com/node: kraftlet`) that does not exist anywhere else
  in this repo.
- **kraftlet hand-off convention.** The `sandbox: CNI_CONTAINERID` convention
  described above is this plugin's own choice, not something confirmed
  against kraftlet's actual CRI/containerd integration.

See [.local/kraftlet-cilium-tap-plan.md](../../.local/kraftlet-cilium-tap-plan.md)
section 7 for the full list.
