# XDP attach mode

Every Galactic XDP attachment on a host uses one attach mode, chosen once per
process at startup by `internal/plumbing/ebpf/xdpmode`. That covers
`galactic-gateway`'s `edge_lb` and `edge_return`, `galactic-nat`'s
`nat_ingress`, and the shared dispatcher (`xdp_dispatch`) both of them use in
dispatch mode.

| Host                        | Mode            | Shown by `ip -d link show` as |
| --------------------------- | --------------- | ----------------------------- |
| Any NIC driven by `bnxt_en` | generic (SKB)   | `xdpgeneric`                  |
| Every other host            | native (driver) | `xdp`                         |

## Why bnxt_en hosts run generic mode

On `bnxt_en`, native XDP redirect traffic is associated with receive queues
that stop delivering and never recover (#673). The suspected driver defect is
that RX producer updates are suppressed while the paired XDP TX ring is busy.
That mechanism is a hypothesis, not a confirmed root cause.

Generic mode runs the same programs after the driver has built an skb. Their
`XDP_TX` and `XDP_REDIRECT` verdicts then go through the kernel's ordinary
transmit path, so the driver's XDP TX ring is never used. Short test runs in generic mode
saw no NIC queue discards or stalls. That is limited-duration evidence, not
proof that the stall is gone.

The `GalacticNatUplinkRxQueueStalled` alert (`config/monitoring/`) still
watches for it, and `galactic-nat` still exports the `bnxt_en` ring counters
from #779.

## What the selection looks at

- **Drivers come from sysfs.** Each interface under `/sys/class/net` with a
  `device` link is a physical NIC, and its driver is the last element of
  `device/driver`. Bond masters, VLANs, veths and other virtual interfaces have
  no `device` link and are ignored, but they still get the host's mode, so a
  host never mixes native and generic redirect paths.
- **A bnxt_en NIC anywhere selects generic for everything.** It doesn't have
  to be one of the datapath's own targets.
- **Unknown state fails startup.** A target interface that doesn't exist, a
  target NIC whose driver can't be read, or any NIC whose driver link exists
  but can't be read, stops the process at startup with the reason in the
  error. None of them ever settles the mode by omission.
- **A NIC with no driver at all is skipped.** That happens while a driver
  unbinds. If the NIC isn't one of the datapath's targets it carries no
  driver traffic, so it is left out of the decision with a warning naming
  it.
- **The decision is logged.** Each process logs
  `Selected the XDP attach mode for this host` with `mode` and `reason`. The
  reason names the matching NICs.
- **The mode is fixed for the life of the process.** A NIC hot-added later
  doesn't change it, so restart both pods after adding one.
- **The latest decision is recorded on the host.** Each dispatch-mode process
  that attaches records the mode it selected in a pinned record beside the
  dispatcher (`/sys/fs/bpf/galactic-xdp/host_mode`). A datapath being turned
  off only clears its slots and records nothing. A process whose mode no longer
  matches the record doesn't move a link back. It logs the error, reports its
  interfaces uncovered, and stays not-ready until it is restarted. Two
  processes that disagree therefore never move one link back and forth.

## Attach, readiness and coverage

- **No fallback between modes.** Every attach requests its mode explicitly
  (`XDPGenericMode` or `XDPDriverMode`) and returns an error rather than
  trying the other one.
- **The native-support check runs only in native mode.** The netdev
  `xdp-features` check is skipped in generic mode, which runs on any
  interface.
- **Readiness reads the real attach mode.** Coverage, and so readiness, reads
  the mode back from the kernel (`IFLA_XDP_ATTACHED`). An interface whose hook
  holds the program in the other mode counts as uncovered.
  - Direct mode: `xdpattach.Set.Attached` and `Reconcile`.
  - Dispatch mode: `xdpdispatch.Dispatcher.Linked` and `Coverage`, which
    report `ErrModeMismatch`.
  - The gateway's `readiness` gRPC service reports NOT_SERVING, and the
    shard's `EgressShard` reports `UplinksMissing`, until the mode matches.

## Moving a running node to the selected mode

**Direct mode** needs nothing special. Links aren't pinned, so the restart
that brings the new release detaches the old program and attaches in the
selected mode. That bounces each uplink, as every direct-mode restart does.

**Dispatch mode** keeps its links pinned across restarts, so a node already
running the dispatcher in native mode is migrated in place.

1. A link in the other mode isn't counted as linked. So the reconcile that
   finds it runs the same guards as a first attach, under the node-wide
   dispatch lock.
2. A bond member that is the only one carrying traffic is left for a later
   pass. Its old link still carries traffic, but its coverage reads as
   missing, so the pod stays not-ready until a sibling is up and the member
   can be migrated.
3. The pinned link is detached and the root attached again in the selected
   mode, then re-pinned. The kernel won't change a link's mode in place or
   hold a native and a generic program on one interface at once.
4. The driver resets its rings, as on a first attach. The process waits for
   the member to rejoin its bond before touching the next. A member that
   doesn't rejoin in time defers every remaining member to the next pass.
5. The interface carries no program between the detach and the new attach.

Only the link changes. The dispatch maps, the root program, every slot, lease
and role row survive, so each datapath's slot runs again as soon as the new
link is up.

If the new attach fails, the root is attached again in the mode it was in, the
error is logged, and the interface stays uncovered for readiness. Retries for
that interface back off, from 30 seconds doubling up to 10 minutes, so a
failure that persists doesn't bounce the uplink on every reconcile. If even
the restore fails, the interface has no dispatcher until a later reconcile
attaches one fresh.

A pinned link whose current mode can't be read is left alone with an error
rather than detached, and so is a foreign XDP program in either mode.

## Performance

Generic mode allocates an skb for every frame before the program runs, so
the program no longer sees frames straight from the driver's receive ring.
Expect fewer packets per second per core and
more CPU per packet than native mode on the same NIC. On `bnxt_en` hosts that
cost buys uplinks that keep receiving.

Compare `galactic_nat_*` and `galactic_edge_*` packet rates and node CPU
before and after the change on the same traffic before relying on the old
capacity figures.

## Rollback

- **Rolling back to a release without mode selection doesn't restore native
  mode by itself.** Those releases attach in native mode, but in dispatch mode
  they accept any live pinned link without checking its mode, so a node
  already migrated stays generic. To return such a node to native mode:
  1. Roll back the image.
  2. Run `hack/xdp-dispatch-release.sh` on the node to detach the dispatcher.
  3. Restart `galactic-gateway` and `galactic-nat`.

  Every uplink bounces once, so do this in a maintenance window.
- **In direct mode, rolling back and restarting is enough.**
- **There is no override variable.** The mode follows the host's NICs, so
  every datapath on a host always agrees.

## Validation

On a host with a `bnxt_en` NIC after the release reaches it:

1. Both pods log `Selected the XDP attach mode for this host` with
   `mode=generic` and a reason naming the `bnxt_en` NICs.
2. `ip -d link show` on the node shows `xdpgeneric` with
   `prog/xdp ... name xdp_dispatch` on every bond member, and nothing in
   native mode.
3. The gateway's readiness probe passes, the `EgressShard` is `Ready`, and
   `galactic_nat_uplink_covered` is 1 for every uplink.
4. NAT64 and NAT66 TCP, UDP and ping through the shard, and VIP traffic
   through the gateway, all pass. Use `task verify:nat-egress` and
   `task verify:gateway-ingress` in the lab, and the same checks against
   your own clusters.
5. Over at least a day of normal traffic, neither
   `GalacticNatUplinkRxQueueStalled` nor `GalacticNatUplinkRxQueueLossy`
   fires, per-queue receive counters keep rising on every queue, and NIC
   queue discards stay at zero.

A node that already runs the dispatcher in generic mode needs no migration
and sees no bounce.
