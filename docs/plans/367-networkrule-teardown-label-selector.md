# Implementation Plan — Withdraw Every Advertisement a NetworkRule Ever Created

- **Issue:** [datum-cloud/galactic#367](https://github.com/datum-cloud/galactic/issues/367) — "A rule created
  before its gateway nodes waits hours to be programmed."
- **Found while reviewing:** #351.
- **Status:** planning only — no implementation started.

## 1. Issue recap and current status

The issue describes two timing gaps in `internal/controller/networkrule_controller.go`'s
per-rule lifecycle:

1. **No re-examination when gateway nodes register.** A rule created before any
   gateway node exists parks at `Accepted=False`/`NoGatewayNodes` and nothing
   re-queues it — `SetupWithManager` only watched `NetworkRule`, and the
   zero-nodes comment claimed a re-trigger that the watch graph didn't actually
   provide.
2. **Teardown naming can't survive node churn.** Deleting a rule withdraws its
   `BGPAdvertisement`s by reconstructing their names from
   `gatewayNodeNames(ctx, r.Client, rule.Namespace)` — the gateway nodes
   registered *right now*. A node that was registered when the rule was
   created and has since left the namespace is not in that list, so the
   advertisement created for it is never named and never withdrawn. The
   finalizer is removed anyway, leaving a route advertised with no forwarding
   state behind it.

**Gap 1 is already fixed**, on `main`, by commit `7fe39ec` ("fix(gateway): watch
NetworkGateway from NetworkRuleReconciler"): `SetupWithManager` now also
watches `NetworkGateway` via `gatewayToRuleRequests`, which re-queues every
`NetworkRule` in the namespace on any gateway-node change, and the zero-nodes
comment was rewritten to describe that watch accurately instead of the
non-existent re-trigger. Verified by reading current
`internal/controller/networkrule_controller.go:120-140,244-292` — matches the
issue's "Desired outcome" items 1 and 2 exactly. **No further work needed for
gap 1.**

This plan covers **gap 2 only**: teardown discovery.

## 2. Root cause

`bgpAdvertisementNamesForRule(rule, nodeNames)` (`networkrule_controller.go:302`)
derives each advertisement's name as `rule.Name + "-" + node + "-v4"/"-v6"` for
every node in `nodeNames`. `applyBGPAdvertisements`
(`networkgateway_controller.go:474`) uses the identical convention when
*creating* them — one object per gateway node per non-empty VIP address
family, name-qualified by that node's own name, because Active-Active means
every gateway node advertises the same rule independently (see that method's
doc comment on the AlreadyExists race it fixed).

The two sides agree on the naming convention, but only one of them has a
stable view of *which nodes ever created one*. Creation is driven by "this
node is reconciling this rule" — inherently per-node, at whatever moment that
node is registered. Teardown reconstructs "every node" from
`gatewayNodeNames` at deletion time, which answers "which nodes are
registered now," not "which nodes ever were." Membership is not
monotonic — nodes can be added and removed over a rule's lifetime — so name
reconstruction from current membership is structurally unable to find
advertisements for departed nodes. This is the same class of bug gap 1 was:
inferring historical state from a present-tense list.

## 3. Fix: discover by label, not by reconstructing names

Add a label to every `BGPAdvertisement` a rule owns at creation time, and have
teardown `List` by that label instead of reconstructing names. A label
recorded once at creation is immune to membership changing later — it doesn't
need to be recomputed, so there's nothing for node churn to invalidate.

Owner references (also suggested in the issue's comment) were considered as
well; see §6 for why this plan proposes the label alone rather than both.

### 3.1 New label constant

Add to `internal/controller/networkrule_controller.go`, next to
`networkRuleFinalizer` (same file, same convention as the `annotationConfigHash`
constant in `bgprouter_controller.go` / `crdnames`'s annotation constants —
this one is a label, not an annotation, since it exists purely to be listed
against, not read as data):

```go
// networkRuleLabel is set to rule.Name on every BGPAdvertisement a
// NetworkRule owns (one per gateway node per non-empty VIP address family —
// see applyBGPAdvertisements), so reconcileDelete can discover all of them
// with a List + label selector instead of reconstructing their names from
// the namespace's *current* gateway-node membership. A node that was
// registered when the rule was created and has since left would not appear
// in that reconstruction — see issue #367.
const networkRuleLabel = "galactic.datum.net/network-rule"
```

### 3.2 `applyBGPAdvertisements` sets and backfills the label

`networkgateway_controller.go:507-540` — set the label in the `IsNotFound`
(create) branch's `ObjectMeta`:

```go
adv = &bgpv1alpha1.BGPAdvertisement{
    ObjectMeta: metav1.ObjectMeta{
        Namespace: rule.Namespace,
        Name:      name,
        Labels:    map[string]string{networkRuleLabel: rule.Name},
    },
    Spec: ...,
}
```

And backfill it in the update branch, so any advertisement that predates this
fix (created by a cluster already running the old code) self-heals the next
time its owning node reconciles it, rather than being invisible to teardown
forever:

```go
advCopy := adv.DeepCopy()
if advCopy.Labels == nil {
    advCopy.Labels = map[string]string{}
}
advCopy.Labels[networkRuleLabel] = rule.Name
advCopy.Spec.RouterRef = ...
```

### 3.3 `reconcileDelete` lists by label instead of reconstructing names

`networkrule_controller.go:201-222` — replace the
`gatewayNodeNames` + `bgpAdvertisementNamesForRule` loop:

```go
advList := &bgpv1alpha1.BGPAdvertisementList{}
if err := r.List(ctx, advList,
    client.InNamespace(rule.Namespace),
    client.MatchingLabels{networkRuleLabel: rule.Name},
); err != nil {
    return ctrl.Result{}, fmt.Errorf("list BGPAdvertisements for NetworkRule %s/%s teardown: %w",
        rule.Namespace, rule.Name, err)
}
for i := range advList.Items {
    if delErr := r.Delete(ctx, &advList.Items[i]); delErr != nil && !apierrors.IsNotFound(delErr) {
        return ctrl.Result{}, fmt.Errorf("withdraw BGPAdvertisement %s: %w", advList.Items[i].Name, delErr)
    }
}
```

This finds every advertisement ever created for the rule regardless of
whether the node that created it is still registered, closing the gap
directly — no dependency on node membership at all during teardown.

No RBAC change: `config/galactic-gateway/rbac.yaml` already grants `list` on
`bgpadvertisements` to this ServiceAccount (`galactic-gateway` ClusterRole,
full CRUD comment already covers create+delete for this exact code path).

### 3.4 Remove now-dead code

- `bgpAdvertisementNamesForRule` (`networkrule_controller.go:302-325`) has no
  remaining caller once §3.3 lands (it was only ever called from
  `reconcileDelete`; `applyBGPAdvertisements` constructs its name inline and
  never called this helper) — delete it.
- `gatewayNodeNames` is still used elsewhere (`assignPrimaryNode`,
  `isGatewayNode`) — no change there.
- Update `applyBGPAdvertisements`'s doc comment
  (`networkgateway_controller.go:460-473`), which currently says the node
  qualifier keeps it "shared with networkrule_controller.go's teardown logic,
  so both sides always agree on which objects exist for a given rule" — that
  claim is no longer true (teardown no longer depends on the naming
  convention at all, only on the label) and should be rewritten to say so.

## 4. Testing

`internal/controller/networkrule_controller_test.go`:

- `TestNetworkRuleReconciler_TeardownOrder_WithdrawsBGPBeforeRemovingFinalizer`
  — its `adv` fixture needs the `networkRuleLabel` set (matching what
  `applyBGPAdvertisements` would now write) so the label-selector `List`
  finds it; otherwise this existing test starts failing under the new
  discovery mechanism.
- New: `TestNetworkRuleReconciler_TeardownWithdrawsAdvertisementForDepartedNode`
  — the regression test for the actual bug. Fixture: a `NetworkRule` with the
  finalizer and a deletion timestamp, a `BGPAdvertisement` labeled for that
  rule but named with a node (e.g. `testNodeGWB`) that has **no**
  corresponding `NetworkGateway` object in the fake client (simulating a node
  that registered, got an advertisement created, then left). Assert the
  advertisement is still deleted. This is the case the old
  `gatewayNodeNames`-reconstruction approach could never pass.
- New: `TestNetworkRuleReconciler_TeardownIgnoresAdvertisementForDifferentRule`
  — a second rule's differently-labeled advertisement in the same namespace
  must survive one rule's teardown, guarding against a selector that's too
  broad (e.g. an empty/missing label match).

`internal/controller/networkgateway_controller_test.go`:

- Extend `TestNetworkGatewayReconciler_CreatesBGPAdvertisementWithComputedLocalPref`
  (or add a sibling) to assert the created object carries
  `networkRuleLabel: rule.Name`.
- New: `TestNetworkGatewayReconciler_BackfillsLabelOnExistingAdvertisement` —
  a pre-existing `BGPAdvertisement` without the label, reconciled once,
  should come out with the label set (covers the self-heal path in §3.2).

## 5. Rollout

Per [[project_galactic_cni_not_production]]'s sibling reasoning for the
gateway control plane (also pre-production, per this repo's `docs/agents/
ARCHITECTURE-GATEWAY.md`), there's no back-compat constraint on existing
`BGPAdvertisement` objects lacking the label — the backfill-on-update in
§3.2 heals them the next time any gateway node reconciles the rule, which
happens on every `NetworkRule`/`NetworkGateway` change and at worst by the
informer's periodic resync. No manual migration step, no deployment ordering
constraint.

## 6. Alternative considered: owner references

The issue comment suggests owner references as an alternative to (or
alongside) a label. Considered and set aside for this pass:

- An owner reference from each `BGPAdvertisement` to its `NetworkRule` would
  give a Kubernetes-GC backstop (dependents get cleaned up once the owner is
  actually removed from etcd), but that's *after* `reconcileDelete` has
  already run `RemoveFinalizer` — by the time GC could act, this reconciler's
  own explicit delete-before-finalizer-removal ordering (the design plan's
  Teardown Ordering this finalizer exists to guard) has already had to find
  and delete the objects itself. Owner references don't help *find* them any
  more directly than a label does; `List` still needs a selector (label or
  field) either way — `client.Client.List` has no "list by owner reference"
  filter without also indexing on it, which is the same amount of plumbing
  as indexing/matching on a label.
- A label is one field on `ObjectMeta`, no `Scheme`/`controllerutil.
  SetControllerReference` call, and no risk of colliding with a future
  legitimate owner (e.g. if `BGPAdvertisement` ever gains a different owner
  for GC purposes elsewhere in this codebase — it doesn't today, but nothing
  rules it out).
- Nothing in this codebase uses owner references today (confirmed: no
  `SetOwnerReference`/`OwnerReferences` call site anywhere under `internal/`),
  so a label keeps this fix consistent with the codebase's existing
  all-explicit-reconciliation style rather than introducing the first
  dependency on implicit Kubernetes GC behavior.

If a future need arises for Kubernetes-native cascade delete independent of
this reconciler (e.g. an operator manually deleting a `BGPAdvertisement`
namespace-wide), owner references can be added later without conflicting with
the label — they're not mutually exclusive, just not necessary to close this
issue.

## 7. Open questions for review

- Should the label key also be usable for `internal/gc`'s existing
  orphan-sweep logic (`gc.CollectOrphanedCRDs`), or is that sweep's
  containerID-based liveness check (CNI-side attachments) unrelated enough to
  the gateway's rule-based advertisements that they should stay separate
  vocabularies? Leaning toward separate — the gateway's `BGPAdvertisement`s
  and the CNI attach chain's are different producers with different liveness
  models — but flagging since both ultimately clean up the same CRD kind.
