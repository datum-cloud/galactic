# Implementation Plan — Fail ADD When the CNI Chain Is Missing `galactic-bgp`

- **Issue:** [datum-cloud/galactic#331](https://github.com/datum-cloud/galactic/issues/331) — "An
  incomplete plugin chain still reports a successful attach."
- **Related:** #305 (moved BGP/SRv6/eBPF publish out of the master plugin and into its own
  chained binary, `galactic-bgp`), #327 (same failure shape — silently-wrong config produces a
  pod that looks attached and isn't; fixed at the IPAM-config level, this issue is the
  chain-topology-level counterpart).
- **Status:** implemented — see `internal/hostconf.VerifyChainIncludes`,
  `internal/nadpatch.VerifyChainComplete`, and the wiring in
  `internal/cni/ops_add.go`/`internal/cnitap/ops_add.go`. `task lint`/
  `task build`/`task test:unit` all pass; `task test:e2e` was not re-run
  (the new check doesn't change behavior on the no-`CNI_ARGS` path
  `TestCNITapInterface` exercises — see its updated doc comment).

## 1. Problem statement

Before #305, the master plugin (`galactic-veth`/`galactic-tap`) published BGP/SRv6 state
itself, in-process, as part of its own ADD. A successful ADD *was* proof the datapath existed.
#305 moved that work into `galactic-bgp`, a separate binary the CNI runtime invokes next,
named in the attachment's own conflist (its `NetworkAttachmentDefinition.spec.config`, authored
by the external VPC operator — not this repo).

`galactic-bgp` guards its *own* invocation: `inferFromPrevResult`
(`internal/cnibgp/prevresult.go`) errors if `prevResult` is absent, so it can't run un-chained.
But nothing guards the other direction. If the conflist simply omits the `galactic-bgp` stanza —
a stale template, a hand-edit, a bug in the operator that generates it — every plugin that *does*
run (`galactic-veth`/`galactic-tap`, `galactic-ipam`, optionally `galactic-route`) returns
success. The pod ends up with a working interface and addresses, and zero BGP/SRv6 state: no
route to its VPC, and nothing anywhere logs or errors about it.

**Outcome wanted (from the issue):** ADD fails, loudly, the moment the chain is provably
incomplete — rather than handing back an attachment that looks fine and cannot reach anything.

## 2. Where "the chain" is actually visible to a plugin

Per the CNI chaining model, each plugin binary in a chain is invoked with **only its own**
config object on stdin, plus `prevResult` — never the full plugin list. So the master plugin's
own `args.StdinData` cannot answer "is `galactic-bgp` chained after me?" by itself; the full
list only exists in one place at ADD time: the `NetworkAttachmentDefinition` object's own
`spec.config` (a full conflist JSON: `{"cniVersion":..., "name":..., "plugins":[...]}` — see
`deploy/containerlab/resources/tenants/ns10/dfw/nad.yaml` for a real example, and
`docs/cni/configuration.md`'s "Chain structure" section).

The master plugin already talks to that exact object today — `internal/nadpatch.AnnotateNAD`
patches it with the host-interface-name annotation, using `pluginConf.Name` as the NAD's own
k8s object name and `nadpatch.ParsePodNamespace(args.Args)` as its namespace (both `ops_add.go`
call sites already resolve these before calling `AnnotateNAD`). Fetching `spec.config` is a
`Get` against that same object, by that same identity — no new lookup mechanism, just reading a
field nothing currently reads.

This is *not* the same file `internal/hostconf.Load` reads (`/etc/cni/net.d/10-galactic.conflist`,
written once per node by `internal/installer.Bootstrap`, carrying only node-local settings under
a single `"type": "galactic-cni"` entry). That static conflist has no `vpc`/`vpcattachment` and
never contains `galactic-bgp` — it is the wrong document to check. The per-attachment chain
lives only in the NAD.

## 3. Standalone/manual invocation must still no-op

`nadpatch.AnnotateNAD` already treats an empty `nadNamespace` (no `CNI_ARGS`, i.e. not really
invoked by Multus — e.g. `tests/e2e`'s `TestCNITapInterface`, which pipes a raw CNI config
directly into `/galactic-tap` and manually chains `galactic-bgp` itself afterward, precisely
*because* it has no NAD/RBAC fixture set up for a real conflist-driven chain) as "nothing to
patch." The new check must follow the exact same convention: no `CNI_ARGS` means no NAD to read,
so skip rather than fail. Anything else would break that e2e test (and any other standalone/
manual invocation) for a reason unrelated to what #331 is actually about.

## 4. New code

### 4.1 `internal/hostconf`: a reusable "does this conflist chain X" check

`hostconf` already owns the CNI conflist envelope shape (`conflistEnvelope`, used by `Load`) and
the other cross-cutting master-plugin config guard (`RejectMovedIPAMKeys`). Add the BGP-plugin
identity and a small parser next to those:

```go
// BGPPluginType is the "type" value a conflist entry must carry for
// galactic-bgp, the chained plugin that publishes BGP/SRv6/eBPF state after
// a master plugin (galactic-veth/galactic-tap) creates the interface. Both
// master plugins check for its presence in their own attachment's conflist
// before doing any other work — see VerifyChainIncludes.
const BGPPluginType = "galactic-bgp"

// VerifyChainIncludes parses configJSON as a CNI NetConfList — the same
// {"plugins":[{"type":...}, ...]} envelope Load already parses, here read
// from a NetworkAttachmentDefinition's own spec.config rather than a file —
// and reports an error naming expectedType if no entry's "type" field
// equals it anywhere in the list.
//
// Presence-only, not position-aware: a conflist that names expectedType
// out of order is a separate authoring bug this does not catch. Presence
// is what #331 asks for ("attach fails when the chain is incomplete") and
// is the cheapest check that catches the actual failure mode reported
// there — a stale/hand-edited conflist that drops the entry entirely.
func VerifyChainIncludes(configJSON []byte, expectedType string) error
```

Table-driven unit tests in `hostconf_test.go`: complete chain (pass), `galactic-bgp` entry
missing (fail, error names `expectedType`), empty/malformed `plugins`, and a single flat
NetConf object with no `"plugins"` key at all (the pre-#305 shape — must fail, not silently pass,
since a hand-edit reverting to that shape is exactly the kind of stale-conflist drift #331 is
about).

### 4.2 `internal/nadpatch`: fetch `spec.config` and run the check

```go
// VerifyChainComplete fetches nadName's NetworkAttachmentDefinition and
// fails if its own spec.config does not chain expectedType anywhere in its
// plugins list. A conflist that omits it — stale, hand-edited, or a bug in
// the external operator that authors it — would otherwise let every
// plugin that DOES run report ADD success, handing back a pod with a
// working interface and no path to its VPC (issue #331).
//
// nadNamespace == "" (no CNI_ARGS — a standalone/manual chain invocation,
// not a real Multus-driven attach; see tests/e2e's TestCNITapInterface) is
// treated as nothing to check, mirroring AnnotateNAD's own convention:
// there is no NAD to read in that case.
func VerifyChainComplete(ctx context.Context, k8s client.Client, nadName, nadNamespace, expectedType string) error {
	if nadNamespace == "" {
		return nil
	}
	nad := &unstructured.Unstructured{}
	nad.SetGroupVersionKind(nadGVK)
	if err := k8s.Get(ctx, client.ObjectKey{Name: nadName, Namespace: nadNamespace}, nad); err != nil {
		return fmt.Errorf("get NetworkAttachmentDefinition %s/%s: %w", nadNamespace, nadName, err)
	}
	configStr, found, err := unstructured.NestedString(nad.Object, "spec", "config")
	if err != nil || !found || configStr == "" {
		return fmt.Errorf("NetworkAttachmentDefinition %s/%s has no spec.config", nadNamespace, nadName)
	}
	return hostconf.VerifyChainIncludes([]byte(configStr), expectedType)
}
```

Reuses the package's existing `nadGVK`. Unit tests in `nadpatch_test.go`, mirroring the existing
`AnnotateNAD` fake-client tests: NAD not found (fail), NAD found with a complete conflist (pass),
NAD found with `galactic-bgp` missing from `spec.config` (fail, error surfaces the missing
type), empty namespace (pass/no-op, no Get issued — assert on the fake client's call count or
via a client that fails any Get to prove it's never invoked).

### 4.3 Wiring into both master plugins

`internal/cni/ops_add.go` and `internal/cnitap/ops_add.go` are near-identical here — both do the
following today, right before the NAD annotation step: `NewK8sClient()`, then
`nadpatch.ParsePodNamespace(args.Args)`, then a `context.WithTimeout(..., cnimaster.NADPatchTimeout)`,
then `AnnotateNAD`. The fix:

1. Move the `NewK8sClient()` call (and `podNamespace` resolution) up, to immediately after the
   existing `NODE_NAME` check — before `vrf.Add`/`veth.Add`/`tap.Add`. This is deliberately
   *before* any kernel state is created: a stale conflist should fail ADD with nothing to roll
   back, not after already creating a VRF and interface. It also keeps
   `TestCmdAddPrevResultValid` (`internal/cni/cni_test.go`) passing unchanged — that test
   unsets `NODE_NAME` specifically to force a deterministic failure *before* anything
   k8s-client-dependent runs, and the new check must stay after that gate for the same reason.
2. Call `nadpatch.VerifyChainComplete(ctx, k8sClient, pluginConf.Name, podNamespace, hostconf.BGPPluginType)`
   using the same `cnimaster.NADPatchTimeout`-bounded context pattern already used for
   `AnnotateNAD`. On error, return a `*types.Error{Code: 7, Msg: ...}` — code 7 matches every
   other "the externally-authored config is wrong" failure in this chain
   (`hostconf.RejectMovedIPAMKeys`, `errInvalidCNIConfig`, the VPC/VPCAttachment-required
   errors), not code 6 (reserved for `prevResult` validation) or code 4 (env vars).
3. Reuse the same `k8sClient` for the later `AnnotateNAD` call instead of constructing a second
   client — drop the now-redundant second `NewK8sClient()` call.
4. Update `cnimaster.NADPatchTimeout`'s doc comment: it now bounds two k8s calls per ADD (the
   chain-completeness `Get` and the annotation `Patch`), not just one.

## 5. Scope: master plugins only

This only guards `galactic-veth`'s and `galactic-tap`'s own ADD. It does not touch
`internal/cniroute` or `internal/cnibgp` themselves — `galactic-bgp` already guards the
direction it can (`inferFromPrevResult` requires `prevResult`), and `galactic-route` passes
`prevResult` through unchanged with no equivalent claim to verify. The gap #331 identifies is
specifically "nothing guards the other direction," i.e. nothing upstream confirms a downstream
plugin's existence — that's what this plan adds.

## 6. Testing

- `internal/hostconf`: table-driven tests for `VerifyChainIncludes` (§4.1).
- `internal/nadpatch`: fake-client tests for `VerifyChainComplete` (§4.2).
- `internal/cni` / `internal/cnitap`: no new test can exercise the wired-in `cmdAdd` call
  itself beyond what already exists — `NewK8sClient()` needs a real (or in-cluster) kubeconfig,
  which is exactly why `TestCmdAddPrevResultValid` already stops at the `NODE_NAME` gate rather
  than reaching this far; that precedent doesn't change. The two unit-tested pieces above cover
  the actual new logic in isolation.
- e2e: no new Kind-cluster test. `tests/e2e`'s existing `TestCNITapInterface` continues to
  no-op through the new check (no `CNI_ARGS` → empty `podNamespace`) for the same reason it
  already no-ops through NAD annotation — see its own doc comment. A true conflist-driven
  negative test (real NAD, `galactic-bgp` stanza removed, expect ADD to fail) would need the
  BGPRouter fixture and RBAC that comment already says this e2e suite doesn't set up; treat as
  manual/documented verification only, same call `docs/plans/328-ipam-orphan-reclaim.md` made
  for its own hard-to-automate case — e.g. edit one containerlab tenant NAD (see
  `deploy/containerlab/resources/tenants/ns10/dfw/nad.yaml`) to drop its `galactic-bgp` entry
  and confirm the next attach on that NAD now fails ADD instead of succeeding with no route.

## 7. Rollout

Per [[project_galactic_cni_not_production]], no back-compat constraint applies — this is a
behavior tightening (previously-silent misconfiguration now fails loudly), which is exactly the
outcome the issue asks for, not a regression to guard against. No deployment/manifest changes:
RBAC already grants the master plugins' ServiceAccount `get`/`patch` on
`NetworkAttachmentDefinition` (required for the existing `AnnotateNAD` patch); a `Get` needs
nothing additional.

## 8. Open questions for review

- `VerifyChainComplete` fails ADD on *any* `Get` error, including transient API-server
  hiccups — not just a genuinely missing/incomplete conflist. `AnnotateNAD` already has this
  same fail-closed shape for its own NAD fetch, so this isn't a new class of risk, just a second
  instance of an already-accepted one — but worth confirming that's still the right call now
  that it gates *before* any kernel state is created (previously a transient failure here would
  only affect the NAD annotation, after the interface already existed).
- Presence-only vs. position-aware checking (§4.1): should `VerifyChainIncludes` also confirm
  `galactic-bgp` appears *after* the master's own entry, not just anywhere in the list? Leaning
  toward presence-only for now — cheaper, and matches the issue comment's "cheapest version"
  framing — but flagging in case a hand-edited conflist with `galactic-bgp` misordered (rather
  than removed) turns out to be a real observed failure mode worth catching too.
