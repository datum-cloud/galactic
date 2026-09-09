# Implementation Plan — Per-Node Rendered Config for `fabric-router`

- **Component:** `fabric-router` (`config/fabric-router/`, `containers/fabric-router/`) — the FRR underlay eBGP DaemonSet every other Galactic binary depends on for a converged underlay and a reachable `lo` address.
- **Status:** proposed, not started.
- **Touches:** `containers/fabric-router/Dockerfile`, `config/fabric-router/`, a new `cmd/fabric-init` + `internal/fabricinit`, `deploy/containerlab/resources/fabric-{router,control}/`, `deploy/containerlab/scripts/deploy-fabric.sh`, `README.md`, `CLAUDE.md`, `deploy/containerlab/AGENTS.md`.

## 1. Problem statement

`config/fabric-router/daemonset.yaml` mounts one ConfigMap, `fabric-config`, and its `frr-init` container selects a key from it by node name:

```sh
cp "/tmp/frr-config/frr.conf.${NODE_NAME}" /etc/frr/frr.conf
```

So a single cluster-wide object must contain the full FRR configuration of *every* node the DaemonSet lands on. That does not scale:

1. **One object, N authors.** Every node addition, decommission, or peering change is an edit to the same ConfigMap. Two operators touching two different nodes conflict on one resource; a bad edit for node A is applied to the object node B also reads.
2. **Blast radius.** A malformed or truncated apply takes the underlay config for the whole fleet with it. `fabric-router` is the bottom of the dependency stack (`galactic-router` can't start without the `lo` address FRR brings up), so this is the worst object in the repo to make fleet-global.
3. **Every pod sees every node's config.** Each pod projects the entire fleet's underlay topology — peer addresses, ASNs, locators — and reads one key out of it.
4. **Hard ceilings.** A ConfigMap is capped at ~1 MiB. Real per-node `frr.conf` bodies in the lab are already 30–50 lines with comments; a few hundred nodes runs into both that limit and etcd/apiserver watch cost for an object every fabric pod in the cluster watches.
5. **Generation is awkward.** A Kustomize `configMapGenerator` has to enumerate every node name at build time (`deploy/containerlab/resources/fabric-router/iad/kustomization.yaml` already lists three files by hand), so the manifest tree encodes the cluster's node inventory.
6. **It forced a DaemonSet split in the lab.** `deploy/containerlab/resources/fabric-control/iad/` exists *only* because iad's route-reflector node needs a different `frr.conf` and "a single shared ConfigMap can't serve both" (`deploy/containerlab/AGENTS.md`). That produced a duplicated overlay, two narrowed affinities, and a JSON6902 rename — all of it downstream of this one limitation.

**Goal:** each `fabric-router` pod resolves and renders *its own* config, from its own per-node source object, before FRR starts. No object in the system contains more than one node's configuration.

## 2. Why the trivial fix doesn't work

The obvious change — mount `fabric-config-$(NODE_NAME)` instead of `fabric-config` — is not expressible. A pod spec's `volumes[].configMap.name` is a static string; the downward API can only be projected into env vars, `subPath` (via `subPathExpr`), and file contents, never into the *name* of the object a volume references. A DaemonSet has one pod template, so kubelet will always mount the same ConfigMap on every node.

`subPathExpr` gets close — it can expand `$(NODE_NAME)` into a path *within* a mounted volume — but the volume still has to reference one ConfigMap holding all the keys, which is exactly the object being eliminated.

That leaves two shapes: fetch the right object from the API at pod start, or rewrite the pod's volume reference at admission time. §9 explains why this plan takes the first.

## 3. Design

### 3.1 `fabric-init` — a real init binary

Replace the `sh -c` init command with a small Go binary, `cmd/fabric-init`, built into the `fabric-router` image (logic in `internal/fabricinit` so it is unit-testable; `cmd/` stays a thin `main`, matching every other binary here).

Sequence:

1. Read `NODE_NAME` from the downward API (already wired in the current manifest).
2. Seed `/etc/frr` from the image defaults (`/etc/frr-defaults/*` — `daemons`, `vtysh.conf`), preserving today's behavior. A ConfigMap-supplied `daemons`/`vtysh.conf` still overrides them if present (§3.2).
3. Resolve this node's config (§3.2) and write `/etc/frr/frr.conf`.
4. Validate it (§3.4).
5. Persist a last-known-good copy (§3.5).
6. `install -d -o frr -g frr -m 775 /run/frr /var/log/frr`, `chown frr:frr /etc/frr/frr.conf`, exit 0.

Every step logs a single structured line naming the source it used, so `kubectl logs <pod> -c frr-init` answers "where did this node's config come from" without inspecting the cluster.

### 3.2 Config source: one ConfigMap per node

Primary source: ConfigMap **`fabric-config-<nodename>`** in the pod's own namespace, with keys:

| Key          | Required | Meaning                                                                 |
| ------------ | -------- | ----------------------------------------------------------------------- |
| `frr.conf`   | yes¹     | This node's complete FRR config, verbatim.                              |
| `daemons`    | no       | Overrides the image default baked in by `containers/fabric-router/Dockerfile`. |
| `vtysh.conf` | no       | Same.                                                                    |

¹ Unless the templated mode of §3.3 is in use, which supplies `frr.conf` by rendering instead.

Notes that matter for implementation:

- **Name construction and validation.** `fabric-config-<nodename>` must be a valid DNS-1123 subdomain. Node names already are, and the 14-character prefix leaves 239 characters, so a collision with the limit is theoretical — but `fabric-init` validates and fails with an explicit message rather than emitting a confusing 404 from the API.
- **Kustomize hash suffixes are a trap here.** A `configMapGenerator` appends a content hash to the object name, which breaks a by-name lookup. Every generator producing these must set `generatorOptions: disableNameSuffixHash: true`. This is called out in the docs (§7) and is the single most likely way a deployer gets this wrong.
- **Retry, don't crash-fast.** A 404 for this node's ConfigMap is a genuine misconfiguration and should fail loudly and immediately (with a message naming the exact object the operator needs to create). A transient API error is not: retry with capped exponential backoff for a bounded window (~2 min) before falling back to §3.5 or failing.
- **Namespace** comes from the projected service-account namespace file, not a hardcoded `galactic-system`.

### 3.3 Optional templated mode (Phase 2)

Per-node *files* solve the tenability problem but still mean hand-authoring a full `frr.conf` per node. Phase 2 adds rendering so the per-node object shrinks to values:

- ConfigMap `fabric-template`, key `frr.conf.tmpl` — one cluster-wide Go `text/template`, shared and reviewed once.
- Per-node ConfigMap `fabric-config-<nodename>`, key `values.yaml` — that node's variables only.
- Template context = the values file, plus locally discovered facts `fabric-init` can read without anyone typing them: node name, hostname, the `lo` global-unicast IPv6 address, and fabric-facing link names with their link-local addresses (`internal/plumbing/loaddr` and `vishvananda/netlink` already do this elsewhere in the repo).

Precedence: a `frr.conf` key in the node's ConfigMap always wins (escape hatch for a node that genuinely needs bespoke config); otherwise, if `fabric-template` exists, render it; otherwise fail.

**What makes this actually worth doing** is shrinking the per-node variance. Comparing `deploy/containerlab/resources/fabric-router/{dfw/frr.conf.dfw-worker,iad/frr.conf.iad-worker,sjc/frr.conf.sjc-worker}`, the only real differences are hostname, `lo` address, uplink interface address, peer address, router-id, and the locator prefixes originated. Of those, the peer address and uplink address can disappear entirely with FRR **unnumbered eBGP** (`neighbor <ifname> interface remote-as external` over IPv6 link-local) — leaving a values file of roughly:

```yaml
hostname: iad-fabric
routerID: 10.255.255.1
loopback: fc00:0:4::1/128
uplinks: [eth1]
remoteAS: 65100
originate:
  - 2001:db8:ff03::/48
  - fc00:0:4::/48
```

Whether to adopt unnumbered eBGP is a fabric-design decision independent of this plan and is listed as an open decision (§11), not assumed. Phase 2 is worth building only if the answer is yes; if the fabric keeps numbered peering, per-node verbatim files (Phase 1) are the honest end state and Phase 2 should be dropped rather than half-adopted.

### 3.4 Validate before handing off to FRR

Today a malformed per-node `frr.conf` surfaces as an opaque FRR crashloop. `fabric-init` runs FRR's own config check (`vtysh -C -f /etc/frr/frr.conf`, available in the base image) and, on failure, exits non-zero with the parser output in the log. The init container's failure message then names the problem directly, and the `frr` container never starts against a config that cannot parse.

This does not catch semantically wrong-but-parseable config (wrong peer address, wrong ASN) — nothing at init time can.

### 3.5 Last-known-good cache on the host

`fabric-router` is boot-critical: nothing else on the node converges until its underlay session is up. Add a `hostPath` (`/var/lib/fabric-router/`, `DirectoryOrCreate`) where `fabric-init` writes each successfully validated config. If the API is unreachable past the retry window (§3.2) *and* a cached config for this node exists, use it, log loudly that it is stale, and continue.

This turns "node reboots during an API-server outage" from "underlay never comes back" into "underlay comes back on its last-known-good config." Recommended but separable — it is the one piece of this plan a reviewer could reasonably want split into its own PR.

### 3.6 API dependency: not actually new

`fabric-init` reaching the API server at pod start looks like a new dependency for a boot-critical DaemonSet. It isn't: kubelet already fetches `fabric-config` from the same API server to project the volume, so the pod cannot start today without the same reachability. Moving the fetch from kubelet into the init container changes who makes the call, not whether the node needs the control plane to boot. §3.5 makes the situation strictly better than today.

## 4. RBAC — a new gap to close

`config/fabric-router/` has **no ServiceAccount and no RBAC today** — the pod runs as `default` and needs no API access, because kubelet does all the fetching. This plan requires both:

- `config/fabric-router/serviceaccount.yaml` — ServiceAccount `fabric-router` in `galactic-system`.
- `config/fabric-router/rbac.yaml` — a namespaced `Role` + `RoleBinding` (not a ClusterRole; everything read lives in one namespace) granting `get` on `configmaps`. `list`/`watch` are not needed for Phase 1 and should not be granted — a by-name `get` is the whole access pattern, and withholding `list` means a compromised fabric pod cannot enumerate other nodes' configs, preserving the isolation property this plan is buying.
- Add `serviceAccountName: fabric-router` and `automountServiceAccountToken: true` to the pod spec.

Follow `config/galactic-gateway/rbac.yaml`'s convention of a header comment justifying each rule against the code that needs it.

If Phase 2 (§3.3) reads Node objects for facts instead of taking them from the values file, that adds a ClusterRole with `get` on `nodes` — noted as a reason to prefer local netlink discovery over the Node API where both work.

## 5. Manifest changes (`config/fabric-router/`)

- `daemonset.yaml`:
  - `initContainers[frr-init].command` → `["/usr/local/bin/fabric-init"]` (config via env/flags per `internal/config` convention, e.g. `FABRIC_INIT_*`).
  - Drop the `frr-config-source` volume and its ConfigMap reference entirely. Nothing is projected by kubelet anymore.
  - Add the `frr-cache` hostPath volume (§3.5), mounted only into `frr-init`.
  - `serviceAccountName: fabric-router`.
  - Rewrite the long `volumes:` doc comment that currently explains the `frr.conf.<nodename>` key scheme.
- `kustomization.yaml`: add `serviceaccount.yaml` and `rbac.yaml`.
- `config/fabric-router/` stays out of the root `config/kustomization.yaml`, unchanged — it still has no generic default, since a per-node ConfigMap is still deployer-authored.

**Rollout on config change is still not solved.** With one ConfigMap per node, a checksum annotation in the pod template is impossible by construction (one template, N configs), so the README's existing caveat — a `fabric-config` edit does not trigger a rollout — carries over verbatim to `fabric-config-<nodename>`. §10 Phase 3 is where that gets fixed properly.

## 6. Image and build changes

- `containers/fabric-router/Dockerfile` becomes multi-stage: a `golang` builder stage compiling `./cmd/fabric-init`, then the existing `quay.io/frrouting/frr` stage with the binary copied to `/usr/local/bin/fabric-init`. Keep the existing `apk` debugging tools and the `/etc/frr-defaults/` copy.
  - Match the ldflags/`internal/metadata` stamping the other `containers/*/Dockerfile`s use, so `fabric-init --version` reports the same build metadata as every other binary.
  - The build context is already the repo root (`containers/fabric-router/daemons` is referenced by full path), so no CI context change is needed.
- `Taskfile.yaml` → `build:binaries`: add `go build ... -o bin/fabric-init ./cmd/fabric-init`.
- `.github/workflows/publish.yaml` needs no change — `publish-fabric-router-image` already builds this Dockerfile and stamps the tag into `config/fabric-router`.

## 7. Documentation

- **`README.md`** "Production Deployment": rewrite the `config/fabric-router/`: per-node `frr.conf` bullet. New instruction is one ConfigMap per node named `fabric-config-<nodename>` with an `frr.conf` key, plus the `disableNameSuffixHash: true` warning for generated ones, plus the unchanged no-auto-rollout caveat.
- **`CLAUDE.md`**: the `config/fabric-router/` deployment bullet currently describes the `NODE_NAME`-selects-a-key mechanism in detail; update it to the per-node object model.
- **`deploy/containerlab/AGENTS.md`**: update the shared-manifests paragraph, which explains the `fabric-control` split as a consequence of the shared-ConfigMap limitation (§8 removes that split).
- **New `docs/fabric/configuration.md`**, alongside `docs/router/configuration.md` and `docs/cni/configuration.md`: the ConfigMap contract, `fabric-init`'s env vars, resolution precedence, the validation step, and the cache semantics. Neither `docs/fabric/` nor any `fabric-router` doc exists today, which is itself a gap worth closing while touching this.

## 8. Lab migration (`deploy/containerlab/`) — a net simplification

Per-node objects remove the reason the lab has two fabric overlays:

- **Delete `deploy/containerlab/resources/fabric-control/` entirely.** It exists only to give `iad-worker-rr` a different `frr.conf`. Its `frr.conf` becomes `resources/fabric-router/iad/frr.conf.iad-worker-rr` under its own ConfigMap, and the node — already labeled `galactic.datumapis.com/fabric: router` like every other lab worker — is picked up by the single DaemonSet. This also removes the JSON6902 rename patch and the second `fabric-lab-patch.yaml`.
- **Drop the affinity narrowing in `resources/fabric-router/base/fabric-lab-patch.yaml`.** It only exists to keep the two overlays from double-scheduling. What remains in that patch is what it should have been all along: `image: fabric-router:latest` + `imagePullPolicy: Never`.
- **Per-site kustomizations** become one `configMapGenerator` entry per node instead of one file list:

  ```yaml
  generatorOptions:
    disableNameSuffixHash: true
  configMapGenerator:
    - name: fabric-config-iad-worker
      files: [frr.conf=frr.conf.iad-worker]
    - name: fabric-config-iad-worker-rr
      files: [frr.conf=frr.conf.iad-worker-rr]
    - name: fabric-config-iad-gateway1
      files: [frr.conf=frr.conf.iad-gateway1]
    - name: fabric-config-iad-gateway2
      files: [frr.conf=frr.conf.iad-gateway2]
  ```

  The `frr.conf.<node>` filenames can stay as-is on disk — the node name now lives in the object name, and the key is always `frr.conf`.
- **`deploy/containerlab/scripts/deploy-fabric.sh`** loses `copy_fabric_control_config`, the second `copy_to`/`apply_k` pair for iad, and the paragraph of comments explaining the split. iad's fabric deploy collapses to the same shape as dfw's and sjc's.

Verification in the lab is the real functional test for this change (§9).

## 9. Alternatives considered

| Alternative | Why not |
| ----------- | -------- |
| **Mutating admission webhook** rewriting `volumes[frr-config-source].configMap.name` to `fabric-config-<spec.nodeName>` at pod admission. Workable — the DaemonSet controller sets `spec.nodeName` before admission — and needs no API access from the pod. | Puts a cluster-wide admission dependency (plus cert rotation) in front of the *most* boot-critical DaemonSet in the cluster. A webhook outage or an expired cert blocks underlay bring-up fleet-wide, which is a strictly worse failure mode than the one being fixed. `internal/webhook` exists, so this is cheap to build — that is not the same as safe to depend on. |
| **One DaemonSet per node**, pinned by `kubernetes.io/hostname`, like `config/galactic-gateway/base/` is instantiated today. | N DaemonSets and N overlays per cluster. Trades one unmanageable object for N manageable ones and makes any fleet-wide spec change an N-way edit. |
| **Per-node Secret** instead of ConfigMap. | Underlay BGP config is topology, not credentials — no secret material is in it today. If BGP MD5/TCP-AO passwords are ever adopted, revisit; the resolution logic is identical. |
| **A `FabricRouter` CRD** rendered by a controller. | The right long-term shape if the underlay ever becomes cluster-managed rather than site-authored, but it is a much larger change (API types, a reconciler, a new controller binary) for a problem that a per-node object solves. §3.3's template mode captures most of the ergonomic benefit without an API surface. Revisit if Phase 2 lands and per-node values still feel like too much hand-authoring. |
| **`subPathExpr` with `$(NODE_NAME)`.** | Expands only within an already-mounted volume; the volume must still reference one ConfigMap holding every node's key. Doesn't address the problem. |

## 10. Phasing

**Phase 1 — per-node ConfigMaps (the ask).** `cmd/fabric-init` + `internal/fabricinit` with by-name resolution, image/Taskfile changes, ServiceAccount + Role/RoleBinding, `daemonset.yaml` rewrite, validation (§3.4), lab migration (§8), docs (§7). Self-contained and independently shippable.

**Phase 1.5 — last-known-good cache (§3.5).** Small, separable, reviewable on its own.

**Phase 2 — templated rendering (§3.3).** Only if the unnumbered-eBGP decision (§11) goes the way that makes it worthwhile.

**Phase 3 — reload without a pod bounce.** Watch this node's own ConfigMap and run `frr-reload.py` on change, closing the "a ConfigMap edit doesn't trigger a rollout" gap the README documents today. Needs `watch` on the one ConfigMap (widening §4's RBAC to `get`/`list`/`watch` with `resourceNames` scoped to this node's object) and a decision about whether the watcher is a sidecar or a mode of `fabric-init`. Explicitly out of scope for Phase 1 — the ask is init-time rendering.

## 11. Open decisions

1. **Unnumbered eBGP for the fabric?** Gates whether Phase 2 is worth building (§3.3). This is a fabric-design question that outlives this plan and should be answered by whoever owns underlay peering, not decided here.
2. **Migration for existing clusters.** Should `fabric-init` accept the legacy layout (`fabric-config` with an `frr.conf.<nodename>` key) as a deprecated fallback for one release, or is this a clean cut with a documented one-time conversion? A clean cut is mechanically trivial — splitting one ConfigMap into N is a short script — but it is a coordinated change with whoever operates real `fabric-router` deployments. Recommend clean cut *if* the lab is the only current consumer; confirm before building the fallback path, since a fallback path is dead code the day after migration.
3. **Cache location.** `/var/lib/fabric-router/` assumed for §3.5; confirm it matches whatever host-path convention the fleet's node images expect.
4. **Failure policy when the node's ConfigMap is absent.** This plan fails the init container loudly. The alternative — start FRR with an empty config so the pod is "up" — is worse (a silently non-peering underlay node looks healthy), but it is worth confirming nothing downstream depends on the pod reaching `Ready` regardless of config.

## 12. Testing

- **Unit (`internal/fabricinit`, table-driven per `docs/agents/CONVENTIONS.md`):** name construction and DNS-1123 validation including the over-length case; resolution precedence (verbatim `frr.conf` beats template; missing both fails); 404 vs. transient-error handling; cache write on success, cache read only on exhausted retries; optional-key override behavior for `daemons`/`vtysh.conf`; template rendering against fixture values (Phase 2). A fake client (`sigs.k8s.io/controller-runtime/pkg/client/fake`) covers the API side; the `vtysh -C` call goes behind an interface so validation is testable without FRR.
- **Lab (`deploy/containerlab`)** is the functional test and the acceptance gate: bring up all three clusters, confirm every fabric pod's `frr-init` logs name its own ConfigMap, `vtysh -c "show bgp summary"` on each of iad's four fabric pods shows the expected sessions (in particular `iad-worker-rr`, which now comes from the single DaemonSet rather than `fabric-control`), and `galactic-router`/`galactic-gateway` converge as before. Also verify the negative path: delete one node's ConfigMap, bounce that pod, confirm the init container fails with a message naming the missing object rather than a downstream FRR crashloop.
- **`task ci`** before PR, as always. Note that `task test:e2e`'s Kind lifecycle test does not cover `fabric-router` at all today — this plan does not change that, and the lab remains the only place this is exercised end to end.

## 13. Non-goals

- Managing the *content* of any node's underlay config. This plan changes where config comes from, not who decides what a node peers with.
- Auto-discovering fabric topology (peers, ASNs, locators) from anything other than what a deployer supplies or what is directly readable off the node's own links.
- A `fabric-router-rr` (underlay route-reflector) role — still future, per `docs/node-labels.md`.
- Reload-without-restart (Phase 3 above).
