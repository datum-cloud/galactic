# Deploy fabric-api

Install the opt-in looking glass in a cell. After installation, follow [verification and rollout](operations.md). Flags are in [configuration](configuration.md), and certificates in [security](security.md).

## What you deploy

fabric-api has four runtime parts, all from one image,
`ghcr.io/datum-cloud/fabric-api`:

| Part    | Kind                                         | Where                      | What it does                                                                                                          |
| ------- | -------------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| node    | Sidecar in the `fabric-router` DaemonSet pod | Every `fabric-router` node | Reads FRR over its vty sockets and sends ICMP probes; answers mTLS gRPC on the node's own address                     |
| gateway | Deployment, 2 replicas, leader-elected       | One per cell               | Executes `FabricQuery` objects by fanning out to the node sidecars; serves the operator debug service                 |
| certs   | DaemonSet `fabric-api-certs`                 | Every `fabric-router` node | Obtains the node's certificate from a csi-driver volume and copies it to the node for the sidecar; needs no API token |
| janitor | CronJob                                      | One per cell               | Deletes expired `FabricQuery` copies the federation failed to delete                                                  |

Everything is opt-in. `kubectl apply -k config/` does not deploy any of it, and
the base `fabric-router` DaemonSet is unchanged unless you include the
Component.

## Prerequisites

None of these are created by this repository's manifests.

1. **cert-manager and its csi-driver**, running on every node that runs
   `fabric-router` (tolerating the nodes' taints), because the `fabric-api-certs`
   pods mount a csi volume. The csi-driver needs no special setting.
2. **An `Issuer` named `fabric-api`** in `galactic-system`, backed by a dedicated
   per-cell fabric-api CA. Not a general cluster CA: trust is per cell. Infra owns
   it in production; the lab's stand-in is
   `deploy/containerlab/resources/fabric-api/pki/pki.yaml`.
3. **The `FabricQuery` CRD** (`fabricqueries.galactic.datumapis.com`). Infra owns
   its lifecycle in every cell. `config/fabric-api/crd/` is a copy for the lab and
   tests only; do not apply it where infra manages the CRD.
4. **A per-cell `fabric-api` ConfigMap** in `galactic-system` (see
   [Per-cell ConfigMap](#step-2-per-cell-configmap)).
5. **A federation path that delivers `FabricQuery` objects** to the cell, pinned
   to its member cluster. That is NSO and Karmada's work and is out of scope here.

### Why certificates are issued in a separate pod

A `csi.cert-manager.io` volume blocks its pod until the certificate is issued.
The driver's `continueOnNotReady` setting does not change that: it covers only the
driver's own readiness gates. With a broken Issuer a lab test showed
`MountVolume.SetUp` waiting ("Referenced issuer does not have Ready condition")
and a `fabric-router` pod stuck in `PodInitializing` with FRR down. So the
sidecar's certificate does not come from a volume in the `fabric-router` pod:

- The Component adds a DaemonSet, `fabric-api-certs`, with the same placement as
  `fabric-router` and no API token. It runs `fabric-api certsync`, which copies
  `tls.crt`, `tls.key` and `ca.crt` from its csi volume (`fabric-api-csi`) to the
  node's tmpfs directory `/run/fabric-api/tls` every 10 seconds. It validates the
  key pair first and replaces each file atomically.
- The `fabric-router` pod mounts `/run/fabric-api/tls` read-only as a hostPath of
  type `DirectoryOrCreate`, which never blocks the pod.
- A broken Issuer therefore stalls only the `fabric-api-certs` pod (it waits in
  `ContainerCreating`). The sidecar reports no credentials and fails closed;
  routing is unaffected. When the Issuer is repaired the sidecar picks the
  certificate up without a restart.

`task verify:fabric-api-bootstrap` in `deploy/containerlab/` is the lab's check of
this property.

## Deployment

### Step 1: cell-wide RBAC and ServiceAccounts

```sh
kubectl apply -k config/fabric-api/
```

This applies only `serviceaccount.yaml` and `rbac.yaml`: the `fabric-api-gateway`
and `fabric-api-janitor` ServiceAccounts, and their roles. It is safe and
idempotent in any cell.

| Identity             | Scope             | Permissions                                                                                                  |
| -------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------ |
| `fabric-api-gateway` | Cluster           | `fabricqueries`: get, list, watch. `fabricqueries/status`: get, update, patch. `nodes`: get (node selectors) |
| `fabric-api-gateway` | `galactic-system` | `pods`: get, list, watch. `leases`: get, list, watch, create, update, patch. `events`: create, patch         |
| `fabric-api-janitor` | Cluster           | `fabricqueries`: list, delete                                                                                |

The gateway cannot edit a spec, create or delete a query, or touch FRR's
ConfigMaps. Delete access is deliberately a separate identity.

### Step 2: per-cell ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: fabric-api
  namespace: galactic-system
data:
  site: dfw
  cell: dfw
  cluster-name: dfw
```

| Key            | Used by       | Meaning                                                                                                       |
| -------------- | ------------- | ------------------------------------------------------------------------------------------------------------- |
| `site`         | node, gateway | The location this cell serves. The gateway executes only `FabricQuery` objects whose `spec.site` equals it    |
| `cell`         | node, gateway | The cell name in every mTLS identity. Must equal the `CELL_NAME` in the certificates' URI SANs                |
| `cluster-name` | gateway       | This cell's Karmada member cluster name. The gateway executes only objects whose `spec.clusterName` equals it |

The gateway's Deployment references all three keys as required, so it will not
start without the ConfigMap. The node sidecar references `site` and `cell` as
optional: without `cell` it stays up, logs an error, serves only metrics and
reports diagnostics unavailable, so a missing ConfigMap never crash-loops a
container in the `fabric-router` pod. Container environment is fixed at start, so
creating the ConfigMap after the Component is rolled out means recreating the
pods, which restarts FRR. Create it first.

### Step 3: the gateway and janitor

`config/fabric-api/base/` holds the gateway Deployment, its ClusterIP Service, a
PodDisruptionBudget (`minAvailable: 1`) and the janitor CronJob. It is not applied
by anything by default because it needs per-cell values: the ConfigMap above and
the cell name in the gateway certificate's URI SAN. Instantiate it from a per-cell
overlay (compare `deploy/containerlab/resources/fabric-api/gateway/dfw/`):

```yaml
# overlays/<cell>/gateway/kustomization.yaml
namespace: galactic-system
resources:
  - ../../../config/fabric-api/base
configMapGenerator:
  - name: fabric-api
    literals:
      - site=dfw
      - cell=dfw
      - cluster-name=dfw
generatorOptions:
  disableNameSuffixHash: true
patches:
  - target:
      kind: Deployment
      name: fabric-api-gateway
    patch: |-
      - op: replace
        path: /spec/template/spec/volumes/0/csi/volumeAttributes/csi.cert-manager.io~1uri-sans
        value: spiffe://fabric-api.datumapis.com/cell/dfw/gateway
```

Adjust the relative path to `config/fabric-api/base`. `disableNameSuffixHash`
matters: the pods reference the ConfigMap by the fixed name `fabric-api`.

The base pins `ghcr.io/datum-cloud/fabric-api` at a tag the release pipeline
stamps. Override it from an overlay's `images:` stanza. The gateway runs as UID
65532 with a read-only root filesystem and no capabilities, requests 20m CPU and
64Mi memory, and limits memory to 512Mi.

### Step 4: the node sidecar Component, as a canary

Add the Component to an overlay of `config/fabric-router` and replace
`CELL_NAME` in the URI SAN of the `fabric-api-certs` DaemonSet's csi volume:

```yaml
# overlays/<cell>/fabric-router/kustomization.yaml
resources:
  - ../../../config/fabric-router
components:
  - ../../../config/fabric-router/components/fabric-api
patches:
  - path: fabric-api-cell-patch.yaml
```

```yaml
# overlays/<cell>/fabric-router/fabric-api-cell-patch.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fabric-api-certs
spec:
  template:
    spec:
      volumes:
        - name: fabric-api-csi
          csi:
            driver: csi.cert-manager.io
            volumeAttributes:
              csi.cert-manager.io/uri-sans: spiffe://fabric-api.datumapis.com/cell/dfw/ns/${POD_NAMESPACE}/pod/${POD_NAME}
```

`fabric-router` still needs its own per-node `fabric-router.<nodename>`
ConfigMaps as usual (see `AGENTS.md`). The Component does not create the cell
ConfigMap, the Issuer or the CRD. Applying it adds the `fabric-api-certs` DaemonSet and recreates every `fabric-router` pod
and restarts FRR; follow [Rollout](operations.md#rollout).

What the Component changes in the pod:

- Adds the `fabric-api` container (`args: [node]`) with ports `fabric-api`/9344
  and `api-metrics`/9345, 10m CPU and 64Mi memory requested, a 768Mi memory limit
  and `GOMEMLIMIT=640MiB` (the search index holds a copy of bgpd's selected routes;
  see [Search index](configuration.md#search-index)).
  It has no readiness, liveness or startup probe, on purpose.
- Mounts FRR's `/run/frr` read-only and the node's `/run/fabric-api/tls` (a
  hostPath, filled by `fabric-api-certs`) at `/var/run/fabric-api/tls` read-only.
- Runs the container as UID 0, GID 102 (`frrvty`), dropping every capability and
  adding only `NET_RAW`, with a read-only root filesystem and no privilege
  escalation. Raw ICMP sockets need `NET_RAW` in the effective set, which a
  non-root container cannot get; without `CAP_DAC_OVERRIDE` it reaches FRR's
  `0770 frr:frrvty` sockets through group 102.
- Sets `automountServiceAccountToken: false` on the pod and adds a projected
  token volume mounted only into `frr-init` and `config-agent`, the containers
  that call the Kubernetes API. The sidecar has no API access unless the
  opt-in `components/fabric-api-permits` Component adds `--probe-permits` and
  mounts the token into it (see
  [Enabling aggregate probe budgets](operations.md#enabling-aggregate-probe-budgets)).

The `fabric-api-certs` DaemonSet runs the same image with `args: [certsync, ...]`,
tolerates every taint, avoids control-plane nodes and requires the same
`galactic.datumapis.com/fabric` label values as `fabric-router`. It runs as root
(to write the root-owned node directory) with every capability dropped, a
read-only root filesystem, 5m CPU and 16Mi memory requested and a 64Mi limit.

### Lab

In `deploy/containerlab/`: `task build:fabric-api` builds the image,
`task deploy:cert-manager` installs cert-manager and the csi-driver in every
cluster (the csi-driver must run on every fabric node before `deploy:fabric`), and `task deploy:fabric-api` installs the CRD copy, RBAC, a stand-in PKI,
the gateway and the janitor. `task deploy` does all of them in the right order
(`deploy:cert-manager` before `deploy:fabric`, `deploy:fabric-api` last). In the
lab each site is one cell whose cell, site and member cluster name are all the site
name. Each site's fabric-router overlay creates that site's `fabric-api`
ConfigMap, so it lands with the node sidecars in `deploy:fabric`, ahead of their
start. `task verify:fabric-api` (which first runs
`task verify:fabric-api-config`, a check that the overlays render it) and
`task verify:fabric-api-bootstrap` are the checks.
