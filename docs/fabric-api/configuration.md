# fabric-api Deployment & Configuration

This is a how-to and reference guide for deploying and configuring
`fabric-api`, the looking glass over `fabric-router`'s FRR state. For the
design rationale (why a sidecar, why pod identities, why the budgets are what
they are) see
[docs/agents/ARCHITECTURE-FABRIC-API.md](../agents/ARCHITECTURE-FABRIC-API.md);
this document covers the "how". The `FabricQuery` contract is in
[api.md](api.md).

> Last verified: 2026-10-07 against the `feat/fabric-api` working tree:
> `cmd/fabric-api/`, `internal/fabric/`, `config/fabric-api/`,
> `config/fabric-router/components/fabric-api/`, `config/monitoring/`, and the
> lab in `deploy/containerlab/` (`deploy:cert-manager`, `deploy:fabric-api`,
> `verify:fabric-api`, `verify:fabric-api-bootstrap`).

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
3. **The `FabricQuery` CRD** (`fabricqueries.network.datumapis.com`). Infra owns
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
and restarts FRR; follow [Rollout](#rollout).

What the Component changes in the pod:

- Adds the `fabric-api` container (`args: [node]`) with ports `fabric-api`/9344
  and `api-metrics`/9345, 10m CPU and 64Mi memory requested, a 768Mi memory limit
  and `GOMEMLIMIT=640MiB` (the search index holds a copy of bgpd's selected routes;
  see [Search index](#search-index)).
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
  that call the Kubernetes API. The sidecar has no API access.

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
name. `task verify:fabric-api` and `task verify:fabric-api-bootstrap` are the
checks.

## Ports

| Port | Component | Bound to                                     | Protocol                    | Name in the pod spec |
| ---- | --------- | -------------------------------------------- | --------------------------- | -------------------- |
| 9344 | node      | The pod's `hostIP` only                      | mTLS gRPC                   | `fabric-api`         |
| 9345 | node      | `<hostIP>:9345`, or `--metrics-bind-address` | HTTP `/metrics`             | `api-metrics`        |
| 9346 | gateway   | All addresses, or `--debug-bind-address`     | mTLS gRPC                   | `debug`              |
| 9347 | gateway   | `:9347` (all addresses)                      | HTTP `/metrics`             | `metrics`            |
| 9348 | node      | `127.0.0.1` only                             | BMP (bgpd's Loc-RIB stream) | none (loopback)      |
| 8081 | gateway   | `:8081` (all addresses)                      | HTTP `/healthz`, `/readyz`  | `health`             |

`fabric-router` pods use the host network, so 9344 and 9345 are on the node's own
address. The listener is bound to `hostIP` rather than every interface because
edge nodes carry public uplinks. Reachability does not bypass mTLS, but do not
rely on the bind address alone: where your CNI or host firewall can restrict who
reaches 9344 and 9345 (gateway pods to 9344, your scraper to 9345), do so.
`9342` and `9343` on the same pods belong to `frr-exporter` and the config agent.
The debug Service is `ClusterIP` only; a port-forward to it is a transport choice
and does not bypass the gateway's identity checks.

## Identities and certificates

Every certificate carries exactly one URI SAN in the trust domain
`fabric-api.datumapis.com`:

| Identity | URI SAN                                                                  | Issued to                              | Key usages                |
| -------- | ------------------------------------------------------------------------ | -------------------------------------- | ------------------------- |
| gateway  | `spiffe://fabric-api.datumapis.com/cell/<cell>/gateway`                  | The gateway Deployment (both replicas) | `client auth,server auth` |
| node     | `spiffe://fabric-api.datumapis.com/cell/<cell>/ns/<namespace>/pod/<pod>` | Each node's `fabric-api-certs` pod     | `server auth`             |
| operator | `spiffe://fabric-api.datumapis.com/cell/<cell>/operator/<name>`          | A person or tool calling directly      | `client auth`             |

The node identity names a **pod**, not the node: the csi-driver can template a
pod's name and namespace (`${POD_NAME}`, `${POD_NAMESPACE}`) but not its node's
name. That pod is the node's `fabric-api-certs` pod, not the `fabric-router` pod
the sidecar runs in. The gateway maps each node to its newest Running
`fabric-api-certs` pod (selected by `--certs-selector`, default
`app.kubernetes.io/name=fabric-api-certs`), records it in
`status.nodes[].certificatePod`, and dials accepting only the identities of
that node's certs pods: the newest one, and any it is replacing, since a sidecar
keeps presenting a replaced pod's certificate until the new one reaches it. A
node with no running certs pod is omitted with reason `NoCertificatePod`. The
sidecar does not know that pod's name, so it accepts any node identity in its own
cell and namespace as its own; the gateway's pinning is what ties a certificate to
a node. Each path segment must be a lower-case DNS-label-like string (`[a-z0-9]`,
with `.` and `-` inside).

How an identity is checked:

- TLS 1.3 minimum, mutual. The server requires a client certificate and the
  client accepts only a server proving the identity it expected.
- The chain is verified against the trust bundle current at handshake time, with
  the right key usage, and the identity's **cell must equal this process's own
  cell**.
- A process refuses to load a certificate whose identity is not its own (for
  the sidecar: any node identity in its cell and namespace), is not valid now, or does not chain to the bundle it shipped with.
- At the handshake a node accepts only gateway and operator identities. Per RPC, a
  gateway or operator may call the node's `Execute` and `Info`; on the gateway's
  debug service an operator may call `Query` and `ListNodes`, and the gateway
  identity may call only `Query` (the form in which a follower forwards to the
  leader). Anything else is `Unauthorized`.

The csi volume attributes in the `fabric-api-certs` DaemonSet (volume
`fabric-api-csi`) and the gateway Deployment:

| Attribute                          | `fabric-api-certs`                                       | Gateway                      |
| ---------------------------------- | -------------------------------------------------------- | ---------------------------- |
| `csi.cert-manager.io/issuer-name`  | `fabric-api`                                             | `fabric-api`                 |
| `csi.cert-manager.io/issuer-kind`  | `Issuer`                                                 | `Issuer`                     |
| `csi.cert-manager.io/uri-sans`     | `.../cell/CELL_NAME/ns/${POD_NAMESPACE}/pod/${POD_NAME}` | `.../cell/CELL_NAME/gateway` |
| `csi.cert-manager.io/key-usages`   | `server auth`                                            | `client auth,server auth`    |
| `csi.cert-manager.io/duration`     | `24h`                                                    | `24h`                        |
| `csi.cert-manager.io/renew-before` | `8h`                                                     | `8h`                         |
| `csi.cert-manager.io/fs-group`     | not set                                                  | `65532`                      |

`CELL_NAME` is a literal placeholder in both manifests that your overlay must
replace with the cell name (the same value as the ConfigMap's `cell` key). The
csi-driver cannot take it from a ConfigMap. A mismatch is not subtle: the process
rejects its own certificate (`certificate identity ... is not ...`), reports
credentials not loaded and fails closed. The files are `tls.crt`, `tls.key` and
`ca.crt`, read from `/var/run/fabric-api/tls` (`--tls-cert`, `--tls-key`,
`--tls-ca`). For the gateway that is its own csi volume; for the sidecar it is the
hostPath that `certsync` fills.

### Operator certificates

An operator certificate is a normal cert-manager `Certificate` from the same
`fabric-api` Issuer, for example the lab's:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: fabric-api-operator
  namespace: galactic-system
spec:
  secretName: fabric-api-operator
  duration: 24h
  renewBefore: 8h
  uris:
    - spiffe://fabric-api.datumapis.com/cell/dfw/operator/alice
  usages:
    - digital signature
    - client auth
  privateKey:
    algorithm: ECDSA
    size: 256
  issuerRef:
    name: fabric-api
    kind: Issuer
```

An operator certificate can reach any node and the gateway in its cell, so treat
who may request one as an access decision.

### Rotation

Certificates last 24h and renew 8h before expiry. The csi-driver renews in place; for
the sidecar, `certsync` copies the new files to the node within 10 seconds. The
sidecar polls its files every 10 seconds, the gateway every 30, and each swaps in a new certificate, key and bundle without a
restart, and without touching FRR. A new set is accepted only if the certificate
matches the process's identity, is valid now and chains to the bundle delivered
with it. If it does not, the previous credentials stay in use until they expire.
With none loaded, every handshake fails closed, the process keeps running and
retrying, and routing is unaffected.

| Situation                          | Behaviour                                                      | Signal                                                                     |
| ---------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Files missing or unreadable        | Handshakes fail; warning logged every 30s                      | `fabric_api_credentials_loaded` 0; `FabricAPICredentialsMissing` after 15m |
| Renewal produces a bad certificate | The previous one keeps serving until its `notAfter`, then none | `fabric_api_certificate_expiry_timestamp_seconds` stops advancing          |
| Certificate expires                | Credentials cleared; handshakes fail closed                    | `FabricAPICertificateRenewalFailing` fires earlier, at under 4h left       |
| Wrong cell, pod or role in the SAN | Certificate rejected at load                                   | Warning in the log; credentials not loaded                                 |

**Rotating the CA.** A peer verifies the other side against its own current
bundle, so a leaf from a new CA is unusable by any peer that has not yet loaded a
bundle trusting that CA. Rotate with overlap, using a bundle that holds both
certificates (the loader accepts a multi-certificate `ca.crt`):

1. Make every pod's `ca.crt` trust both the old and the new CA.
2. Wait until every node sidecar and the gateway have reloaded it (within 30
   seconds of the volume updating), confirmed by `fabric_api_credentials_loaded` 1 and
   a fresh `fabric_api_certificate_expiry_timestamp_seconds` per pod.
3. Switch issuance to the new CA. Leaves renew within 24 hours and chain to it.
4. After every leaf from the old CA has been replaced (allow more than the 24h
   duration), remove the old CA from the bundle.

How step 1 is achieved depends on the issuer integration (infra owns it) and is
not exercised by this repository's lab; the code path that tolerates the overlap
is covered by `TestRotationWithOverlappingBundle`.

## Command-line reference

Every flag below is on the `fabric-api` binary; where an environment variable is
listed, it supplies the flag's default and an explicit flag wins. Durations use Go
syntax (`10m`).

### Global (all subcommands)

| Flag              | Env          | Default | Meaning                                      |
| ----------------- | ------------ | ------- | -------------------------------------------- |
| `--log-level`     | `LOG_LEVEL`  | `info`  | `debug`, `info`, `warn` or `error`           |
| `--log-format`    | `LOG_FORMAT` | `json`  | `json` or `text`                             |
| `--version`, `-V` |              |         | Print the version and exit (root only)       |
| `--build-info`    |              |         | Print build information and exit (root only) |

Tracing is enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set; the standard OpenTelemetry exporter
variables then apply. Trace-context propagation is always on.

### `fabric-api node`

| Flag                           | Env                      | Default                           | Meaning                                                                                                                                                         |
| ------------------------------ | ------------------------ | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--node-name`                  | `NODE_NAME`              |                                   | This node's name. Required; requests naming another node are refused (`WrongNode`)                                                                              |
| `--site`                       | `SITE`                   |                                   | Site this node serves; reported by `Info`                                                                                                                       |
| `--cell`                       | `CELL`                   |                                   | Cell name in the mTLS identities. If empty the process idles and serves only metrics                                                                            |
| `--namespace`                  | `POD_NAMESPACE`          |                                   | This pod's namespace. Required                                                                                                                                  |
| `--pod-name`                   | `POD_NAME`               |                                   | This pod's name. Required                                                                                                                                       |
| `--host-ip`                    | `HOST_IP`                |                                   | Address the gRPC service binds to: the pod's `hostIP`. Required                                                                                                 |
| `--port`                       |                          | `9344`                            | gRPC port                                                                                                                                                       |
| `--metrics-bind-address`       | `METRICS_BIND_ADDRESS`   | `<host-ip>:9345`                  | Address serving `/metrics`                                                                                                                                      |
| `--frr-socket-dir`             |                          | `/run/frr`                        | Directory holding `bgpd.vty` and `zebra.vty`                                                                                                                    |
| `--tls-cert`                   | `FABRIC_API_TLS_CERT`    | `/var/run/fabric-api/tls/tls.crt` | Certificate file                                                                                                                                                |
| `--tls-key`                    | `FABRIC_API_TLS_KEY`     | `/var/run/fabric-api/tls/tls.key` | Private key file                                                                                                                                                |
| `--tls-ca`                     | `FABRIC_API_TLS_CA`      | `/var/run/fabric-api/tls/ca.crt`  | Trust bundle file                                                                                                                                               |
| `--probe-source-ipv4`          | `PROBE_SOURCE_IPV4`      |                                   | Explicit IPv4 probe source                                                                                                                                      |
| `--probe-source-ipv6`          | `PROBE_SOURCE_IPV6`      |                                   | Explicit IPv6 probe source                                                                                                                                      |
| `--probe-source-interface`     | `PROBE_SOURCE_INTERFACE` | `lo`                              | Interface whose single global address per family is the source for a family with no explicit one; empty disables                                                |
| `--deny-prefixes`              |                          |                                   | Comma-separated platform or management CIDRs no probe may target                                                                                                |
| `--operator-allow-prefixes`    |                          |                                   | Comma-separated CIDRs only operator identities may probe. Lab only; never set in production                                                                     |
| `--enable-expensive-queries`   |                          | `false`                           | Enable `ASPath`, `Community` and `LargeCommunity` searches. See [Query types](#query-types)                                                                     |
| `--max-concurrent`             |                          | `4`                               | `Execute` calls running at once; further calls wait within their deadline                                                                                       |
| `--max-expensive`              |                          | `1`                               | Expensive searches running at once; no queue (`NodeBusy`)                                                                                                       |
| `--max-probes`                 |                          | `2`                               | Probes running at once; no queue (`NodeBusy`)                                                                                                                   |
| `--probe-packet-rate`          |                          | `20`                              | Probe packets per second across all probes on the node (burst 5, not configurable)                                                                              |
| `--expensive-breaker-cooldown` |                          | `10m`                             | How long expensive searches stay suspended after one times out (`--search-source=frr` only)                                                                     |
| `--search-source`              |                          | `index`                           | What answers AS-path and community searches: `index` (a local copy of bgpd's Loc-RIB fed over BMP) or `frr` (FRR's own scans, which starve bgpd on full tables) |
| `--bmp-station-address`        |                          | `127.0.0.1:9348`                  | Loopback address the BMP station listens on, with `--search-source=index`                                                                                       |
| `--search-index-max-routes`    |                          | `4000000`                         | Prefixes the index holds at most; announcements for new prefixes beyond it are dropped and counted                                                              |

Not configurable by flag: the 4 MiB FRR read cap, the 2 second socket dial
timeout, the duplicate-suppression cache (1024 entries or 32 MiB), the 60 second
FRR identity refresh and the credential polls (10 seconds in the sidecar, 30 in
the gateway). The sidecar's ASN and router ID come from `show bgp summary json`,
refreshed every 60 seconds. While FRR is unreachable, as during its own startup,
the sidecar re-reads it every 5 seconds, and a request finding the last read
unreachable re-reads FRR itself (at most once a second) rather than failing on
the stale result.

To change a flag in production, patch the `fabric-api` container's `args` in your
overlay (keep `node` first). Any such change is a pod template change and restarts
FRR, so it follows [Rollout](#rollout).

### `fabric-api gateway`

| Flag                                  | Env                                  | Default                                                | Meaning                                                                                                                                                                   |
| ------------------------------------- | ------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--site`                              | `SITE`                               |                                                        | Site this cell serves. Required                                                                                                                                           |
| `--cluster-name`                      | `CLUSTER_NAME`                       |                                                        | This cell's Karmada member cluster name. Required                                                                                                                         |
| `--cell`                              | `CELL`                               |                                                        | Cell name in the mTLS identities. Required                                                                                                                                |
| `--namespace`                         | `POD_NAMESPACE`                      | `galactic-system`                                      | Namespace of the `fabric-router` pods, the election lease and this pod                                                                                                    |
| `--pod-name`                          | `POD_NAME`                           |                                                        | This pod's name. Required                                                                                                                                                 |
| `--debug-bind-address`                |                                      |                                                        | Address the debug service binds to. Empty binds every address in the pod's network namespace, which a port-forward (through the pod's loopback) and the Service both need |
| `--pod-selector`                      |                                      | `app.kubernetes.io/name=fabric-router`                 | Label selector of `fabric-router` pods                                                                                                                                    |
| `--certs-selector`                    |                                      | `app.kubernetes.io/name=fabric-api-certs`              | Label selector of the per-node `fabric-api-certs` pods whose identity each sidecar presents                                                                               |
| `--lease-name`                        |                                      | `fabric-api-gateway`                                   | Leader election lease name                                                                                                                                                |
| `--debug-port`                        |                                      | `9346`                                                 | Operator debug gRPC port                                                                                                                                                  |
| `--metrics-bind-address`              |                                      | `:9347`                                                | Address serving `/metrics`                                                                                                                                                |
| `--health-probe-bind-address`         |                                      | `:8081`                                                | Address serving `/healthz` and `/readyz`                                                                                                                                  |
| `--tls-cert`, `--tls-key`, `--tls-ca` | `FABRIC_API_TLS_CERT`, `_KEY`, `_CA` | `/var/run/fabric-api/tls/tls.crt`, `tls.key`, `ca.crt` | As for the node                                                                                                                                                           |
| `--cell-slots`                        |                                      | `8`                                                    | Node RPCs running at once across all queries                                                                                                                              |
| `--cell-expensive-slots`              |                                      | `2`                                                    | Of those, expensive searches                                                                                                                                              |
| `--cell-queue`                        |                                      | `256`                                                  | Node RPCs that may wait for a slot                                                                                                                                        |
| `--max-nodes`                         |                                      | `32`                                                   | Nodes one query executes on in this cell (ceiling 32)                                                                                                                     |
| `--max-object-bytes`                  |                                      | `393216` (384 KiB)                                     | Serialized `FabricQuery` size ceiling (ceiling 384 KiB)                                                                                                                   |
| `--max-node-response-bytes`           |                                      | `131072` (128 KiB)                                     | Node response ceiling (ceiling 128 KiB)                                                                                                                                   |
| `--max-in-flight`                     |                                      | `256`                                                  | Queries executing at once; more wait for a requeue                                                                                                                        |
| `--retention`                         |                                      | `1h`                                                   | Retention the stale-object count assumes; keep equal to the janitor's `--retention`                                                                                       |
| `--cleanup-grace`                     |                                      | `15m`                                                  | Cleanup grace the stale-object count assumes; keep equal to the janitor's `--grace`                                                                                       |

`--max-nodes`, `--max-object-bytes` and `--max-node-response-bytes` can only lower
their ceilings: zero or a value above the ceiling selects the ceiling. The
liveness and readiness probes are plain pings of `/healthz` and `/readyz`; a
follower replica is ready.

### `fabric-api certsync`

Runs in the `fabric-api-certs` pod; you normally do not run it by hand.

| Flag         | Default                    | Meaning                                                                 |
| ------------ | -------------------------- | ----------------------------------------------------------------------- |
| `--source`   | `/var/run/fabric-api/csi`  | Directory the csi-driver writes the certificate to                      |
| `--dest`     | `/var/run/fabric-api/node` | Node-local directory the sidecar reads (hostPath `/run/fabric-api/tls`) |
| `--interval` | `10s`                      | Time between syncs                                                      |

It copies only when `tls.crt`, `tls.key` and `ca.crt` all exist, the key pair
validates and the content differs from `--dest`, replacing each file atomically.

### `fabric-api janitor`

| Flag          | Default | Meaning                                                              |
| ------------- | ------- | -------------------------------------------------------------------- |
| `--retention` | `1h`    | How long a finished query is kept                                    |
| `--grace`     | `15m`   | How long past retention to wait for the federation to delete a query |
| `--interval`  | `0`     | Time between sweeps. `0` sweeps once and exits, for a CronJob        |

### `fabric-api query`

The operator client. `fabric-api query [TYPE [TARGET]]`, where `TYPE` is one of
`RouteLookup`, `ASPath`, `Community`, `LargeCommunity`, `BGPSummary`, `Ping` or
`Traceroute`. Set exactly one of `--gateway` and `--node`.

| Flag                                  | Env                                  | Default                              | Meaning                                                                               |
| ------------------------------------- | ------------------------------------ | ------------------------------------ | ------------------------------------------------------------------------------------- |
| `--gateway`                           |                                      |                                      | Gateway debug service address (`host:port`). Applies the public destination policy    |
| `--node`                              |                                      |                                      | Node sidecar address (`host:port`). Applies the operator destination policy           |
| `--node-name`                         |                                      |                                      | With `--node`: the node's name                                                        |
| `--node-pod`                          |                                      |                                      | With `--node`: the node's `fabric-api-certs` pod, whose identity its sidecar presents |
| `--namespace`                         |                                      | `galactic-system`                    | The `fabric-router` pods' namespace, for the node identity                            |
| `--cell`                              | `CELL`                               |                                      | Cell name                                                                             |
| `--operator`                          | `FABRIC_API_OPERATOR`                |                                      | Operator name in the client certificate                                               |
| `--family`                            |                                      | inferred, else IPv4                  | `IPv4` or `IPv6`                                                                      |
| `--nodes`                             |                                      |                                      | Restrict a gateway query to these node names                                          |
| `--info`                              |                                      | `false`                              | With `--node`: print the node's identity and availability instead of running a query  |
| `--timeout`                           |                                      | `30s`                                | Query timeout                                                                         |
| `--tls-cert`, `--tls-key`, `--tls-ca` | `FABRIC_API_TLS_CERT`, `_KEY`, `_CA` | `./tls.crt`, `./tls.key`, `./ca.crt` | The operator certificate, key and the cell's bundle                                   |

Probe targets must be numeric addresses; the client never resolves a name.

```sh
# Is a node healthy, and what does it support?
fabric-api query --cell dfw --operator alice \
  --node '[fd00::10]:9344' --node-name dfw-worker --node-pod fabric-api-certs-abcde --info

# Every node's BGP summary, through the cell gateway (public policy)
fabric-api query --cell dfw --operator alice \
  --gateway 127.0.0.1:19346 BGPSummary --family IPv6
```

The second form is run against `kubectl -n galactic-system port-forward
svc/fabric-api-gateway 19346:9346`. Output is JSON; failures print as
`<code>: <message>`.

## Query types

All seven types are accepted by the API. `RouteLookup`, `BGPSummary`, `Ping` and
`Traceroute` are always enabled on a node that has credentials and a supported
FRR. `ASPath`, `Community` and `LargeCommunity` search the whole BGP table. They
are off by default, and are answered from the [search index](#search-index), not
by FRR:

- A node without `--enable-expensive-queries` answers them with
  `QueryTypeUnavailable`.
- With it set, a node runs at most `--max-expensive` (1) at a time with no queue
  (`NodeBusy`), and the gateway runs at most `--cell-expensive-slots` (2) across the
  cell.
- With the index, a search is `QueryTypeUnavailable` while the index is not synced
  with bgpd. There is no fallback to scanning bgpd.
- With `--search-source=frr`, a scan that times out suspends every expensive search
  on that node for `--expensive-breaker-cooldown` (10 minutes,
  `fabric_api_node_expensive_breaker_open` 1). The index does not use the breaker.
- `fabric-api query --node ... --info` lists the enabled types and omits the
  expensive ones while they are off, the index is unsynced, or the breaker is open.

The release gate was a full-table load test, which direct FRR scans failed and the
index passed; see [load-test.md](load-test.md). Enabling searches is a staged infra
rollout: after staging confirms those numbers on real fabric routers, enable them on
a canary node first, check `fabric_api_node_search_index_synced` and bgpd's session
and convergence behaviour, and expand in paces. The containerlab lab enables them.

## Search index

The index is a copy of bgpd's selected routes, kept in the sidecar's memory from a
BMP stream, so searches never touch bgpd. It requires bgpd to stream its Loc-RIB to
the sidecar, which a node's `frr.conf` must ask for.

**FRR configuration.** Under `router bgp` in each node's `frr.conf`:

```
 bmp targets fabric-api
  bmp connect 127.0.0.1 port 9348 min-retry 1000 max-retry 10000
  bmp monitor ipv4 unicast loc-rib
  bmp monitor ipv6 unicast loc-rib
 exit
```

bgpd must load the BMP module (`-M bmp`); the `fabric-router` image's `daemons` file
already does (`containers/fabric-router/daemons`). Infra's `frr.conf` renderer must
emit this block for production nodes; the lab's per-node `frr.conf` files carry it
(`deploy/containerlab/resources/fabric-router/*/frr.conf.*`). Without it the index
never syncs and searches stay `QueryTypeUnavailable`. A change to `frr.conf` is
applied live by the config agent; the BMP module itself needs a pod restart.

**Behaviour.**

- The sidecar's BMP station listens on `127.0.0.1:9348` (`--bmp-station-address`),
  accepts only loopback peers and serves one session at a time.
- Each session starts with an empty index: bgpd resends the whole table. The index is
  *synced* once bgpd's initial table dump is over. FRR 10.7 sends no End-of-RIB
  for Loc-RIB monitoring, so the station watches the update rate: the dump
  arrives orders of magnitude faster than steady churn, and the index counts as
  synced once the session has carried routes and the rate over the last 5 seconds
  has fallen to 50 per second or 1% of the session's peak, whichever is higher. A
  quiet period would never come on a churning full table; this does. An explicit
  End-of-RIB, should bgpd send one, also syncs. In the load test 200,000 routes
  synced in 9 seconds and a full IPv4 and IPv6 table in under 30. When the session ends the index is unsynced until bgpd reconnects (bgpd
  retries every 1 to 10 seconds with the block above).
- The index holds each prefix's **selected path only**, so it can return fewer
  prefixes than FRR's own search, which lists any path that matches. See
  [api.md](api.md#searches-and-the-index).
- Announcements for new prefixes beyond `--search-index-max-routes` are dropped and
  counted, never served as a complete table.

**Sizing.** In the load test (1.39 million prefixes, IPv4 and IPv6) the index held
about 212,500 distinct attribute sets, synced in about 29 seconds, and the sidecar's
RSS was about 430 MB (Go heap in use about 370 MB). The Component requests 64Mi,
limits memory to 768Mi and sets `GOMEMLIMIT=640MiB` so the Go collector stays inside
the limit. A fabric that carries only default routes needs a few Mi. If a node
carries a table larger than the load test's, size the limit and
`--search-index-max-routes` for it. Building the index cost bgpd 23.4 CPU-s once.

**Metrics** (port 9345, only with `--search-source=index`):

| Metric                                                       | Meaning                                                 |
| ------------------------------------------------------------ | ------------------------------------------------------- |
| `fabric_api_node_search_index_routes{afi}`                   | Prefixes in the index, by family                        |
| `fabric_api_node_search_index_attribute_sets`                | Distinct attribute sets held                            |
| `fabric_api_node_search_index_overflow_total`                | Announcements dropped at the route ceiling              |
| `fabric_api_node_search_index_synced`                        | 1 when the index holds bgpd's full table and follows it |
| `fabric_api_node_search_index_last_update_timestamp_seconds` | When the index last applied a route change              |
| `fabric_api_node_bmp_route_messages_total`                   | BMP route monitoring messages applied                   |

The `FabricAPISearchIndexUnsynced` alert (below) fires when a node's index holds
routes but has not been synced for 15 minutes.

## Limits

Byte and count limits are fixed ceilings in `internal/fabric/query/limits.go`. A
deployment can configure lower values, and a `FabricQuery`'s `spec.budgets` can
lower them further per request, but nothing a caller supplies can raise one.

| Boundary                     | Default and ceiling          | Where enforced                                                                                         |
| ---------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------ |
| Target                       | 255 bytes                    | `Canonicalize`, at every hop                                                                           |
| AS-path expression           | 128 bytes                    | `Canonicalize`                                                                                         |
| Error message in a result    | 256 bytes                    | `errcode`                                                                                              |
| FRR response read            | 4 MiB                        | vty client; over the cap closes the connection and returns `ResponseTooLarge`                          |
| Node gRPC response           | 128 KiB                      | Node shaping and gateway `--max-node-response-bytes`; the gRPC send limit is the ceiling plus 16 KiB   |
| Node gRPC request            | 64 KiB                       | gRPC receive limit                                                                                     |
| `FabricQuery` object         | 384 KiB                      | Gateway budgets the object before writing status; `--max-object-bytes`                                 |
| Nodes per query per cell     | 32                           | Gateway snapshot; `--max-nodes`. More are recorded as omitted (`NodeBudget`)                           |
| Prefix observations per node | 100                          | Node shaping                                                                                           |
| Paths per prefix             | 8                            | Node shaping; the router's best path is always kept                                                    |
| Communities per path         | 64 of each kind              | Node shaping (communities and large communities separately)                                            |
| Request lifetime             | 120 seconds                  | Node rejects `expires_at` more than 120s away; gateway rejects a spec more than 120s plus 1 minute out |
| Node execution               | 30 seconds                   | One absolute deadline per node, set before queueing, no later than the request's expiry                |
| Ping                         | 3 echo requests              | Probe package                                                                                          |
| Traceroute                   | 20 hops, 1 probe per hop     | Probe package                                                                                          |
| Probe payload                | 32 bytes default, 64 maximum | Probe package                                                                                          |
| Wait for one probe reply     | 1 second                     | Probe package                                                                                          |
| Cells per public query       | 8                            | Declared in the shared `query` package for NSO; not enforced by galactic                               |

Per-node concurrency and the cell executor:

| Budget                                | Default              | Setting                        | When full                                           |
| ------------------------------------- | -------------------- | ------------------------------ | --------------------------------------------------- |
| Node `Execute` calls at once          | 4                    | `--max-concurrent`             | Waits within the deadline, then `NodeBusy`          |
| Node expensive searches at once       | 1                    | `--max-expensive`              | `NodeBusy` at once                                  |
| Node probes at once                   | 2                    | `--max-probes`                 | `NodeBusy` at once                                  |
| Node probe packet rate                | 20 pps, burst 5      | `--probe-packet-rate`          | Packets are delayed within the deadline             |
| Node duplicate cache                  | 1024 entries, 32 MiB | none                           | Oldest completed entries evicted                    |
| Node expensive-search breaker         | 10 minutes           | `--expensive-breaker-cooldown` | `QueryTypeUnavailable`                              |
| Cell node RPCs at once                | 8                    | `--cell-slots`                 | Queued                                              |
| Cell expensive RPCs at once           | 2                    | `--cell-expensive-slots`       | Queued                                              |
| Cell RPC queue                        | 256                  | `--cell-queue`                 | `NodeBusy` at once ("cell execution queue is full") |
| Queries executing at once per gateway | 256                  | `--max-in-flight`              | Requeued after 1 second                             |

The cell queue is served round robin across projects, first in first out within
one, so a burst from one project cannot starve another. Each node's allowance is
derived from the object budget before fan-out: what is left of the object ceiling
after the object itself and 512 bytes of error room per selected node, divided
among the selected nodes and by 3 (JSON is larger than protobuf), no more than the
node response ceiling and no less than 1 KiB. A result that still does not fit when
the gateway assembles it is shrunk, the largest observation first, and marked
truncated.

## Probe sources and destinations

### Source

Probes use the default VRF and an explicit per-family fabric loopback address, and
never fall back to `127.0.0.1`, `::1`, an unspecified address or an unrelated
interface. For each family the sidecar uses, in order:

1. `--probe-source-ipv4` or `--probe-source-ipv6`, if set. The value must parse and
   be of the right family; a loopback or unspecified address makes startup fail.
2. Otherwise the single global unicast address of that family on
   `--probe-source-interface` (default `lo`), ignoring loopback and link-local
   addresses.
3. Otherwise none. A family with no source, or with more than one candidate on the
   interface (the log says "several candidate probe sources; set one explicitly"),
   answers `ProbeSourceUnavailable` for that family. A missing interface logs a
   warning and disables auto-detection.

`Info.probe_sources` lists the sources that resolved. If `lo` carries other global
addresses (VIPs, for instance), set the sources explicitly.

### Destination

A probe's destination is a numeric address pinned by NSO; the node validates it
again and never resolves names. Under the **public policy**, the one applied to
every call from the gateway identity, a destination is refused
(`DestinationNotAllowed`) if it is:

- an IPv6 address outside `2000::/3` (global unicast), or
- in a special-use range: IPv4 `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`,
  `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`,
  `192.31.196.0/24`, `192.52.193.0/24`, `192.88.99.0/24`, `192.168.0.0/16`,
  `192.175.48.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`,
  `224.0.0.0/4`, `240.0.0.0/4`; IPv6 `::/128`, `::1/128`, `::ffff:0:0/96`,
  `64:ff9b::/96`, `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`,
  `2002::/16`, `3fff::/20`, `5f00::/16` (SRv6 SIDs), `fc00::/7`, `fe80::/10`,
  `ff00::/8`, or
- inside a range listed in `--deny-prefixes`: add your management and platform
  ranges here.

The **operator policy** applies to calls made directly to a node with an operator
identity. It is the public policy plus `--operator-allow-prefixes`, and an allowed
prefix bypasses every other rule, including `--deny-prefixes`. The lab uses it to
check cross-site reachability between fabric loopbacks (`10.255.255.0/24` and
`fc00::/32`). A node refuses to start with allow exceptions on the public policy,
and nothing enforces "never in production" except not setting the flag. Calls made
through the gateway's debug service carry the gateway's identity at the node, so
they get the public policy whoever the operator is.

## Per-node and per-cell state

`Info` (and `fabric-api query --info`) reports a node's view:

| Field                           | Meaning                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `diagnosticsAvailable`          | True when FRR is reachable at a supported version and credentials are loaded                            |
| `unavailableReason`             | `FRR has not been read yet`, the FRR error (for example `FRRVersionUnsupported`), or `credentials: ...` |
| `frrVersion`, `routerId`, `asn` | From `show version` and `show bgp summary json`                                                         |
| `enabledQueryTypes`             | Types currently enabled, without expensive types while gated or suspended                               |
| `probeSources`                  | Resolved per-family sources                                                                             |

The only supported FRR release is 10.7. A node reading any other release reports
`FRRVersionUnsupported` and diagnostics unavailable. Do not move the
`fabric-router` image's `FRR_VERSION` to a new release until a `fabric-api` release
supporting it is deployed.

## Cleanup

| Owner        | What it cleans                                                              | When                                                                   |
| ------------ | --------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| NSO          | The hub copies, on public deletion or retention expiry, and any hub orphans | NSO's schedule; out of scope here                                      |
| Karmada      | The propagated cell copies, when the hub copy is deleted                    | On propagation                                                         |
| Cell janitor | Cell copies the federation failed to delete                                 | CronJob every 15 minutes (`*/15 * * * *`), `concurrencyPolicy: Forbid` |
| Gateway      | Nothing: it only reports the backlog as `fabric_api_gateway_stale_objects`  | Every minute, on every replica                                         |

The janitor deletes a `FabricQuery` once the later of its `spec.expiresAt` and its
`status.completionTime` is more than `--retention` (1h) plus `--grace` (15m) in the
past, which is 75 minutes with the defaults. It deletes with a UID precondition, so
a new query reusing a name is never touched, and it never creates or modifies
anything. Karmada recreating a copy the janitor deleted is harmless: an expired
query is finished as `DeadlineExceeded` without executing. The CronJob runs with
`backoffLimit: 2` and an `activeDeadlineSeconds` of 600.

`fabric_api_gateway_stale_objects` and `FabricAPICleanupBacklog` use the gateway's
`--retention` and `--cleanup-grace` (defaults 1h and 15m). Keep them equal to the
janitor's `--retention` and `--grace`, or the gauge and alert disagree with what the
janitor deletes. The janitor has no metrics: it logs each deletion (and, at debug
level, each outcome), so read its activity from the CronJob's logs.

## Observability

Scrape config and alert rules are in `config/monitoring/` (not part of
`config/kustomization.yaml`; they need the Prometheus Operator CRDs):

- The `fabric-router` PodMonitor's `api-metrics` endpoint scrapes the sidecar's
  port 9345 as `job="fabric-api-node"`, with a `node` label. A pod without the port
  yields no target.
- `podmonitor-fabric-api-gateway.yaml` scrapes the gateway's port 9347 as
  `job="fabric-api-gateway"`.
- The `fabric-api` group in `prometheusrule.yaml`, unit-tested by `task test:alerts`.
  None fires merely because nobody ran a query.

| Alert                                 | Fires when                                                                                                                                   | For |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --- |
| `FabricAPIExecutionStalled`           | A gateway has executions in flight and finished none in 10 minutes                                                                           | 10m |
| `FabricAPINodeDiagnosticsUnavailable` | `fabric_api_node_diagnostics_available` is 0                                                                                                 | 15m |
| `FabricAPINodeUnreachable`            | More than half of at least 5 node calls in 30 minutes were `NodeUnreachable` or `Timeout`                                                    | 15m |
| `FabricAPIResultsOversized`           | 10 or more `ResponseTooLarge` outcomes on a node in an hour                                                                                  | 15m |
| `FabricAPICleanupBacklog`             | More than 50 stale `FabricQuery` objects                                                                                                     | 1h  |
| `FabricAPICertificateRenewalFailing`  | A loaded certificate has less than 4 hours left                                                                                              | 15m |
| `FabricAPICredentialsMissing`         | `fabric_api_credentials_loaded` is 0                                                                                                         | 15m |
| `FabricAPISearchIndexUnsynced`        | `fabric_api_node_search_index_synced` is 0 on a node whose index has held routes (a node with no `bmp targets fabric-api` block never fires) | 15m |
| `FabricAPIMetricsDown`                | A fabric-api target cannot be scraped                                                                                                        | 10m |

All are `severity: warning`, `service: galactic`, `team: connect`. On Datum's infra
the PodMonitors are scraped on each edge cluster but the rules are evaluated from
infra's copy; change the rules here, with their tests, then update infra's copy.

Node metrics (port 9345, a private registry with Go and process collectors):
`fabric_api_node_requests_total{type,outcome}`,
`fabric_api_node_request_duration_seconds{type}`,
`fabric_api_node_response_bytes{type}`,
`fabric_api_node_truncated_responses_total{type}`,
`fabric_api_node_in_flight_requests`,
`fabric_api_node_duplicate_requests_total`,
`fabric_api_node_duplicate_cache_entries`,
`fabric_api_node_diagnostics_available`,
`fabric_api_node_frr_info{version,supported}`,
`fabric_api_node_expensive_breaker_open`,
`fabric_api_node_probe_packets_total`,
`fabric_api_node_identity_refreshes_total{outcome}`,
`fabric_api_certificate_expiry_timestamp_seconds` and
`fabric_api_credentials_loaded`.

Gateway metrics (port 9347, on controller-runtime's registry, so its own metrics
appear too): `fabric_api_gateway_queries_total{type,reason}`,
`fabric_api_gateway_node_outcomes_total{outcome}`,
`fabric_api_gateway_node_rpc_duration_seconds{type,code}`,
`fabric_api_gateway_queue_depth`, `fabric_api_gateway_status_writes_total{kind,outcome}`,
`fabric_api_gateway_status_bytes`, `fabric_api_gateway_truncated_results_total`,
`fabric_api_gateway_stage_latency_seconds{stage}` (`receipt`, `execution`,
`completion`), `fabric_api_gateway_executions_in_flight`,
`fabric_api_gateway_queue_wait_seconds` (time a node RPC waited for a cell slot),
`fabric_api_gateway_stale_objects`, `fabric_api_certificate_expiry_timestamp_seconds`
and `fabric_api_credentials_loaded`. Request IDs and targets are never labels.

## Rollout

The `fabric-api` sidecar lives in the `fabric-router` pod, and `/run/frr` stays a
pod-scoped `emptyDir` so FRR's sockets are never exposed beyond the pod. The cost
is that changing the sidecar's tag, flags or the Component itself changes the
DaemonSet's pod template, and the rolling update recreates the whole pod, FRR
included. **A sidecar release is a routing rollout.**

1. **Do the prerequisites first**, outside the pods: cert-manager with its
   csi-driver on every fabric node, the Issuer, the cell ConfigMap and the CRD. Roll out the
   gateway and janitor first; they do not touch `fabric-router`.
2. **Canary one node.** Stage the change so only one node's pod is recreated
   first, however your delivery system stages a DaemonSet change (the per-node
   overlays used for `galactic-gateway` pin an instance to one node; the same idea
   applies). Do not let the first change reach every node at once.
3. **Check underlay sessions and convergence** on the canary: every `frr_bgp_peer_state`
   for the node back to Established for both families (frr-exporter on port 9342),
   no `FabricBGPSessionDown` or `FabricBGPPrefixesDropped`, and `fabric-router` Ready.
   Shallow daemon liveness is not a convergence gate. Then check the looking glass:
   `fabric_api_node_diagnostics_available` 1, `fabric_api_credentials_loaded` 1, and
   a direct `fabric-api query --info`.
4. **Pace the expansion**, one site or a small batch at a time, repeating step 3.
   Stop on any session loss.
5. **Roll back** by restoring the previous tag or removing the Component from the
   overlay; that is another rolling restart, so pace it the same way. Probe success
   is not evidence of routing health.

Keep the gateway's and the sidecar's tags in step. They are the same image, and
this repository does not test a gateway and sidecars at different versions. The
publish pipeline stamps one tag into both `config/fabric-api/base` and the
Component.

A failing sidecar must not gate any of this, and a certificate that cannot be issued
stalls only the `fabric-api-certs` pod. If a `fabric-api-certs` pod hangs in
`ContainerCreating`, the csi-driver is missing on that node or the Issuer cannot
issue; the node then shows `NoCertificatePod` to the gateway. A `fabric-router` pod
that hangs on `fabric-api-tls` should not occur, since that is a hostPath; check the
Component's patch. If the sidecar runs but reports diagnostics
unavailable, FRR and the underlay are unaffected; read `unavailableReason`.

## Verifying

```sh
# Per node (lab): ASN, router ID, both address families' sessions, exact and
# longest-match lookups with zebra evidence, operator probes, then each gateway
# and a FabricQuery end to end.
cd deploy/containerlab && task verify:fabric-api

# Disruptive: break the Issuer, recreate one fabric-router pod, check FRR and the
# underlay come up with diagnostics unavailable, then repair the Issuer.
cd deploy/containerlab && task verify:fabric-api-bootstrap
```

In a real cell, read the same facts from the cluster:

```sh
kubectl -n galactic-system get pods -l app.kubernetes.io/name=fabric-router \
  -o custom-columns=NODE:.spec.nodeName,POD:.metadata.name,READY:.status.containerStatuses[*].ready
kubectl -n galactic-system logs deploy/fabric-api-gateway | grep -i "fabric query"
kubectl get fabricqueries -A      # short name: fq
```

## Troubleshooting

| Symptom                                             | Likely cause and where to look                                                                                                                                                             |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `fabric-api-certs` pod stuck in `ContainerCreating` | csi-driver not installed or not on this node, or the Issuer cannot issue. FRR is unaffected; the node reports no credentials and the gateway omits it as `NoCertificatePod`                |
| `unavailableReason` starts with `credentials:`      | Issuer missing or not ready, `certsync` has not copied files yet, or `CELL_NAME` in the `fabric-api-certs` volume is not the ConfigMap's `cell`; check the certs pod and the sidecar's log |
| `unavailableReason` is `FRRVersionUnsupported`      | FRR is not 10.7; ship a fabric-api that supports the new release before the `fabric-router` image                                                                                          |
| `unavailableReason` is `FRRUnavailable`             | `bgpd.vty`/`zebra.vty` not reachable: FRR restarting, or the container lacks group 102                                                                                                     |
| Sidecar logs "fabric-api node is not configured"    | `CELL` is empty: the ConfigMap or its `cell` key is missing. Fix it and recreate the pod                                                                                                   |
| Gateway pod `CreateContainerConfigError`            | The `fabric-api` ConfigMap or one of `site`, `cell`, `cluster-name` is missing                                                                                                             |
| `FabricQuery` stays untouched                       | `spec.site` or `spec.clusterName` does not equal this gateway's; or this replica is not the leader                                                                                         |
| `NodeUnreachable` for every node                    | Gateway cannot reach `hostIP:9344` (host firewall) or the TLS handshake fails; check identities and cell values                                                                            |
| `Unauthorized`                                      | The caller's role may not make this call: a node identity cannot call anything, and a gateway identity may call only the debug `Query`                                                     |
| `DestinationNotAllowed` on a ping                   | Public policy applied; a direct node call with an operator identity may carry `--operator-allow-prefixes` in the lab                                                                       |
| `ProbeSourceUnavailable`                            | No probe source for that family; see [Source](#source)                                                                                                                                     |
| `QueryTypeUnavailable`                              | Expensive types are gated, or the breaker is open after a timed-out scan                                                                                                                   |
| `NodeBusy`                                          | Node or cell budget full; expensive and probe budgets have no queue                                                                                                                        |
| `ResponseTooLarge`                                  | FRR's answer exceeded 4 MiB, or did not fit the node's budget even when shaped; see `FabricAPIResultsOversized`                                                                            |
| `DuplicateConflict`                                 | A request ID was reused with different arguments                                                                                                                                           |

For the typed codes carried in results, see [api.md](api.md#error-codes).
