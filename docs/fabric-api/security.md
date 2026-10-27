# fabric-api identities and probe policy

This reference defines authentication, certificate rotation and which probe addresses are permitted. Start with [deployment](deployment.md) before provisioning credentials.

## Identities and certificates

Every certificate carries exactly one URI SAN in the trust domain
`fabric-api.datumapis.com`:

| Identity | URI SAN                                                                  | Issued to                                 | Key usages                |
| -------- | ------------------------------------------------------------------------ | ----------------------------------------- | ------------------------- |
| gateway  | `spiffe://fabric-api.datumapis.com/cell/<cell>/gateway`                  | The gateway Deployment (both replicas)    | `client auth,server auth` |
| node     | `spiffe://fabric-api.datumapis.com/cell/<cell>/ns/<namespace>/pod/<pod>` | Each node's `fabric-api-certs` pod        | `server auth`             |
| operator | `spiffe://fabric-api.datumapis.com/cell/<cell>/operator/<name>`          | A person or tool calling directly         | `client auth`             |
| service  | `spiffe://fabric-api.datumapis.com/cell/<cell>/service/<name>`           | The customer-facing Looking Glass service | `client auth`             |

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
- The gateway also accepts node identities, which may call only its
  `RequestPermit` and `ReleasePermit` (and the gateway identity, forwarding
  them to the leader). The handler further requires the node identity's
  namespace to be the gateway's `--namespace` and its pod to be a
  `fabric-api-certs` pod on the node the call names.
- The gateway also accepts a service identity whose name is in
  `--service-identities`. A service may call only the Looking Glass service's
  `GetCapabilities` and `RunDiagnostic`, never `Query`, `ListNodes` or a node.
  The gateway identity may call the gateway-only `ForwardDiagnostic`, with which
  a follower hands a request to the leader; no other identity may.
- On every gateway RPC, unary or streaming, the gateway verifies the caller's
  certificate again against its current bundle and clock, so a connection opened
  by a certificate that has since expired, or whose CA has left the bundle, is
  refused with `UNAUTHENTICATED`. A call's context ends when the caller's
  certificate expires, after which a stream sends and receives nothing more.
  Metadata keys starting `x-fabric-api-` are dropped from every call the
  gateway identity did not make.

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

### Service certificates

The customer-facing Looking Glass service gets one certificate per cell it calls,
from that cell's `fabric-api` Issuer, with URI SAN
`spiffe://fabric-api.datumapis.com/cell/<cell>/service/<name>` and usage
`client auth`, issued like an operator certificate. The gateway accepts it only
when `<name>` is in its `--service-identities` list. The project and request
IDs in a `RunDiagnostic` request are trusted because that identity is
authenticated: issuing a service certificate grants the right to attribute
diagnostics to any project, so treat it as an access decision too. The
service presents the certificate on its gRPC connection to the gateway's
`debug` port and, to rotate without a restart, reloads the files as cert-manager
renews them; the gateway accepts the overlapping-bundle rotation below. The
service contract is [service-contract.md](../designs/looking-glass-service.md). The gateway
executes service diagnostics only while its service switch is on, under
`--aggregate-budgets` (see
[Operating the Looking Glass service](operations.md#operating-the-looking-glass-service));
otherwise it answers a valid `RunDiagnostic` with `ServiceDisabled`, and
`GetCapabilities` reports `enabled: false`. While execution is on,
`GetCapabilities` also lists `aggregate-probe-budgets` and the cell's
admission limits.

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
