# MASQUE connector service

`cmd/masque-provider` is the CONNECT-IP service a MASQUE connector reaches. It serves CONNECT-IP ([RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)) over HTTP/3 on UDP, and over HTTP/2 with TLS on TCP for clients whose UDP is blocked. It runs as an unprivileged Galactic Edge provider. It forwards each admitted connector's packets into the connector's gVPC through the [provider adapter](masque-provider.md). The [grant authority](masque-authority.md) authorizes every request. The service accepts no credential of its own.

The service and the conformance fixture (`tests/edgeconformance/masqueprovider`) run the same code, `internal/edge/masque/service`. They differ only in where grants come from: the fixture can also use static test credentials.

Images:

- `ghcr.io/datum-cloud/masque-provider` (`containers/masque-provider/Dockerfile`)
- `ghcr.io/datum-cloud/masque-authority` (`containers/masque-authority/Dockerfile`)

`.github/workflows/publish.yaml` publishes both.

## Deployment

`config/masque` holds the manifests. None of them is in the root `config/kustomization.yaml`. CI stamps both images into the `galactic-kustomize` bundle at the tag of the same build, so an overlay of that bundle needs no image pin. The TUN device plugin's image is a third-party image pinned by digest, which CI does not stamp or mirror.

| Path                                     | Applies                                                                                                                                                                      | Needs from an overlay                                                                                                                 |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `config/galactic-edge/tun-device-plugin` | DaemonSet `galactic-system/tun-device-plugin`, which serves `devic.es/tun` on the nodes labeled `galactic.datumapis.com/node=edge` and `galactic.datumapis.com/edge=enabled` | Nothing                                                                                                                               |
| `config/masque`                          | Namespace `masque-system`, both ServiceAccounts, the authority's RBAC, and the `EdgeProvider` named `masque`                                                                 | Nothing                                                                                                                               |
| `config/masque/authority`                | The `masque-authority` Deployment and Service                                                                                                                                | `--cell`, and Secret `masque-authority-tls` for `masque-authority.masque-system.svc`                                                  |
| `config/masque/provider`                 | The `masque-provider` Deployment and UDP/443 + TCP/443 Service                                                                                                               | `--authority`, Secret `masque-provider-tls` for that name, ConfigMap `masque-authority-ca` (`ca.crt`), and how the Service is exposed |

The [certificates](#certificates) section covers both Secrets and the CA.
For shared logical gateway hostnames, use [managed endpoints](#managed-endpoints)
instead of a single `--authority` and mounted public certificate.

## Managed endpoints

`masque-provider --managed-endpoints` serves all
`galactic.datumapis.com/v1alpha1` `MASQUEEndpoint` resources in `POD_NAMESPACE`
whose `spec.provider` matches the process's `--provider`. This reuses the existing
provider Deployment, EdgeInstance/Lease, and both listeners. It creates no
per-gateway capacity. Defaults remain TCP and UDP `:8443`; expose both through
the existing Service's port 443. Remove the legacy public TLS volume and its
mount when enabling managed mode, but retain the private grant-authority CA.

Install the generated CRD on the distribution control plane and serving cells
before delivering registrations. `config/masque/managed-endpoints-crd` exports
only this CRD; its canonical source is in `config/crd`. `task generate:crd`
refreshes the local generated copy so the export builds with default Kustomize
load restrictions. `task test:manifests` checks that both copies match exactly.
`config/masque` includes runtime RBAC;
the root Galactic Kustomization still does not enable MASQUE.

### Registration and delivery contract

The [API reference](../api/galactic.md#masqueendpoint) defines the complete
schema. The spec contains only `hostname`, `provider`, `revision`,
`certificateRef` and `enabled`. Registration name, hostname and provider are
immutable. No customer project, gateway, endpoint,
network or binding identifiers are copied into the spec or ownership annotations.
One gateway endpoint serves separately authorized network bindings. The hostname
is a lowercase DNS name without a port. Every mutable change increments the
positive `spec.revision`, including certificate replacement, disable and
reactivation. Exactly one registration may claim a hostname within the namespace,
even across different providers in that namespace.

Each cell/metro has a separate control plane. Connect retains placement in its
service-provider Project, targets exactly one selected cell through Karmada,
and uses that control plane's reader and grant credentials. Registration and
its retained fence contain no copied cell/metro fields. The provider has no
`--cell` flag. The grant authority retains `--cell`, and grant requests and
per-VPC/cell ledgers retain their existing cell scope; a grant from another
cell remains unauthorized.

`provider` selects a local named `EdgeProvider`, not placement. The runtime
supports independently selectable providers in one API/namespace: `--provider`
selects registrations and EdgeInstance membership, and the authority rejects
other providers' registrations. Each EdgeProvider has its own approval and
ServiceAccount identities. The default bundle instantiates `masque`, but does
not impose a singleton provider API.

`certificateRef.name` identifies a same-namespace `kubernetes.io/tls` Secret.
`certificateRef.revision` is lowercase SHA-256 of the leaf certificate DER,
matching `TLSCertificate.status.certificateRevision`, never an expiry ordering.
The Secret contains `tls.crt` and `tls.key` and this annotation:

```yaml
masque.galactic.datumapis.com/certificate-revision: <leaf-der-sha256>
```

Use immutable, versioned Secret names. Issuance infrastructure and selected
serving cells hold the keys; neither customer nor service-provider Projects
receive them. Delivery validates issuance ownership upstream; the runtime
checks the named registration certificate reference, exact fingerprint, matching private
key, SAN hostname and validity. Runtime trusts the authorized delivery writer;
external probes must verify public WebPKI trust and packet reachability.

### Activation, readiness and revocation

The runtime polls every two seconds. Each endpoint switches certificate and
registration together after validation. Same-expiry and shorter-lived rekeys
are supported. Replacements cancel and drain that endpoint's active requests
before activation, including emergency rekeys; clients reconnect. Other
hostnames and their connections are unaffected. SNI selects the certificate;
every HTTP/3 or HTTP/2 request checks authority and SNI before authenticating
its own credential and VPC selector against the authority. Two authenticated
CONNECT-IP streams may select different VPCs on **one** QUIC or TLS/TCP
connection. Authentication of one stream never authorizes a sibling stream.
Only the registered hostname or that hostname with `:443` is accepted. Unknown,
removed and mismatched authorities return 421.

The old valid registration may continue during a failed replacement while its
own Secret remains readable and valid. Deletion of the active Secret stops
admission and drains sessions. Ten seconds without successfully validating the
active Secret, or certificate expiry, closes admission; a 250 ms sweep cancels
active requests. API failure is not interpreted as registration deletion.

`status.instances` is keyed by `instanceName` and reports `observedRevision`, `appliedRevision`, `appliedCertificateRevision`,
`state` (`Applied`, `Disabled`, `Error`), `forwardingStopped`,
`lastHeartbeatTime` and an optional `message`. A failed replacement reports
the old applied version and `Error`, never the desired certificate revision.
`Disabled` and `forwardingStopped` are acknowledged only after tracked request
handlers finish releasing their admission leases and packet backends. Physical
route withdrawal remains subject to the existing Edge claim lifecycle; this
acknowledgment does not certify that every kernel route has been removed.

Readiness consumers enumerate **all** matching EdgeInstances in the provider
namespace using `spec.providerRef.name`, not only instances already in the
acknowledgment list. Require an exact desired revision/certificate revision, a
fresh heartbeat (at most ten seconds) strictly after both instance creation and
Lease `spec.acquireTime`, and a live same-name Lease owned by that instance.
The provider preserves acquisition time on renewal and changes it on takeover.
Status does not copy instance or pod UIDs; the runtime privately checks object
incarnations again before publishing the acknowledgment. Lease boot-clock annotations are not
wall timestamps; remote readers can use renewal time/duration and released
state as a liveness check but must not replace the runtime lease gate. New pods
without acknowledgments block endpoint readiness. Karmada delivery, pod
`/readyz`, and these acknowledgments alone do not establish DNS, external TLS,
both transport paths, or real VPC forwarding readiness.

Disable at a new revision and wait for all relevant instances' stopped
acknowledgments before deleting registrations and delivered Secrets. The
provider retains `masque-endpoint-<sha256(hostname)>` ConfigMaps labeled
`masque.galactic.datumapis.com/endpoint-fence=<provider>` without owner references.
The hash is lowercase hex SHA-256 of canonical hostname bytes only; the
registration namespace scopes the ConfigMap. The fence privately binds the
registration name and incarnation, immutable spec identity, and accepted/revoked
revisions. They fence stale revisions, equal-version conflicts, identity reuse, and
deletion/recreation. Never delete or roll back these fences during endpoint
cleanup. A higher revision may reactivate the same live identity; retired
gateway identities and hostname reservations remain Connect's responsibility.
Lost-cell cleanup requires explicit operational recovery, not a fabricated ack.

### Endpoint-bound grants

`pkg/masquegrant.New(uncachedCellClient, namespace)` exposes `Create`, `Rotate`,
`Disable` and `Retire` using the existing authority/ledger implementation.
`CreateRequest.EndpointRef` is `{Namespace, Name}` and `CreateRequest.VPC`
is the public name-only `VPCRef {Namespace, Name}`. No caller supplies object
UIDs. Connect authenticates the customer project and caller, resolves authorized
named bindings/networks, and privately pins their incarnations. Galactic does
not resolve customer Network objects. Connect checks its pinned VPC before and
after mint using uncached reads and retires any raced grant before returning it.
Galactic independently resolves and privately pins the cell VPC at creation,
verifies each request's controller-issued VPC selector, and rechecks that pin
on authorization, rotation and refresh. Creation and rotation resolve the named
endpoint and verify its accepted durable fence. Old managed record schemas are
rejected rather than silently treated as unscoped legacy credentials.
Retain a deterministic, binding-specific
connector UUID across retries: a failed create reuses its allocation, while an
already-created record requires rotation because plaintext credentials are not
stored. `Retire` retains the `/96` allocation tombstone.

Each binding has its own credential, EdgeService, route/attachment claims and
`/96` allocation in its VPC/cell ledger. Revoking a binding or deleting its VPC
ends only the corresponding sessions, not the shared transport or other VPCs.
Recreating a same-name VPC cannot revive the old UID-pinned credential. Network
binding changes do not alter endpoint registration, DNS or certificates.
Disabling the endpoint drains **all** its streams. Overlapping VPC address
space still requires isolated VRFs and client routing; sharing a transport
does not combine routing domains or qualify overlapping OS routes.

`pkg/masquegrant.NewLedgers(client, namespace)` exposes the existing `Ledgers`
administrative bootstrap API, including `Init`. Provision ledgers explicitly;
the broker must never initialize them as a side effect of a grant request.

The upstream `config/masque/endpoint-status-policy.yaml` restricts status writes
by `system:serviceaccount:masque-system:masque-provider` to the authenticated
pod's `ei-<podUID>` entry and preserves every other entry. Install the policy
and binding with runtime RBAC; adapt its username if renaming the namespace or
ServiceAccount. Providers need pod-bound tokens with the Kubernetes pod UID
authentication extra. Managed listeners disable TLS session tickets so a new
connection cannot bypass certificate selection through session resumption.

Providers include the locally resolved named endpoint reference in `/v1/authorize`; the authority compares
it to the credential record and rechecks registration/fences during refresh.
The `/v1/authorize` response contains named service/endpoint references, not
VPC or service UIDs. Its opaque authorization receipt binds the private service
incarnation. The provider uses an uncached local reader to resolve the service
and VPC, validate the receipt and hydrate private datapath identity. Bind the
unbound `masque-provider-tenant` ClusterRole in each authorized VPC namespace:
it grants only `get` on `edgeservices` and `vpcs`, never tenant Secrets or writes.
Install these tenant bindings before upgrading authority-backed providers,
including legacy single-hostname deployments. Upgrade authority and providers
together for the name-only wire contract; stale incarnation receipts fail closed.
Legacy credentials are accepted only on the legacy single-authority path, never
on a managed endpoint. Disabling/removing an endpoint advances a durable
revocation floor. Reactivation does not revive old credentials; retire them and
create a new authorized connector. Certificate renewal alone preserves the
credential epoch. Cell migration needs a new assignment, grant and attachment;
this feature does not implement transparent roaming or address preservation.

### Shared-transport authorization test

With `setup-envtest` installed, run:

```sh
CI=true GODEBUG=http2xconnect=1 \
  KUBEBUILDER_ASSETS="$(setup-envtest use 1.37.0 -p path)" \
  go test -race ./internal/edge/masque/authority \
  -run '^TestManagedEndpointMultiplexedAuthority$' -count=1 -v
```

Alternatively set `KUBEBUILDER_ASSETS` to an installed Kubernetes envtest
binary directory. `CI=true` makes missing assets fail instead of skipping.
This test counts physical dials and requires exactly one connection per H3/H2
case. It uses the real grant ledger, authorization and refresh implementation
against an API server, with managed SNI/authority resolution and separate
CONNECT-IP streams. It covers two VPCs, denied sibling/third-VPC replay,
independent revocation, VPC deletion/recreation, unchanged endpoint identity
during network changes, shorter-lived certificate replacement, and endpoint
disable draining all streams. Its packet backend is a test double: this is
not kernel VRF, route withdrawal, overlapping client OS routes, public TLS/DNS,
or production datapath qualification. The existing containerlab and external
cross-system acceptance gates remain required.

The bases leave out `--cell` and `--authority`, so a pod started without its overlay exits at startup instead of serving a wrong name. An overlay appends them, for example:

```yaml
patches:
  - target: {kind: Deployment, name: masque-provider}
    patch: |
      - op: add
        path: /spec/template/spec/containers/0/args/-
        value: --authority=masque.example.com
```

The cell must already run Galactic Edge: CRDs, `config/galactic-edge`, galactic-controller with `--edge` and the galactic-edge DaemonSet on the edge nodes ([provider contract](provider-contract.md)). The provider pods schedule only on nodes labeled `galactic.datumapis.com/node=edge` and `galactic.datumapis.com/edge=enabled`, and each requests one `devic.es/tun` device from the node's TUN device plugin. An overlay can rename that resource; the plugin must then serve the new name.

The TUN device plugin runs [`squat/generic-device-plugin`](https://github.com/squat/generic-device-plugin) privileged, with the host's `/dev` and the kubelet's `/var/lib/kubelet/device-plugins`. It needs the `galactic-system` namespace (`config/galactic-system`) and the kernel's `tun` driver, with its device node at `/dev/net/tun`, on each edge node. Any `PacketAccess` provider in the cell can use it, not only MASQUE.

To bring up a cell:

1. Apply `config/galactic-edge/tun-device-plugin` and wait for its pods to be ready on the edge nodes. Until a node's plugin registers, `kubectl describe node` lists no `devic.es/tun` and provider pods stay Pending with `Insufficient devic.es/tun`.
2. Apply `config/masque`.
3. Approve the provider by applying `config/masque/approval`, the `EdgeProviderApproval` named `masque`. galactic-controller then sets `status.approved` on `EdgeProvider/masque` and binds the provider role and admission policy to `masque-system/masque-provider`. In a GitOps cell, include `config/masque/approval` in the same overlay as `config/masque`; removing it from the overlay, with pruning on, withdraws the approval and both bindings. Applying it needs write access to `edgeproviderapprovals`, which no MASQUE or galactic ServiceAccount holds. A manual write to `status.approved` is reverted.
4. In each tenant namespace the authority serves, bind ClusterRole `masque-authority-tenant` to `masque-system/masque-authority` with a RoleBinding. Without it the authority can't issue that namespace's EdgeServices.
5. Apply the `authority` and `provider` overlays. Each provider pod reports ready once it holds its instance Lease.
6. Create each VPC's ledger and the test connectors with the [operator commands](masque-authority.md#operator-tasks).

The provider Deployment uses a rolling update. A connector that moves to a new pod gets a new authorization: the authority retires the old pod's incarnation and core releases its route before the new pod forwards ([cross-instance replacement](../designs/masque/contract.md#cross-instance-replacement-and-stale-cleanup)). The resource requests are starting values; [#984](https://github.com/datum-cloud/galactic/issues/984) qualifies the pod's size.

To take MASQUE out of a cell, delete the provider overlay first so its pods release their routes, then the authority overlay, then `config/masque`. Delete `config/galactic-edge/tun-device-plugin` last, and only once no other `PacketAccess` provider in the cell requests `devic.es/tun`. Pods already running keep their device, but new ones stay Pending.

### Certificates

The provider pods need two certificates and one CA:

- `masque-provider-tls`, the connector service's certificate, for the name in `--authority`. Clients verify it, so it comes from whatever CA the cell's clients trust. No component in `config/masque` issues it.
- `masque-authority-tls`, the grant authority's certificate, for `masque-authority.masque-system.svc`. Only the provider pods connect to it.
- The CA that signed `masque-authority-tls`, as `ca.crt` in the provider's `authority-ca` volume. The provider trusts no other root for the authority.

The authority and the provider reread their files when the Secret or ConfigMap changes, so a renewed certificate needs no restart.

**With cert-manager.** Include `components/cert-manager` in both overlays:

```yaml
# authority overlay
resources:
  - ../../config/masque/authority
components:
  - ../../config/masque/authority/components/cert-manager
---
# provider overlay
resources:
  - ../../config/masque/provider
components:
  - ../../config/masque/provider/components/cert-manager
```

The authority component creates a self-signed CA used only for the authority (Certificate and Issuer `masque-authority-root`) and issues `masque-authority-tls` from it. The provider component reads `ca.crt` from that Secret, so the pods trust exactly the CA that signed the certificate the authority serves. The authority's key is not mounted in the provider pods. The CA keeps its key when cert-manager renews it, so serving certificates issued before a renewal still verify.

**With another CA.** Supply `masque-authority-tls` yourself, and the CA as ConfigMap `masque-authority-ca` with key `ca.crt`. If the cell's CA tooling publishes the bundle under another name or key, replace the volume's sources with a strategic merge patch on the volume's name. The patch replaces the whole `sources` list, whatever the volume's position:

```yaml
patches:
  - target: {kind: Deployment, name: masque-provider}
    patch: |-
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: masque-provider
      spec:
        template:
          spec:
            volumes:
              - name: authority-ca
                projected:
                  sources:
                    - configMap:
                        name: cell-trust-bundle
                        items:
                          - key: bundle.pem
                            path: ca.crt
```

A `secret` source works the same way. Keep `path: ca.crt`, or set `--grant-authority-ca` to the path you mount instead.

## Configuration

| Flag                      | Default                                   | Meaning                                                                               |
| ------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------- |
| `--provider`              | none, required                            | The `EdgeProvider` the pod runs as                                                    |
| `--authority`             | none, required                            | The `host[:port]` clients send as `:authority`; a request naming another one gets 400 |
| `--listen`                | `:8443`                                   | UDP address of the HTTP/3 server                                                      |
| `--listen-tcp`            | `:8443`                                   | TCP address of the HTTP/2 server; empty serves HTTP/3 only                            |
| `--health-listen`         | `:9188`                                   | TCP address of `/healthz`, `/readyz` and `/metrics`                                   |
| `--tls-cert`, `--tls-key` | `/etc/masque-provider/tls/tls.{crt,key}`  | Server certificate and key, reread when either file changes                           |
| `--grant-authority-url`   | none, required                            | `https://` base URL of `masque-authority serve`                                       |
| `--grant-authority-ca`    | `/etc/masque-provider/authority/ca.crt`   | PEM roots the authority's certificate must chain to, reread when the file changes     |
| `--grant-authority-token` | `/var/run/secrets/masque-authority/token` | Projected ServiceAccount token with audience `masque-authority`, reread on every call |
| `--log-level`             | `LOG_LEVEL`, then `info`                  | Log level                                                                             |

The HTTP/2 server needs Extended CONNECT ([RFC 8441](https://www.rfc-editor.org/rfc/rfc8441)), which Go's `net/http` offers only when the process starts with `GODEBUG` containing `http2xconnect=1`. The image sets it. With `--listen-tcp` set and the variable missing, the provider exits at startup rather than serve a listener no client can use. An overlay that sets `GODEBUG` for another reason must keep `http2xconnect=1` in it.

The pod also needs the downward-API variables `POD_NAMESPACE`, `POD_NAME`, `POD_UID` and `NODE_NAME`, the in-cluster API credentials of its ServiceAccount, and a TUN device from a device plugin. The [adapter's setup](masque-provider.md#setup) lists the cluster side.

The server applies the per-pod limits of the [MASQUE contract](../designs/masque/contract.md#resource-budgets-and-benchmark-contract) with these values:

| Limit                                    | Value                  | Over the limit                                                       |
| ---------------------------------------- | ---------------------- | -------------------------------------------------------------------- |
| Open QUIC and TCP connections            | 128                    | QUIC closed with `H3_EXCESSIVE_LOAD`; TCP closed when accepted       |
| Open QUIC and TCP connections per source | 8                      | QUIC closed with `H3_EXCESSIVE_LOAD`; TCP closed when accepted       |
| QUIC or TLS handshake                    | 5 s                    | Connection dropped                                                   |
| Request streams per connection           | 2                      | QUIC refuses the stream; HTTP/2 advertises it and refuses the excess |
| Request header section                   | 8 KiB                  | Request refused                                                      |
| Requests in admission                    | 16                     | 503                                                                  |
| Requests in admission per credential     | 2                      | 503                                                                  |
| Authorization of one request             | 3 s                    | 503                                                                  |
| Admitted requests                        | 64                     | 503                                                                  |
| Queued packets toward one client         | 128 packets or 256 KiB | Packet dropped, counted as `queue_full`                              |
| Stuck delivery toward one client         | 5 s                    | That request ends, counted as `slow_client`                          |
| HTTP/2 connection with no request        | 30 s                   | Connection closed                                                    |

Delivery is stuck when one write toward the client blocks for 5 s, or when writes that each take over 1.25 s keep recurring for 5 s, with fewer than 16 prompt writes in a row between them. The second case catches an HTTP/3 client that stopped reading, whose QUIC connection still sends two datagrams per probe timeout.

Both transports share every limit from the connection caps down: an HTTP/3 session and an HTTP/2 session each take one of the 64 admitted requests. A QUIC connection counts toward its source IP once its handshake completes, so spoofed packets cannot use up another client's slots. A TCP connection counts once it is accepted, because TCP's own handshake proves the address. The source-IP limit counts every client behind one NAT as one source.

## Packet size

Every admitted request carries 1280-byte inner IPv6 packets in both directions. Over HTTP/3, admission sends a 1280-byte probe datagram after authorization and waits for the client's QUIC stack to acknowledge it. It sends up to three such probes 200 ms apart, and answers 503 when three 1280-byte packets sent on the QUIC connection after the first probe are lost, its own probes or another request's traffic, or when none is acknowledged within 3 seconds. A request over a path that answers nothing therefore holds its session slot and address lease for up to 3 seconds before it is refused.

- The server sends QUIC packets of a fixed 1350 bytes and does not run path MTU discovery. quic-go never shrinks a size that discovery found, so a path that shrank later would drop the larger packets without an error. A 1350-byte QUIC packet carries an inner packet of about 1310 bytes.
- A gVPC packet larger than that gets an ICMPv6 Packet Too Big with MTU 1280, which passes the [packet policy](masque-provider.md#packet-policy) and goes to the sender. This holds on any path that carries 1280-byte inner packets, however its MTU changes.
- When the QUIC connection cannot fit a packet of 1280 bytes or less, the request ends and the packet is counted as `reason="path_mtu"`. The sender cannot shrink below 1280 bytes, so RFC 9484 section 10.1 calls for termination over an error.
- When the path shrinks mid-tunnel so that a 1280-byte packet no longer arrives, the server sees it from the client's acknowledgements. Once three such packets in a row are lost over at least one second, while later packets on the connection still arrive, every request on the QUIC connection ends and one packet is counted as `reason="path_mtu"` per request. The server sends its own probes while it waits, so a request that carries no further traffic is also ended. The sender cannot shrink below 1280 bytes, so RFC 9484 section 10.1 calls for termination over an error. The connector reconnects, and the admission probe refuses it while the path stays too small.
- The HTTP/2 limits are under [HTTP/2 fallback](#http2-fallback).

The device, SRv6 and underlay limits are set by the foundation, not here. `galactic-edge --mtu` sets the attachment MTU.

## HTTP/2 fallback

A client whose UDP/443 is blocked sends the same request over HTTP/2 with TLS on TCP/443: an Extended CONNECT with `:protocol: connect-ip`, the same path, bearer credential and `Galactic-VPC` header. Packets travel in DATAGRAM capsules on the request stream. The request goes through the same admission, grant checks, backend and [packet policy](masque-provider.md#packet-policy) as over HTTP/3. The service does not pick a transport for the client.

- **Packet size.** The HTTP/2 path carries inner packets of up to 1500 bytes. A larger packet from the gVPC gets an ICMPv6 Packet Too Big with MTU 1500. A larger packet from the client is dropped and counted as `reason="too_large"`.
- **Malformed input.** The server holds at most one DATAGRAM capsule per request. It discards larger DATAGRAM capsules and unknown capsules as they arrive. A malformed capsule or an oversized `ADDRESS_REQUEST` ends only its own request.
- **Slow readers.** A capsule write that cannot finish in 5 seconds ends its request. Another request on the same connection keeps forwarding. Over HTTP/3, every request on a QUIC connection shares one datagram send queue, so a blocked packet write closes the client's whole QUIC connection.
- **Moving between transports.** A connector that reconnects over HTTP/2 while its HTTP/3 tunnel still exists is admitted again through the adapter. The adapter treats the new request as a [replacement](masque-provider.md#replacing-a-connectors-request): the old session ends before the new one forwards, so the connector never has two forwarding owners. A replacement on another pod goes through the grant authority's [cross-instance replacement](../designs/masque/contract.md#cross-instance-replacement-and-stale-cleanup).

## Startup and readiness

At start the service registers the pod's `EdgeInstance`, opens its UDP and TCP listeners and starts renewing the instance's Lease. `/readyz` answers 200 only while the listeners are open and the pod holds the Lease at a valid epoch. A pod without its Lease admits no request, so a readiness gate keeps it out of a Service's endpoints until then. `/healthz` answers 200 while the process runs.

A request is admitted only after the authority authorizes its credential and the adapter's attachment and route are ready ([readiness](masque-provider.md#readiness)). The first request of a connector on a pod can take several seconds while galactic-edge programs the attachment.

## Shutdown

SIGTERM or SIGINT starts shutdown:

1. `/readyz` fails and both listeners close, which ends every session on either transport.
2. The adapter stops renewing, releases each route claim, deletes its attachments and releases the Lease ([drain and shutdown](masque-provider.md#drain-and-shutdown)).

Step 2 has 20 seconds, so give the pod a termination grace period of at least 30 seconds. A pod killed before it finishes leaves its routes to expire: galactic-edge closes their gates at the Lease deadline, and core reaps the pod's objects.

## Metrics

`/metrics` serves the instrumentation library's registry: the CONNECT-IP server's request, tunnel and packet metrics (`galactic_connectip_*`) and the adapter's admission, route claim and request state metrics (`galactic_masque_*`), listed in [the MASQUE metrics reference](../observability/masque.md). [Diagnose a MASQUE connector](troubleshooting.md#diagnose-a-masque-connector) uses them with the provider's log lines.

## Verification

`task verify:masque-service`, run from `deploy/containerlab`, deploys this service and the grant authority from `config/masque` in the lab, through the overlays in `deploy/containerlab/resources/masque-service`, and grants its connectors with the [operator commands](masque-authority.md#operator-tasks). Its rows run against real gVPC workloads and cover:

- independent clients connecting, exchanging 1280-byte packets in both directions with a workload on the provider's node and one on the compute node, disconnecting and reconnecting;
- 401 for an unknown credential and 403 for another VPC's selection;
- a client refusing a certificate from another CA or for another name, on both transports;
- return traffic to client-managed addresses in subdivisions of a connector's /96;
- `grant disable` and credential expiry stopping one connector within their bounds while another keeps forwarding through the same instance;
- readiness only while the pod holds its Lease;
- process restart and drain on SIGTERM;
- the same lifecycle, denials, spoofing, cross-tenant isolation and expiry over HTTP/2 with the client's UDP to the provider blocked;
- 1280-byte packets in both directions over each transport, to local and remote workloads and through NAT egress;
- an HTTP/3 request replaced by an HTTP/2 one on the same pod, and moved to a pod on the other edge node, never with two forwarding at once;
- local cutoff, local withdrawal and remote convergence measured separately, the last by polling the compute node's router through its GoBGP API;
- a live path MTU reduction during an HTTP/3 tunnel ([#1237](https://github.com/datum-cloud/galactic/issues/1237));
- each connector state of [the diagnostic workflow](troubleshooting.md#diagnose-a-masque-connector) as the provider's metrics and logs report it;
- a restart of the provider's node container (`scripts/restart-node.sh` restores the lab links the restart removes).

The [lab README](../../deploy/containerlab/README.md#masque-service) lists what the overlays change for the lab.
