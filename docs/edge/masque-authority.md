# MASQUE grant authority

`internal/edge/masque/authority` and `cmd/masque-authority` authenticate MASQUE connector credentials and issue the finite `EdgeService` of each connector authorization. The [MASQUE provider adapter](masque-provider.md) consumes them through `authority.Client`, its `masque.Authorizer`. The design is in the [MASQUE connector contract](../designs/masque/contract.md#authority-and-durable-allocations). This page covers what is built and how to operate it. `.github/workflows/publish.yaml` publishes its image, `ghcr.io/datum-cloud/masque-authority`, and `config/masque` deploys it ([deployment](masque-service.md#deployment)).

The authority runs under its own ServiceAccount. It holds no provider token and no host access. The provider can't write grant records, ledgers or EdgeServices; it receives each grant from the authority.

## State

All state is in the API. The authority keeps nothing in memory between calls, so a restarted or second instance rereads everything before it issues anything.

| Object                                  | Where                          | Written by             | Holds                                                                                                                                                                                     |
| --------------------------------------- | ------------------------------ | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Grant record `masque-grant-<UUID>`      | Secret, authority namespace    | `grant` commands       | Connector UUID, cell, VPC namespace/name/UID, credential revision, SHA-256 digest of the credential, expiry (at most 24 h), enabled flag, at most 64 allowed destinations, traffic policy |
| Ledger `masque-ledger-<VPC UID>-<cell>` | ConfigMap, authority namespace | `ledger init`, `grant` | The VPC's connector /80 and pool /80, and one entry per connector: allocation UUID, /96, /120 pool, creation time, retired flag                                                           |
| `EdgeService masque-<UUID>`             | The VPC's namespace            | `serve`                | One authorization incarnation: the /96 as its only prefix, the /120 as `clientPool`, `validUntil`, and annotations naming the authorization, pod UID, revision, nonce and cell            |

The credential itself is never stored, logged or returned after the command that created it. A ledger holds at most 256 entries. Every ledger and record write carries the read's UID and resourceVersion, so a concurrent writer or a recreated object makes the write fail rather than overwrite. A retired ledger entry is a tombstone: its /96 and pool are never allocated again. A missing ledger refuses every allocation until the operator restores it.

## Calls

Provider pods call `serve` over HTTPS (TLS 1.3) at `POST /v1/authorize`, `/v1/refresh` and `/v1/retire`. Each call presents the pod's projected ServiceAccount token for audience `masque-authority`. The authority reviews it with a `TokenReview` and accepts only a token bound to one pod of `--provider-service-account`. Each call has a 2 s budget, and every read it makes is uncached.

| Call        | Succeeds when                                                                                                                                                                                                                                                           | Effect                                                                                                                                                                                         |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authorize` | The credential's digest matches one record (compared in constant time against every record), the credential is unexpired, the record is enabled and in this cell, the VPC selector `namespace/name` matches, the VPC has the record's UID, and the ledger entry is live | Returns the pod's current incarnation, renewed, if it has one under this revision. Otherwise retires every other incarnation of the connector and issues a new one once core has released them |
| `refresh`   | The incarnation is the calling pod's, unretired and unexpired, issued under the record's current revision, and the record, VPC and ledger entry still pass                                                                                                              | Moves `validUntil` forward. A refusal also retires the incarnation                                                                                                                             |
| `retire`    | The incarnation is the calling pod's                                                                                                                                                                                                                                    | Marks it retired and sets `validUntil` in the past. Retiring one already deleted succeeds                                                                                                      |

An issued or renewed `validUntil` is the credential's expiry or the grant read's start plus 28 s (30 s less a 2 s issuer allowance), whichever is earlier, rounded down to the second. Core and galactic-edge stop the connector 2 s (MaxSkew) before it. The adapter refreshes every 5 s, so a renewal comes well before that cutoff. Renewing in place is a new EdgeService generation, and core keeps the attachment, route and epoch across it (`TestAgainstCore/renewing_the_service_keeps_forwarding`).

Answers map to HTTP status as follows. 401 is unauthenticated: an unknown, malformed or expired credential, or a caller that is not a provider pod. 403 is forbidden: a disabled connector, another VPC or cell, a recreated VPC, a retired allocation or authorization, or a stale revision. 400 is a malformed call. 503 means the authority couldn't decide now and issued nothing.

### Retries and replacement

Each `authorize` call carries a random nonce and the time it was first sent. A retry resends both. The authority refuses a call sent more than 10 s ago (`RetryWindow`) or more than 2 s in the future. A retired incarnation is deleted only after `RetryWindow` has passed and core has released every client-pool address it held (`status.allocations` empty). A retry therefore either finds the incarnation it created, or is refused as stale. It never creates a second one.

A connector's pool is the same in every incarnation, and core refuses the attachments of the later of two services with overlapping pools. Replacement is therefore sequential:

1. Retire the old incarnation, which ends its forwarding at core and galactic-edge.
2. Wait for core to release its attachments and for `RetryWindow` to pass.
3. Delete it.
4. Issue the successor.

Until then, `authorize` answers 503 and the client retries. An incarnation is named for its connector, and the authority creates one only after every other incarnation of the connector is gone. Pods racing to issue therefore contend for one name: the API server accepts one create, and the others get 503. The UID tells successive incarnations of one name apart. After each create or renewal, the authority rereads the grant record. If the record was rotated, disabled or deleted in the meantime, it retires the incarnation and answers 403.

### Revocation

`serve` sweeps every second (`--sweep-interval`), and only touches incarnations its own cell issued. An unretired incarnation is retired when:

- its record is deleted, disabled or expired;
- its record is at another revision; or
- its `validUntil` has passed without renewal.

Retired incarnations that core has released are deleted after `RetryWindow`. The provider learns of a revocation from its next `refresh` (403), at most 5 s later. The service's `validUntil` is the backstop if the provider, the authority or the API stalls: no packets 31 s after a committed revocation, or 1 s after credential expiry. Revocation push notifications are not built. Revoking one connector never touches another connector's incarnation, and the shared instance Lease keeps renewing.

## Operator tasks

All commands take `--namespace` (or `POD_NAMESPACE`) for the authority namespace and use the caller's kubeconfig.

```sh
# Once per VPC and cell: reserve a connector /80 and a pool /80 inside the VPC.
masque-authority ledger init --vpc tenant/vpc --cell cell-1 \
  --connectors fd20:a1b:2c3d:10:1::/80 --pools fd20:a1b:2c3d:10:2::/80

# Create a test connector. The credential is printed once, as JSON.
masque-authority grant create --vpc tenant/vpc --cell cell-1 --lifetime 12h \
  --route fd20:a1b:2c3d::/48 --ingress-policy allow-in --egress-policy allow-out

masque-authority grant rotate  <connector>   # new credential, next revision
masque-authority grant disable <connector>   # revoke; the allocation is kept
masque-authority grant retire  <connector>   # revoke and tombstone the allocation
```

`ledger init` refuses ranges that aren't masked IPv6 /80s inside one of the VPC's networks, or that overlap each other. It also refuses ranges that overlap those of another cell's ledger for the same VPC, so two cells are never handed overlapping /80s. And it refuses while any EdgeService the authority issued for the VPC in that cell still exists, so a recreated ledger can't hand out a /96 or pool that one still holds. Issued services of other cells don't block it. Choose ranges that overlap no workload subnet; core refuses a delegated route that does.

`grant create` allocates the /96 before it writes the grant record. If the record write fails, the error names the connector and its /96. Run `grant create` again with `--connector <connector>` to keep that /96, or `grant retire <connector>` to tombstone it. A plain retry allocates another /96. If the error says the connector already has a grant record, the write succeeded but its reply was lost: run `grant rotate <connector>` for a credential.

Run the server with:

```sh
masque-authority serve --provider masque --provider-service-account edge/masque --cell cell-1 \
  --tls-cert /etc/masque-authority/tls/tls.crt --tls-key /etc/masque-authority/tls/tls.key
```

It rereads the certificate and key when either file changes. `authority.Client` rereads its CA bundle when it changes, so roots can rotate with an overlap and no restart.

The authority's ServiceAccount needs these permissions:

- get, list, create and update on Secrets and ConfigMaps in its namespace;
- get, list, create, update and delete on `edgeservices`, and get on `vpcs`, in each tenant namespace it serves;
- list on `edgeservices` across the cluster, for the sweep;
- create on `tokenreviews`.

The provider's ServiceAccount needs none of these.

The conformance fixture uses the authority when its configuration sets `grantAuthority` (`url`, `caFile`, `tokenFile`) in place of `services` and `connectors`.

## Verification

- `go test ./internal/edge/masque/authority/` runs the ledger unit tests. With `KUBEBUILDER_ASSETS` set, `TestAuthority` runs against a real API server. It covers:
  - admission and every refusal;
  - retries and the retry window;
  - takeover after release, and racing pods;
  - rotation, credential expiry, revocation and the sweep;
  - an unavailable store;
  - recreated VPCs and ledgers;
  - credentials staying out of logs.

  `TestOverHTTPS` runs `authority.Client` against `Server` on TLS 1.3.
- `go test ./internal/edge/masque/ -run TestAgainstCore` includes the in-place renewal check against core.
- `task verify:masque-service` runs the authority with the [MASQUE service](masque-service.md#verification) in the lab. It creates ledgers and grants with the operator commands, and measures `grant disable` and credential expiry against forwarding over HTTP/3.

Not yet covered: the same measurements over the HTTP/2 transport ([#981](https://github.com/datum-cloud/galactic/issues/981)).
