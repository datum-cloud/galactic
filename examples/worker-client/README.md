# Worker client

An independent client of the Galactic Worker service API
([docs/worker/contract.md](../../docs/worker/contract.md)). It is built from the
published interface alone: its module imports only
`go.datum.net/galactic/api/galactic/worker/v1alpha1` and
`go.datum.net/galactic/pkg/workerclient`, and its module path lies outside
`go.datum.net/galactic`, so the compiler refuses any import of Galactic's
internal packages. `task test:worker-client` builds and tests it and fails if
it imports any other Galactic package.

`TestIndependentClient` in `internal/worker` builds this binary and runs its
lifecycle against a real Worker on a unix socket, with the real authentication
chain and a ServiceAccount allowed `local.veth_pair` only.

## Identity

The client presents its pod's projected ServiceAccount token, audience
`galactic-worker`, read from `--token-file` on every call. Worker accepts it
only from a process of the pod the token is bound to, on the same node, and
only for the capabilities its allowlist grants the ServiceAccount.

## Build

```sh
cd examples/worker-client
CGO_ENABLED=0 go build -o worker-client .
```

The module builds against the API of the checkout it sits in
(`replace go.datum.net/galactic => ../..`).

## Use

```sh
worker-client capabilities --socket /run/galactic-worker/worker.sock

worker-client lifecycle --node node-a --vpc <vpc-id> --attachment <attachment-uid> \
  --destination <uid> --update-destination <uid> \
  --handoff veth_pair --forbidden-handoff tap
```

`lifecycle` checks that the negotiated version is `v1alpha1` and that
`--handoff` is allowed. It then:

1. Requests the forbidden handoff and expects `PERMISSION_DENIED` with
   `CapabilityNotAllowed`.
2. Requests the claim at generation 1, then repeats the request as a duplicate.
3. Observes the claim until Worker reports on generation 1.
4. Updates the claim to generation 2 and observes until Worker reports on it.
5. Sends a stale release at generation 1 and expects `ABORTED`.
6. Releases at generation 2 and observes until the release is confirmed.
7. Releases again, which succeeds because the claim no longer exists.
