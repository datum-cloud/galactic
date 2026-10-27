# Looking Glass service client

An independent client of the Looking Glass service, the API a cell's
fabric-api gateway serves to an authorized customer-facing service
([docs/designs/looking-glass-service.md](../../docs/designs/looking-glass-service.md)).
It is built from the published service API alone: its module imports only
`go.datum.net/galactic/api/fabric/service/v1` and `api/fabric/v1`, and its
module path lies outside `go.datum.net/galactic`, so the compiler refuses any
import of Galactic's internal packages. `task test:looking-glass-client`
builds and tests it and fails if it imports any other Galactic package.

The Looking Glass qualification (`task verify:looking-glass` in
`deploy/containerlab`, [docs/fabric-api/qualification.md](../../docs/fabric-api/qualification.md))
sends every request through this client.

## Identity

The client authenticates with a service certificate whose URI SAN is
`spiffe://fabric-api.datumapis.com/cell/<cell>/service/<name>`, issued by the
cell's fabric-api CA, for client auth. The gateway accepts it only when
`<name>` is in its `--service-identities`. The client accepts only a server
whose single URI SAN is `spiffe://fabric-api.datumapis.com/cell/<cell>/gateway`,
verified against `--ca`.

## Build

```sh
cd examples/looking-glass-client
CGO_ENABLED=0 go build -o looking-glass-client .
```

The module builds against the service API of the checkout it sits in
(`replace go.datum.net/galactic => ../..`). To pin a released API instead,
drop the `replace` and require the release's `go.datum.net/galactic` version.

## Use

Every subcommand takes `--addr` (the gateway, `host:port`), `--cell`, and the
service's `--cert`, `--key` and `--ca` PEM files. `--cert ""` presents no
client certificate.

| Subcommand     | Does                                                                                                                                   |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `capabilities` | Calls `GetCapabilities` and prints the response, or the refusal, as JSON.                                                              |
| `run`          | Runs one diagnostic and prints its record (below). `--events` also prints every event, payloads included, to stderr.                   |
| `load`         | Runs a workload spec over one connection; prints one record per attempt, then one summary per group. SIGINT ends it and keeps results. |
| `invoke`       | Calls any unary method with an empty request and prints its status, to show a method is closed to the service.                         |

```sh
looking-glass-client run --addr gateway:9346 --cell dfw --cert tls.crt --key tls.key --ca ca.crt \
  -project 7f1c0e2a -type Ping -target 2c0f:40::2   # the containerlab lab's probe destination
```

`run` takes the request's fields (`-project`, `-request-id`, `-type`,
`-target`, `-family`, `-nodes`, `-require`, `-api-major`, `-expires-in`,
`-request-cell`), a transport `-deadline`, and consumer behaviour:
`-read-delay` before each read, `-stop-reading-after N` events, and
`-cancel-after` a duration or `-cancel-after-events N`. `-metadata key=value`
adds request metadata. A `-type` of `enum:N` sends the raw query type N.

gRPC retries are off: the service must never replay an attempt.

## Records

A record holds what the consumer observed, never a diagnostic payload:

- `status`: the gRPC code, and from `google.rpc.ErrorInfo` the reason and
  metadata (`scope`, `execution_started`), and from `RetryInfo` the advised
  delay in milliseconds (`-1` when absent).
- `stream`: the stream checked against the contract's grammar and coverage
  rules. `delivered` is true only when a `complete` arrived, every rule held
  and the stream ended with gRPC OK; `violations` lists every broken rule;
  `pending` lists selected routers with no delivered outcome, whose result is
  unknown. Each outcome keeps its node, result, failure reason and scope.
- `timing`: milliseconds from the call's start to the first event, the
  snapshot, each outcome, the `complete`, a client cancellation, and the end.
- `bytes` and `maxEventBytes`: the serialized size of the stream and its
  largest event.

## Workload spec

`load --spec FILE` (`-` reads stdin) takes JSON:

```json
{
  "groups": [
    {
      "name": "burst",
      "count": 12,
      "concurrency": 12,
      "interval": "0s",
      "startAfter": "0s",
      "projects": ["p1", "p2", "p3"],
      "targets": ["2c0f:40::2"],
      "options": { "query": { "type": "Ping" }, "nodes": ["router-a"], "expiresIn": "30s" }
    }
  ]
}
```

Groups start together. A group runs `count` attempts, at most `concurrency`
at once, starting them `interval` apart after `startAfter`; attempts take
`projects` and `targets` in turn. `options` takes the `run` fields by their
JSON names (`query`, `nodes`, `expiresIn`, `deadline`, `requiredFeatures`,
`readDelay`, `stopReadingAfter`, `cancelAfterEvents`, `cancelAfter`,
`metadata`). Each group's summary counts attempts by status and terminal
reason and gives latency percentiles to the first outcome and the `complete`.
