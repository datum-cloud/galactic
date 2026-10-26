# fabric-api configuration reference

For installation use [deployment](deployment.md); for certificate identities use [security](security.md); for rollout, verification and troubleshooting use [operations](operations.md). The [FabricQuery reference](api.md) defines request and result semantics.

The [Looking Glass service contract](../designs/looking-glass-service.md) describes future behavior beyond the currently available operator and FabricQuery interfaces.

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
| `--probe-permits`              |                          | `false`                           | Verify and enforce the gateway's probe permits, and report `probePermits` in `Info`. Needs API access; see [Aggregate probe budgets](#aggregate-probe-budgets)  |
| `--require-probe-permits`      |                          | `false`                           | With `--probe-permits`, refuse any probe without a permit; a direct operator's probe first obtains one from `--gateway-address`                                 |
| `--gateway-address`            |                          |                                   | `host:port` of the cell gateway's gRPC service, from which direct operator probes obtain permits. Required by `--require-probe-permits`                         |
| `--gateway-lease-name`         |                          | `fabric-api-gateway`              | The gateway's election lease, read uncached in `--namespace` to verify each permit's epoch                                                                      |

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
FRR, so it follows [Rollout](operations.md#rollout).

### `fabric-api gateway`

| Flag                                  | Env                                  | Default                                                | Meaning                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------- | ------------------------------------ | ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--site`                              | `SITE`                               |                                                        | Site this cell serves. Required                                                                                                                                                                                                                                                                                             |
| `--cluster-name`                      | `CLUSTER_NAME`                       |                                                        | This cell's Karmada member cluster name. Required                                                                                                                                                                                                                                                                           |
| `--cell`                              | `CELL`                               |                                                        | Cell name in the mTLS identities. Required                                                                                                                                                                                                                                                                                  |
| `--namespace`                         | `POD_NAMESPACE`                      | `galactic-system`                                      | Namespace of the `fabric-router` pods, the election lease and this pod                                                                                                                                                                                                                                                      |
| `--pod-name`                          | `POD_NAME`                           |                                                        | This pod's name. Required                                                                                                                                                                                                                                                                                                   |
| `--debug-bind-address`                |                                      |                                                        | Address the debug service binds to. Empty binds every address in the pod's network namespace, which a port-forward (through the pod's loopback) and the Service both need                                                                                                                                                   |
| `--pod-selector`                      |                                      | `app.kubernetes.io/name=fabric-router`                 | Label selector of `fabric-router` pods                                                                                                                                                                                                                                                                                      |
| `--certs-selector`                    |                                      | `app.kubernetes.io/name=fabric-api-certs`              | Label selector of the per-node `fabric-api-certs` pods whose identity each sidecar presents                                                                                                                                                                                                                                 |
| `--lease-name`                        |                                      | `fabric-api-gateway`                                   | Leader election lease name                                                                                                                                                                                                                                                                                                  |
| `--debug-port`                        |                                      | `9346`                                                 | Operator debug gRPC port                                                                                                                                                                                                                                                                                                    |
| `--metrics-bind-address`              |                                      | `:9347`                                                | Address serving `/metrics`                                                                                                                                                                                                                                                                                                  |
| `--health-probe-bind-address`         |                                      | `:8081`                                                | Address serving `/healthz` and `/readyz`                                                                                                                                                                                                                                                                                    |
| `--tls-cert`, `--tls-key`, `--tls-ca` | `FABRIC_API_TLS_CERT`, `_KEY`, `_CA` | `/var/run/fabric-api/tls/tls.crt`, `tls.key`, `ca.crt` | As for the node                                                                                                                                                                                                                                                                                                             |
| `--cell-slots`                        |                                      | `8`                                                    | Node RPCs running at once across all queries                                                                                                                                                                                                                                                                                |
| `--cell-expensive-slots`              |                                      | `2`                                                    | Of those, expensive searches                                                                                                                                                                                                                                                                                                |
| `--cell-queue`                        |                                      | `256`                                                  | Node RPCs that may wait for a slot                                                                                                                                                                                                                                                                                          |
| `--max-nodes`                         |                                      | `32`                                                   | Nodes one query executes on in this cell (ceiling 32)                                                                                                                                                                                                                                                                       |
| `--max-object-bytes`                  |                                      | `393216` (384 KiB)                                     | Serialized `FabricQuery` size ceiling (ceiling 384 KiB)                                                                                                                                                                                                                                                                     |
| `--max-node-response-bytes`           |                                      | `131072` (128 KiB)                                     | Node response ceiling (ceiling 128 KiB)                                                                                                                                                                                                                                                                                     |
| `--max-in-flight`                     |                                      | `256`                                                  | Queries executing at once; more wait for a requeue                                                                                                                                                                                                                                                                          |
| `--retention`                         |                                      | `1h`                                                   | Retention the stale-object count assumes; keep equal to the janitor's `--retention`                                                                                                                                                                                                                                         |
| `--cleanup-grace`                     |                                      | `15m`                                                  | Cleanup grace the stale-object count assumes; keep equal to the janitor's `--grace`                                                                                                                                                                                                                                         |
| `--service-identities`                |                                      |                                                        | Comma-separated names of the Looking Glass service identities allowed to call this gateway. Empty allows none                                                                                                                                                                                                               |
| `--aggregate-budgets`                 |                                      | `false`                                                | Enforce the cell's aggregate admission and probe packet budgets on every caller and issue probe permits. Requires `--cell-slots` at most 8; a principal's share is 2 slots and 32 queued jobs, lowered to `--cell-slots` and `--cell-queue` when those are smaller. See [Aggregate probe budgets](#aggregate-probe-budgets) |

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

## Aggregate probe budgets

Without `--aggregate-budgets` the cell executor above and each node's packet
pacer are the only limits, and they are local: nothing bounds how many probe
packets the cell as a whole sends to one destination. With it, the leader
gateway holds every budget of the
[service contract](../designs/looking-glass-service.md#admission-execution-and-aggregate-accounting)
in memory and charges every probe, whoever asked for it:

| Budget                                 | Default                    | Charged to                                                          | When exhausted                     |
| -------------------------------------- | -------------------------- | ------------------------------------------------------------------- | ---------------------------------- |
| Service requests, cell / project       | 2/s burst 8, 0.2/s burst 2 | Each `RunDiagnostic`                                                | `Throttled` with `RetryInfo`       |
| Probe packets, cell                    | 100/s burst 640            | Every probe's worst case: ping 3, traceroute 20                     | The router's job fails `Throttled` |
| Probe packets, principal               | 20/s burst 640             | Per service project, `FabricQuery` source or operator               | As above                           |
| Probe packets, destination host/prefix | 20/s and 40/s, burst 640   | The destination's /32 or /128, and its /24 or /64                   | As above                           |
| Node jobs at once, per principal       | 2                          | Every node call                                                     | Queued                             |
| Queued node jobs, per principal        | 32                         | Every node call; a service request reserves all its routers at once | `QueueFull`                        |
| Live service streams, cell / project   | 16 / 2                     | Each `RunDiagnostic`                                                | `QueueFull`                        |

Principals are the service request's project, a `FabricQuery`'s
`fabricquery/<source.namespace>/<source.cluster>`, and `operator/<name>` for an operator. A probe an
operator sends a node directly is charged to the operator only on a node that
runs both `--probe-permits` and `--require-probe-permits`. Nothing
charged is refunded. Reads (route lookups, BGP summaries) take a node slot but
no packets. The leader confirms it holds the election Lease, reading it uncached,
before every admission and probe, and once a second besides. After it starts,
acquires the election or fails to read the Lease it admits no probe and no
service request for 125 seconds, then starts every bucket empty. A gateway
restart or failover therefore stops operator and `FabricQuery` probes for about
two minutes; reads are unaffected.

Each probe carries a permit, bound to the Lease's epoch, its node, request,
destination and worst-case packets and a deadline at most 30 seconds away. A
node with `--probe-permits` consumes each permit once, re-reads the Lease to
confirm the epoch, and sends nothing past the permit's packets or deadline. It
refuses every permit for 32 seconds after it starts. The gateway sends a probe
only to a node whose `Info` reports `probePermits`; any other node's job fails
`QueryTypeUnavailable`. With `--require-probe-permits`, a node also refuses a
probe without a permit, and a probe an operator sends it directly first obtains
one from the gateway's `RequestPermit`, charged to that operator.

When a probe's node call ends without the node's answer, its slot stays held
until the job's deadline plus 2 seconds, since the node may still be sending
it. The rates and caps are the contract's defaults; only `--cell-slots` and
`--cell-queue` change them.

### Stream delivery and transport bounds

Every gateway replica bounds Looking Glass service delivery, whether or not
`--aggregate-budgets` is set. None of these values is configurable:

| Bound                                                                                        | Value                              | Past it                                                                                   |
| -------------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------- |
| One write to the consumer, or a finished outcome waiting for the stream's two-outcome buffer | 2 s                                | The request is cancelled and its stream ends `CANCELLED`; its routers stop                |
| One outcome event                                                                            | 144 KiB                            | The router's outcome is a `ResponseTooLarge` failure                                      |
| Serialized events of one stream                                                              | 5 MiB                              | That router and every router still running fail `OutputLimitExceeded`, as does `complete` |
| `RunDiagnostic` calls / forwarded calls                                                      | 32 / 16 per replica                | `QueueFull` with a 1 s retry delay                                                        |
| Service identity TLS connections                                                             | 64 per replica                     | The connection is closed after its handshake                                              |
| A silent connection                                                                          | Pinged after 4 s, closed 4 s later | Its calls are cancelled                                                                   |

Every connection to the listener, and a follower's connection to the leader,
uses fixed 64 KiB flow-control windows and buffers. A follower relays one event
at a time under the same 2 s write bound, and never forwards a call twice. A
client may ping no more often than every 5 seconds. On `SIGTERM` the gateway
closes its listener's connections at once, cancelling operator and service
calls in flight.

To turn the budgets on, follow [Enabling aggregate probe budgets](operations.md#enabling-aggregate-probe-budgets).

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


## Moved sections

These anchors keep older bookmarks working. Use the focused guides linked above for new references.

<a id="deploy-fabric-api"></a>

[deploy fabric api](deployment.md#deploy-fabric-api).

<a id="what-you-deploy"></a>

[what you deploy](deployment.md#what-you-deploy).

<a id="prerequisites"></a>

[prerequisites](deployment.md#prerequisites).

<a id="why-certificates-are-issued-in-a-separate-pod"></a>

[why certificates are issued in a separate pod](deployment.md#why-certificates-are-issued-in-a-separate-pod).

<a id="deployment"></a>

[deployment](deployment.md#deployment).

<a id="step-1-cell-wide-rbac-and-serviceaccounts"></a>

[step 1 cell wide rbac and serviceaccounts](deployment.md#step-1-cell-wide-rbac-and-serviceaccounts).

<a id="step-2-per-cell-configmap"></a>

[step 2 per cell configmap](deployment.md#step-2-per-cell-configmap).

<a id="step-3-the-gateway-and-janitor"></a>

[step 3 the gateway and janitor](deployment.md#step-3-the-gateway-and-janitor).

<a id="step-4-the-node-sidecar-component-as-a-canary"></a>

[step 4 the node sidecar component as a canary](deployment.md#step-4-the-node-sidecar-component-as-a-canary).

<a id="lab"></a>

[lab](deployment.md#lab).

<a id="fabric-api-identities-and-probe-policy"></a>

[fabric api identities and probe policy](security.md#fabric-api-identities-and-probe-policy).

<a id="identities-and-certificates"></a>

[identities and certificates](security.md#identities-and-certificates).

<a id="operator-certificates"></a>

[operator certificates](security.md#operator-certificates).

<a id="service-certificates"></a>

[service certificates](security.md#service-certificates).

<a id="rotation"></a>

[rotation](security.md#rotation).

<a id="probe-sources-and-destinations"></a>

[probe sources and destinations](security.md#probe-sources-and-destinations).

<a id="source"></a>

[source](security.md#source).

<a id="destination"></a>

[destination](security.md#destination).

<a id="operate-fabric-api"></a>

[operate fabric api](operations.md#operate-fabric-api).

<a id="observability"></a>

[observability](operations.md#observability).

<a id="rollout"></a>

[rollout](operations.md#rollout).

<a id="verifying"></a>

[verifying](operations.md#verifying).

<a id="troubleshooting"></a>

[troubleshooting](operations.md#troubleshooting).
