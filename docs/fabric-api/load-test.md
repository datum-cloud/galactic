# Run the fabric-api full-table load test

The harness checks whether diagnostics disturb routing and whether indexed searches agree with FRR. Run it against a candidate release before enabling expensive queries on real fabric routers. The [October 7 measurements](../archive/benchmarks/fabric-api-2026-10-07.md) explain the choice of a BMP-fed index; they are historical evidence, not a fresh capacity measurement.

## Purpose

A search such as an AS-path regular expression traverses the whole BGP table, and
neither a client cancellation nor a response byte cap proves that bgpd stopped
computing. Before searches can be enabled anywhere, a representative full-table load
test must show:

- no query-induced BGP session loss;
- no bgpd memory growth caused by searches;
- routing convergence after a session reset within an agreed budget of the same
  event with no diagnostics running; and
- (added by this test) search answers equal to what FRR itself would answer.

## Gate, as measured here

This is a proposal for infra to adopt; the numeric budget was not fixed before the
test. A configuration passes when, with full IPv4 and IPv6 Internet tables:

1. zero unplanned BGP session drops in every phase;
2. convergence after a session reset under search load within 10% of the idle
   baseline;
3. no bgpd memory growth from searches; and
4. search answers equal FRR's own best-path answers.

## Method

The harness is `hack/fabric-api-loadtest` (Go). It needs Docker and about 4 GiB of
memory, and removes its containers and network on exit.

- **Router.** FRR 10.7.1 (`quay.io/frrouting/frr:10.7.1`, the harness default at the time of the recorded measurement) in
  Docker, with bgpd and zebra.
- **Feeder.** A GoBGP container injects the best paths of RouteViews MRT RIB dumps
  over one IPv4 and one IPv6 eBGP session. One pass per address family, with the
  next hop overridden. Inputs: RouteViews
  `route-views2` `rib.20261007.0000` (IPv4) and `route-views6`
  `rib.20261007.0000` (IPv6). `route-views2` carries no IPv6 table, so IPv6 comes
  from the second file.
- **System under test.** The real `fabric-api node` sidecar beside that FRR, driven
  over mTLS as an operator by 8 concurrent workers (`--concurrency`).
- **Phases**, each 2 minutes (`--duration`) after loading the table:
  1. *baseline*: convergence time after `clear bgp *` with no queries running;
  2. *cheap*: `RouteLookup` and `BGPSummary`;
  3. *expensive*: adds `ASPath`, `Community` and `LargeCommunity` searches, within
     the node's own budgets;
  4. *expensive + reset*: a session reset while the expensive load runs.
- **Measurements.** Per query type: latency percentiles and outcome codes. For
  bgpd: CPU seconds and RSS, sampled from `/proc`. Unplanned session drops, from the
  peers' `connectionsDropped` counters, other than the harness's own resets.
- **Consistency check** (index runs only): the index's counts are compared with
  FRR's own best-path matches for a fixed set of search targets.

### Running it

From the repository root:

```sh
task test:fabric-api-load MRT=<rib-file>[,<rib-file>...] -- [flags]
```

`MRT` is one or more uncompressed `TABLE_DUMP_V2` RIB files, comma-separated, for
example `MRT=rib.20261007.0000,rib6.20261007.0000`. The task builds `gobgpd` and
`gobgp` v4.10.0 into the local bin directory and runs the harness. Flags after `--`
go to the harness:

| Flag              | Default                        | Meaning                                                         |
| ----------------- | ------------------------------ | --------------------------------------------------------------- |
| `--mrt`           |                                | The RIB files (set by the task from `MRT`)                      |
| `--gobgp-bin`     |                                | Directory holding static `gobgpd` and `gobgp` (set by the task) |
| `--frr-image`     | `quay.io/frrouting/frr:10.7.1` | FRR image                                                       |
| `--count`         | `0`                            | Inject at most this many MRT entries; 0 injects all             |
| `--duration`      | `2m`                           | Length of each workload phase                                   |
| `--concurrency`   | `8`                            | Concurrent query workers                                        |
| `--out`           | `fabric-api-loadtest.json`     | Where to write the JSON report                                  |
| `--keep`          | `false`                        | Leave the containers running                                    |
| `--search-source` | `index`                        | The sidecar's `--search-source`: `index` or `frr`               |

In the [archived measurements](../archive/benchmarks/fabric-api-2026-10-07.md), Run A uses `--search-source=frr`; Run B uses the default index.

## Status of searches

Searches remain off by default (`--enable-expensive-queries`). Enabling them is an
infra rollout step, taken after staging confirms these numbers on real fabric
routers, and it requires each node's `frr.conf` to stream its Loc-RIB to the sidecar
(see [configuration.md](configuration.md#search-index)). The containerlab lab
enables them, and `task verify:fabric-api` checks searches against FRR's own answer.

## Moved sections

These anchors keep older bookmarks working. Use the focused guides linked above for new references.

<a id="fabric-api-load-test-evidence-2026-10-07"></a>

[fabric api load test evidence 2026 10 07](../archive/benchmarks/fabric-api-2026-10-07.md#fabric-api-load-test-evidence-2026-10-07).

<a id="results"></a>

[results](../archive/benchmarks/fabric-api-2026-10-07.md#results).

<a id="run-a-direct-frr-scans---search-sourcefrr-ipv4-only"></a>

[run a direct frr scans   search sourcefrr ipv4 only](../archive/benchmarks/fabric-api-2026-10-07.md#run-a-direct-frr-scans---search-sourcefrr-ipv4-only).

<a id="run-b-bmp-fed-index-default-ipv4-and-ipv6"></a>

[run b bmp fed index default ipv4 and ipv6](../archive/benchmarks/fabric-api-2026-10-07.md#run-b-bmp-fed-index-default-ipv4-and-ipv6).

<a id="reading-the-numbers"></a>

[reading the numbers](../archive/benchmarks/fabric-api-2026-10-07.md#reading-the-numbers).
