# fabric-api load-test evidence, 2026-10-07

Historical measurements from one Docker host. These results are not current capacity claims or production qualification. Use the [maintained load-test procedure](../../fabric-api/load-test.md) to repeat the experiment against a candidate release.

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

- **Router.** FRR 10.7.1 (`quay.io/frrouting/frr:10.7.1`, the release used for this measurement) in
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

## Results

### Run A: direct FRR scans (`--search-source=frr`), IPv4 only

1,126,600 prefixes (`route-views2` has no IPv6).

| Phase             | bgpd CPU                   | Query latency and outcomes                                                                                                                                                                                                                                                                        | bgpd RSS         | Unplanned drops |
| ----------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | --------------- |
| baseline          |                            | Convergence after `clear bgp *`: 41.5 s                                                                                                                                                                                                                                                           |                  |                 |
| cheap             | 98.4 CPU-s (82% of a core) | `RouteLookup` n=266,593, p50 2 ms, p99 4 ms, max 15 ms. `BGPSummary` n=265,614, p50 2 ms, p99 4 ms                                                                                                                                                                                                | 1034 to 1087 MiB | 0               |
| expensive         | 120.9 CPU-s (101%)         | `ASPath` n=246: NodeBusy 219, OK 21, ResponseTooLarge 6; p95 3.0 s, p99 3.9 s, max 4.8 s. `Community` n=240: NodeBusy 196, OK 31, ResponseTooLarge 13; p99 3.6 s. `LargeCommunity` n=255: NodeBusy 212, OK 43; p99 4.2 s. `RouteLookup` p50 657 ms, p99 4.3 s. `BGPSummary` p50 661 ms, p99 4.2 s | flat             | 0               |
| expensive + reset | 133.8 CPU-s (112%)         | Convergence under load: 2 m 10.0 s, 3.1 times the idle 41.5 s. `RouteLookup` p50 1.13 s, p99 5.6 s                                                                                                                                                                                                |                  | 0               |

**Conclusion: fails the gate.** bgpd's main thread saturates under searches, cheap
queries that were 2 ms become seconds, convergence after a reset takes 3.1 times
longer, and a `ResponseTooLarge` answer still costs bgpd the whole scan. No sessions
dropped and memory stayed flat, but the convergence and starvation results rule out
enabling direct scans.

### Run B: BMP-fed index (default), IPv4 and IPv6

1,126,600 IPv4 and 263,799 IPv6 prefixes.

**Index build and footprint.** After the sidecar started, the index synced in 29.2 s,
costing bgpd 23.4 CPU-s once. It held 212,524 distinct attribute sets. The sidecar's
RSS was about 430 MB (Go heap in use about 370 MB); bgpd's RSS about 1.5 GB.

**Consistency.** 40 search targets (9 AS-path, 7 community and 4 large-community
targets, each for both families): the index's match counts equalled FRR's own
best-path matches for all 40.

| Phase             | bgpd CPU                                   | Query latency and outcomes                                                                                                                                                                | Unplanned drops |
| ----------------- | ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| baseline          |                                            | Convergence after `clear bgp *`: 41.7 s                                                                                                                                                   |                 |
| cheap             | 107 CPU-s (89% of a core)                  | `RouteLookup` n=212,655, p50 2 ms, p99 22 ms. `BGPSummary` n=212,686, p50 1 ms, p99 22 ms                                                                                                 | 0               |
| expensive         | 3.0 CPU-s (2%)                             | `ASPath` OK 201 (NodeBusy 5,344), p99 515 ms, max 715 ms. `Community` OK 219, p99 90 ms. `LargeCommunity` OK 192, p99 77 ms. `RouteLookup` p99 3 ms. `BGPSummary` p99 2 ms. bgpd RSS flat | 0               |
| expensive + reset | 34.1 CPU-s (28%, the reconvergence itself) | Convergence under load: 43.7 s, +5% over the idle 41.7 s. `ASPath` p99 920 ms. `RouteLookup` p99 186 ms                                                                                   | 0               |

The `NodeBusy` count for `ASPath` is the node's own budget at work: it runs one
search at a time with no queue, and 8 workers keep asking.

**Conclusion: passes** every criterion of the gate above: zero drops, convergence
within 10% of idle (+5%), no bgpd memory growth, and answers equal to FRR's
best-path answers. Searches cost bgpd nothing beyond the one-time
index build (23.4 CPU-s) and the BMP stream.

### Reading the numbers

- Cheap-query throughput in the cheap phase, about 1,700 to 2,200 queries per second
  per node, far exceeds what the gateway's 8 cell slots and NSO's rate limits allow
  to reach a node, so cheap queries are not a capacity concern.
- The runs measure one router in a Docker lab on one machine. They do not measure
  real fabric routers, real peer counts, or concurrent exporter and config-agent
  activity.
