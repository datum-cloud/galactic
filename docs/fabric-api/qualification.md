# Qualify the Looking Glass service

The qualification suite (`tests/lgqualify`) runs the Looking Glass service on
real fabric routers through an independent client and checks every row of the
service contract's [acceptance matrix](../designs/looking-glass-service.md#acceptance-matrix-and-evidence)
against thresholds fixed before the run. Run it against a candidate build
before the service is switched on in a cell. Record each run's revision,
environment and results in the [archive](../archive/README.md#measurements),
next to earlier runs rather than over them.

A pass on the containerlab lab qualifies the code on the lab's routers. It is
not qualification of a production cell, whose routers, kernels, address plan
and load differ (see [Limits of a lab run](#limits-of-a-lab-run)).

## What it exercises

The client in `examples/looking-glass-client` is its own Go module and imports
only the published service API (`api/fabric/service/v1`, `api/fabric/v1`);
`task test:looking-glass-client` fails if it imports anything else. Every
service request in the suite goes through it, authenticated with a service
certificate, against the cell gateway's Service. Operator and `FabricQuery`
traffic goes through `fabric-api query` and the Kubernetes API, as those
callers use them.

| Scenario             | Rows     | Checks                                                                                                                                                                                              |
| -------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `preflight`          | A17      | Records the gateway's build, contract revision, limits and capabilities, every router, and the client's build                                                                                       |
| `authorization`      | A1, A2   | Missing, expired, unlisted, other-cell and operator credentials; a request naming another cell; every non-service method closed to the service identity; forged forwarding metadata ignored         |
| `compatibility`      | A7       | Unsupported API major, feature and query enum are refused, never downgraded                                                                                                                         |
| `diagnostics`        | A3, A6   | `RouteLookup`, `BGPSummary`, `Ping` and `Traceroute` in both families decode; loss, silent hops and no-route results stay observations                                                              |
| `coverage`           | A4, A5   | A fast router's outcome arrives while another is blocked; unreachable and omitted routers; explicit subsets keep `NotRequested` omissions                                                           |
| `destinations`       | A3       | Special-use, operator-allowed and malformed targets are refused with `INVALID_ARGUMENT` before the snapshot                                                                                         |
| `legacy`             | A16      | Operator gateway queries, direct operator probes (which now need a permit) and `FabricQuery` still work; a direct probe works again within 30 s of its node's `fabric-api-certs` pod being replaced |
| `bursts`             | A8       | Cell and project bursts admit no more than their bursts allow; refusals are `Throttled` with scope and retry delay                                                                                  |
| `fairness`           | A8       | A slow project is never refused while a fast one saturates its own rate; project slot caps hold                                                                                                     |
| `destination-budget` | A9, A10  | Emitted packets per destination host, counted on every node, stay within `B + r(T + 32)` in every window; operator and `FabricQuery` probes are throttled by the same buckets                       |
| `cancellation`       | A12      | Probe packets stop within 2 s of a client cancel                                                                                                                                                    |
| `deadline`           | A12      | A request ends `DeadlineExceeded` and its packets stop within 2 s of `expires_at`                                                                                                                   |
| `service-switch`     | A12, A15 | Switching the service off ends running streams `Cancelled` and stops packets within 3 s                                                                                                             |
| `blackhole`          | A12      | A client whose connection silently stops passing packets releases its streams within 12 s                                                                                                           |
| `routing-impact`     | A17      | 40 control and 40 loaded convergence trials of one hard-reset BGP session; no other session resets under load                                                                                       |
| `leader-crash`       | A11, A14 | After the leader is killed, the new leader admits nothing for 125 s and resumes within 134 s; the old leader's work emits nothing after its dispatch plus 32 s                                      |
| `leader-pause`       | A14      | The same bounds when the leader is paused (SIGSTOP) and later resumed                                                                                                                               |
| `api-isolation`      | A11, A14 | A leader cut off from the API server stops dispatch within 2 s of detecting it                                                                                                                      |
| `resources`          | A13, A17 | Peak gateway and sidecar memory and goroutines stay within their container limits and 512 goroutines above baseline                                                                                 |
| `confidentiality`    | A15, A17 | No service target or project in routine gateway or sidecar log lines, nor in any metric label                                                                                                       |
| `cleanup`            | A17      | No injected `DROP` rule remains on a node or in a gateway pod, and every gateway and `fabric-router` pod is Ready within 6 minutes                                                                  |

The thresholds are constants in `tests/lgqualify/thresholds_test.go`, taken
from the contract's [defaults and bounds](../designs/looking-glass-service.md#initial-defaults-and-hard-bounds).
A failure against one is a qualification failure. Change a threshold only with
a contract revision, never to make a run pass. The routing-impact gate passes
when the loaded p95 convergence time is at most 1.10 times the control p95. It
is inconclusive, which is not a pass, when the control p95's bootstrap 95 %
confidence half-width exceeds 10 % of it.

## Running it on the lab

Prerequisites: the containerlab lab deployed with `task deploy` (which includes
`deploy:cert-manager` and `deploy:fabric-api`), and an unchanged working tree,
since the image records its commit as the gateway's contract revision.

From `deploy/containerlab/`:

```sh
# Builds fabric-api from the checkout, loads it on dfw's nodes, and enables the
# service on dfw in the documented order. Restarts dfw's FRR twice.
task deploy:looking-glass

# About 45 minutes. Kills, pauses and isolates the gateway leader, and resets
# one of dfw-worker's BGP sessions 80 times.
task verify:looking-glass

# Switches the service off and walks the enabling steps back. Restarts dfw's
# FRR twice. Then check the existing interfaces after the rollback.
task undeploy:looking-glass
task verify:fabric-api
```

`verify:looking-glass` writes one JSON file per scenario, with its rows,
thresholds, observations and outcome, and the raw per-request records, to
`bin/lg-qualify/<UTC timestamp>/` at the repository root. The test log names
the directory. The run ends with `cleanup`; if it is interrupted before then,
run `task undeploy:looking-glass` and check that no gateway pod keeps a `DROP`
rule for ports 443 or 6443 in its network namespace.

The overlays `deploy:looking-glass` applies are in
`deploy/containerlab/resources/looking-glass/`. tr4 announces `2c0f:40::/64`
for the off-fabric host and drops `11.1.42.0/24` and `2c0f:42::/64` silently,
since the public probe policy refuses documentation addresses; see
[the lab README](../../deploy/containerlab/README.md).

## Limits of a lab run

- Direct operator probes are judged on dfw-worker only. The lab's edge nodes'
  host network reaches neither the cluster DNS server nor the gateway Service,
  so their sidecars cannot ask the gateway for permits. A production edge node
  must reach the gateway Service before `components/fabric-api-require-permits`
  is applied.
- The lab's routers carry a few hundred routes, not full tables, and every node
  shares one host's CPU. The [full-table load test](load-test.md) covers FRR
  under real table sizes.
- With the default limits, a three-router traceroute toward a silent
  destination from one project times out one router as `QueueTimeout` after
  10 s, since a project holds at most two node slots. The contract requires
  qualification to report this default.
