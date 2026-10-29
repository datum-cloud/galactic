# Looking Glass qualification, 2026-10-27

One run of the [qualification procedure](../../fabric-api/qualification.md) on the containerlab lab. It qualifies the code at the commit below on the lab's routers. It is not qualification of a production or staging cell, and it is not a current capacity claim.

## Run

| Item            | Value                                                                                                                                                                                                                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Code under test | Commit `980cc91c` of the branch that added the suite, before its final rebase. The fabric-api image was built from a clean tree at it. The published commits differ from it only in documentation, one gateway unit test, the lab task's output directory and a comment in the lab's fabric deploy script |
| Window          | 2026-10-27, 17:59 to 18:23 UTC (1427 s)                                                                                                                                                                                                                                                                   |
| Cell            | dfw: three fabric routers running FRR 10.7.1, two gateway replicas                                                                                                                                                                                                                                        |
| Limits          | The contract's defaults, as the gateway reported them: cell requests 2/s burst 8, project 0.2/s burst 2, destination host 20 packets/s burst 640, 8 node slots per cell and 2 per project, 10 s queue wait                                                                                                |
| Result          | 21 of 21 scenarios passed, none skipped                                                                                                                                                                                                                                                                   |

After the run, `undeploy:looking-glass` rolled the cell back and `verify:fabric-api` checked the existing interfaces on every site.

## Results by acceptance row

| Row | Scenarios                                                 | Measured                                                                                                                                                            |
| --- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A1  | `authorization`                                           | Only the listed same-cell service identity was served, on new and reused connections and after its certificate rotated                                              |
| A2  | `authorization`                                           | Forged forwarding metadata was ignored, and the request was attributed to the authenticated service                                                                 |
| A3  | `diagnostics`, `destinations`                             | All four operations in both families decoded in the independent client. Every special-use and malformed target was refused before the snapshot                      |
| A4  | `coverage`                                                | Reachable routers' outcomes arrived within 21 ms. The unreachable router's failure arrived at 10.5 s                                                                |
| A5  | `coverage`                                                | Duplicate, unknown, omitted and explicitly unselected routers were counted exactly. Selecting 33 routers was refused                                                |
| A6  | `diagnostics`                                             | Loss, silent hops, no route and a queue timeout after the snapshot stayed distinguishable from backend failures                                                     |
| A7  | `compatibility`                                           | An unsupported API major, query enum and required feature were each refused, never downgraded                                                                       |
| A8  | `bursts`, `fairness`                                      | 8 of 12 concurrent projects and 2 of 5 same-project requests were admitted. The slow project was never refused while the fast one was refused 47 times in 60        |
| A9  | `destination-budget`                                      | 193 packets were emitted to one host. The worst window was 1280 packets under the `640 + 20(T + 32)` bound                                                          |
| A10 | `destination-budget`                                      | Once the service drained the host's bucket, operator and FabricQuery traceroutes to it were throttled by the same bucket                                            |
| A11 | `leader-crash`, `api-isolation`                           | The new leader first admitted 132.3 s after acquiring, inside the 125 to 134 s window, and sent no probe during the hold                                            |
| A12 | `cancellation`, `deadline`, `service-switch`, `blackhole` | Packets stopped before the trigger, or within 0.24 s of the switch and 4.2 s of the blackhole. Bounds 2 s, 3 s and 12 s                                             |
| A13 | `resources`                                               | Peak RSS was 57 MiB of 512 MiB for the gateway and 49 MiB of 768 MiB for a sidecar. Goroutines peaked 56 above baseline                                             |
| A14 | `leader-pause`, `api-isolation`                           | A paused leader sent no packet after resuming. An isolated leader detected the loss in 1.9 s and its running work ended `OwnershipLost`                             |
| A15 | `service-switch`, `confidentiality`                       | No target or project appeared in a routine log line or a metric label                                                                                               |
| A16 | `legacy`, rollback                                        | Operator and FabricQuery queries worked with the service on and after rollback. A direct probe worked 9.1 s after its node's certificate pod was replaced           |
| A17 | `preflight`, `routing-impact`, `resources`, `cleanup`     | Loaded p95 convergence was 3307 ms against a control p95 of 3309 ms (ratio 1.00, control half-width 2.4 ms), with no other session reset. No fault outlived the run |

The per-scenario JSON and raw request records were kept outside the repository with the run.

## Defects found

An earlier run against the previous build found four defects in the service and one in the suite's cleanup. Each was fixed before this run:

- The gateway admitted and charged probes to forbidden destinations, leaving the nodes to refuse them.
- A refused request's log line quoted the caller's probe target.
- With permits required, node certificates lacked client auth, so every direct operator probe failed.
- A node kept requesting permits under a replaced certificate pod's identity.
- The suite's API-isolation fault was left in place when the isolated gateway restarted, and that replica could not reach the API server afterwards.

## Not established by this run

- The target platform. Staging and production cells were not run.
- Direct operator probes from edge nodes. The lab's edge nodes cannot reach the gateway Service, so only one node's direct probes were judged.
- An inventory over 256 routers, CA rotation with an overlapping bundle, and cancellation timed during discovery. Unit tests cover these.
- Emission at its limit. With three routers, node slots kept emission 1280 packets below the bound.
