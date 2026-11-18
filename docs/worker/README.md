# Galactic Worker

Galactic Worker is a node-local service. Service agents use it to
deliver tenant traffic locally or across the fabric, and it becomes the single
writer of shared host state. These pages are the contract for
[epic #1430](https://github.com/datum-cloud/galactic/issues/1430). Every Task of
the epic implements against them on the `integration/galactic-worker` branch.

Status: the service API, reconciliation core, client library and module
interface are implemented by
[#1433](https://github.com/datum-cloud/galactic/issues/1433). No delivery module
is built in yet: Local ([#1435](https://github.com/datum-cloud/galactic/issues/1435))
and Fabric ([#1436](https://github.com/datum-cloud/galactic/issues/1436)) add
them, so every capability reports `ModuleNotRunning` until then.
`examples/worker-client` is an independent client of the published API.

| Page                                   | Contents                                                                                  |
| -------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Service contract](contract.md)        | Claims, operations, state model, errors, versions, trusted sources and worked transitions |
| [Host state ownership](ownership.md)   | Writer inventory, one authority per resource class, bootstrap, adoption and transfer      |
| [Connector decision](connector.md)     | Which component is the provider connector, and its entry point                            |
| [Branch workflow](branch-workflow.md)  | Base and start SHAs, PR target, CI, artifact tags and how Tasks close                     |
| [Qualification plan](qualification.md) | Platform, handoffs, workload, comparison method and limits                                |

## Decision log

"Accepted" means the epic coordinator approved the decision. "Proposed" means
the decision was set while writing this contract and is open to review on its
PR. "Confirmed" means the product owner approved the decision on the date given.

| ID  | Decision                                                                                                                                          | Status               | Page                                                        |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------- | ----------------------------------------------------------- |
| D1  | A claim is keyed by caller, node, VPC and attachment UID, and versioned by a client-assigned generation                                           | Proposed             | [Contract](contract.md#claims)                              |
| D2  | Desired, programmed and observed state are kept and reported separately                                                                           | Proposed             | [Contract](contract.md#state-model)                         |
| D3  | Every mutating call is idempotent per generation; retries use bounded backoff                                                                     | Proposed             | [Contract](contract.md#errors-and-retry)                    |
| D4  | Only the owner releases a claim, and only at its current generation                                                                               | Proposed             | [Contract](contract.md#operations)                          |
| D5  | Session lease of 120 s renewed every 10 s, the XDP dispatcher's values                                                                            | Proposed             | [Contract](contract.md#sessions-restart-and-stale-deletion) |
| D6  | gRPC status codes with machine reasons                                                                                                            | Proposed             | [Contract](contract.md#errors-and-retry)                    |
| D7  | Protobuf package `galactic.worker.v1alpha1`, negotiated through `GetCapabilities`                                                                 | Accepted             | [Contract](contract.md#version-negotiation)                 |
| D8  | gRPC over a host unix socket; projected ServiceAccount token with TokenReview, `SO_PEERCRED`, and a static ServiceAccount-to-capability allowlist | Confirmed 2026-11-18 | [Contract](contract.md#transport-identity-and-access)       |
| D9  | `hostPath` socket mount, including for the galactic-vrf sidecar, which does not use the host network                                              | Confirmed 2026-11-18 | [Contract](contract.md#transport-identity-and-access)       |
| D10 | Trusted sources for locator, VPC, owner, backend SID and policy                                                                                   | Accepted             | [Contract](contract.md#trusted-sources)                     |
| D11 | Own locator resolves to Local, any other to Fabric, with no fallback from Local to Fabric                                                         | Proposed             | [Contract](contract.md#resolution)                          |
| D12 | One mutation authority means owning the scope's fence, or being a class's only writer; CNI writes with `Exclusive`                                | Accepted             | [Ownership](ownership.md#what-one-mutation-authority-means) |
| D13 | Bootstrap, adoption and transfer use the `internal/edge/ownership` fence, generalized                                                             | Accepted             | [Ownership](ownership.md#bootstrap-adoption-and-transfer)   |
| D14 | The connector is `cmd/galactic-edge` with a Worker-backed `agent.Datapath`                                                                        | Accepted             | [Connector](connector.md)                                   |
| D15 | Branch workflow with start commit `451eb40`                                                                                                       | Accepted             | [Branch workflow](branch-workflow.md)                       |
| D16 | NIC: Broadcom NetXtreme-C/E (`bnxt_en`) in generic mode; native mode on lab veth devices                                                          | Confirmed 2026-11-18 | [Qualification](qualification.md#platform)                  |
| D17 | Comparison against the main base on the same host, using the MASQUE benchmark method                                                              | Proposed             | [Qualification](qualification.md#comparison-method)         |
| D18 | Numeric limits, including 1024 claims per caller                                                                                                  | Confirmed 2026-11-18 | [Qualification](qualification.md#limits)                    |
| D19 | The session ID travels in the `x-galactic-worker-session` metadata key; a call without a live session is `FAILED_PRECONDITION`/`NoSession`        | Accepted             | [Contract](contract.md#sessions-restart-and-stale-deletion) |
| D20 | Shard and backend destinations report `DestinationKindUnsupported` until #1437 and #1438 add their resolvers inside Worker                        | Accepted             | [Contract](contract.md#claims)                              |
| D21 | The peer check maps `SO_PEERCRED` to a pod by the cgroup path, so Worker needs `hostPID` and the host `/proc`                                     | Accepted             | [Contract](contract.md#transport-identity-and-access)       |
| D22 | The allowlist is a YAML file passed with `--allowlist`                                                                                            | Accepted             | [Contract](contract.md#transport-identity-and-access)       |
