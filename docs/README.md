# Galactic documentation

Galactic connects VPC workloads through SRv6, BGP and Linux networking. Start
with the [system overview](overview.md) for components and ownership, or
[run the local lab](getting-started.md) to exercise the packet paths.

## Find a task

| I want to…                                           | Start here                                                                             |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Understand components and packet paths               | [Overview](overview.md), [system diagrams](architecture/README.md)                     |
| Build, test or contribute                            | [Development](development/README.md), [coding conventions](development/conventions.md) |
| Run a complete development environment               | [Local lab walkthrough](getting-started.md)                                            |
| Deploy or operate a component                        | The component guides below and [shared operations](operations/README.md)               |
| Inspect metrics and alerts                           | [Observability](observability/README.md)                                               |
| Look up API resources                                | [API reference index](api/README.md)                                                   |
| Evaluate a proposal or remaining implementation work | [Designs](designs/README.md)                                                           |
| Find a dated review or test result                   | [Archive](archive/README.md)                                                           |
| Change this documentation                            | [Documentation maintenance](development/documentation.md)                              |

## Component guides

| Area                        | Architecture and behavior                                                                                                                            | Configuration and operation                                                                                                                                                  |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Workload attachment         | [CNI overview](cni/README.md), [architecture](cni/architecture.md), [ADD/DEL](cni/cni-cmd-sequence.md), [garbage collection](cni/gc-cmd-sequence.md) | [Chain configuration](cni/configuration.md), [environment](cni/environment-variables.md), [conflist fields](cni/conflist-reference.md), [examples](cni/conflist-examples.md) |
| Tenant routing              | [Router architecture](router/architecture.md)                                                                                                        | [Router configuration](router/configuration.md)                                                                                                                              |
| Public ingress              | [Gateway architecture](gateway/architecture.md), [backend health](gateway/backend-health.md)                                                         | [Deployment](gateway/deployment.md), [configuration](gateway/configuration.md)                                                                                               |
| Public egress               | [Active/active egress](nat/active-active.md)                                                                                                         | [Deployment](nat/deployment.md), [configuration](nat/configuration.md), [rollout and rollback](nat/active-active-rollout.md)                                                 |
| Cluster controllers         | [Cell and fabric roles](controller/README.md)                                                                                                        | [API migration](operations/migrations/galactic-api-consolidation.md)                                                                                                         |
| Interface traffic policy    | [Node behavior](traffic-policy/node.md), [cell behavior](traffic-policy/controller.md)                                                               | [Rollout and rollback](traffic-policy/rollout.md)                                                                                                                            |
| Underlay and fabric routing | [Fabric routing index](fabric-routing/README.md), [topology](fabric-routing/topology.md)                                                             | [Operations](fabric-routing/operations.md)                                                                                                                                   |
| VPC ingress sidecar         | [VPC ingress metrics](observability/vpc-ingress.md)                                                                                                  | [Configuration](vrf/configuration.md)                                                                                                                                        |
| Fabric diagnostics          | [Fabric API index](fabric-api/README.md), [architecture](fabric-api/architecture.md), [query API](fabric-api/api.md)                                 | [Deployment](fabric-api/deployment.md), [configuration](fabric-api/configuration.md), [operations](fabric-api/operations.md), [load test](fabric-api/load-test.md)           |
| Provider attachments        | [Edge index](edge/README.md), [provider contract](edge/provider-contract.md)                                                                         | [Troubleshooting](edge/troubleshooting.md)                                                                                                                                   |
| Private services            | [Private-service routing](private-services/README.md)                                                                                                | Configuration and qualification limits are recorded in the same guide.                                                                                                       |

## Reading status correctly

Component guides describe the current repository. A feature may still be
disabled by default or require deployment-specific qualification. Designs state
their implementation status; historical reviews and measurements retain their
original scope and date. None of those is a substitute for a release's rollout
and acceptance checks.

The legacy `agents/`, `enhancements/` and other moved paths contain compatibility
pointers for existing links. Use the canonical pages indexed here for new links.
