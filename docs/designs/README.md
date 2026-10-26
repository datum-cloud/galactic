# Designs and proposals

These documents explain decisions and planned work. Their status describes implementation scope, not whether a deployment has passed its rollout gates. Use component operating guides for current commands and defaults.

| Design                                                    | Status                                                                                         | Current reference                                                                        |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [Interface traffic policy](interface-traffic-policy.md)   | Implemented design; rollout remains explicit                                                   | [Rollout](../traffic-policy/rollout.md) and [node behavior](../traffic-policy/node.md)   |
| [Galactic Edge](galactic-edge.md)                         | Partially implemented and subject to qualification                                             | [Provider contract](../edge/provider-contract.md) and its open items                     |
| [Private Service Connect](private-service-connect.md)     | Partially implemented; qualification gaps remain                                               | [Private-service routes](../router/private-service-routes.md)                            |
| [Looking Glass backend service](looking-glass-service.md) | Proposed implementation contract; authentication scaffolding does not enable service execution | [Current fabric-api](../fabric-api/README.md)                                            |
| [Shared DNS64](dns64/README.md)                           | Proposed; end-to-end validation outstanding                                                    | [NAT configuration](../nat/configuration.md) for implemented translation                 |
| [Latency-aware routing](latency-aware-routing.md)         | Exploratory proposal                                                                           | [Router configuration](../router/configuration.md) for available settings                |
| [MASQUE gateway](masque-gateway.md)                       | Exploratory proposal; external references may describe historical designs                      | [Gateway configuration](../gateway/configuration.md) for the implemented XDP/DSR gateway |

When implementing a proposal, move the available interface or operating procedure into its component guide and update this status. Retain decisions and alternatives here. Keep measurements tied to their revision and environment in the [evidence archive](../archive/README.md), rather than presenting old results as current readiness.
