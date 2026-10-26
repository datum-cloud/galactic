# Galactic controller

`galactic-controller` runs either cell controllers or the central fabric identity allocator. Choose the role explicitly; they are separate deployments with different credentials. This binary does not load a node datapath or replace `galactic-router`.

## Responsibilities

| Process                                  | Responsibility                                                                                                                                                           |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| NSO cell manager                         | VPC, subnet-status and attachment reconciliation, attachment identifiers and NetworkAttachmentDefinitions when Galactic integration is enabled                           |
| `galactic-controller --role=cell`        | TrafficPolicy admission, default policies and binding resolution; pod-interface injection; projection of BGP programming status to attachments and NSO interfaces/claims |
| `galactic-controller --role=cell --edge` | The cell role plus admission, allocation and draining of Edge attachments and acceptance/revocation of Edge route claims                                                 |
| `galactic-controller --role=fabric`      | Central NetworkFabricIdentity allocation using the federation hub and platform IPAM                                                                                      |
| `galactic-router`                        | Node BGP and traffic-policy programming and node-owned status                                                                                                            |
| `galactic-edge`                          | Node-side Edge attachment programming, fencing and release                                                                                                               |

The ownership split above is reflected in `cmd/galactic-controller/main.go` (`SetupCloud`, `Setup`) and `fabric.go`. The [API consolidation migration](../operations/migrations/galactic-api-consolidation.md) describes the transition from the previous cloud controller. Do not run two attachment writers during that transition.

## Shared flags

CLI defaults below describe the binary. Deployment overlays may override them; for example, the fabric Deployment configures metrics on `:8080` instead of the binary default.

| Flag                          | Default                                      | Meaning                                                         |
| ----------------------------- | -------------------------------------------- | --------------------------------------------------------------- |
| `--role`                      | required                                     | `cell` or `fabric`                                              |
| `--namespace`                 | `POD_NAMESPACE`, otherwise `galactic-system` | Local pod and leader-election namespace                         |
| `--metrics-bind-address`      | `:9184`                                      | Metrics listener                                                |
| `--health-probe-bind-address` | `:8081`                                      | Health and readiness listener                                   |
| `--leader-elect`              | `true`                                       | Elect one reconciler; cell webhook replicas all serve admission |

## Cell flags

| Flag                    | Default                                                 | Meaning                                                                                                 |
| ----------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `--webhook-port`        | `9443`                                                  | Admission webhook listener                                                                              |
| `--webhook-cert-dir`    | `/tmp/k8s-webhook-server/serving-certs`                 | Directory containing `tls.crt` and `tls.key`                                                            |
| `--controller-username` | `system:serviceaccount:<namespace>:galactic-controller` | Identity allowed to write the reserved default policy                                                   |
| `--edge`                | `false`                                                 | Enable Edge attachment and route controllers after their CRDs and admission prerequisites are installed |
| `--edge-max-skew`       | `2s`                                                    | Maximum assumed clock error; must match `galactic-edge --max-skew`                                      |

### Installing the cell role

1. Install the Galactic CRDs with `kubectl apply -k config/crd/`.
2. Install cert-manager if the cell does not already provide it.
3. Apply `kubectl apply -k config/galactic-controller/` for the ServiceAccount and RBAC.
4. Apply the deployment and webhook resources from `config/galactic-controller/base/` through the cell's deployment configuration.
5. Verify both replicas become ready and admission succeeds before enabling node policy enforcement. Use the [traffic-policy rollout](../traffic-policy/rollout.md) for audit, enforcement and rollback.

Admission fails closed. Deploy the webhook with its serving Deployment, and keep its certificates and Service reachable. Neither the controller nor its CRDs are installed by the root `config/` kustomization.

For `--edge`, first install the Edge prerequisites in `config/galactic-edge/` and its node agent on eligible nodes. A deleting attachment is held until the node reports `Released` or the node is removed. See [Edge troubleshooting](../edge/troubleshooting.md) and the [provider contract](../edge/provider-contract.md) for ownership and timing requirements.

## Fabric flags

| Flag                   | Default   | Meaning                                                             |
| ---------------------- | --------- | ------------------------------------------------------------------- |
| `--identity-class`     | required  | IPClass from which globally unique network identities are allocated |
| `--identity-namespace` | `default` | Namespace for platform IP claims                                    |
| `--platform-project`   | required  | Platform project used for IPAM                                      |
| `--ipam-kubeconfig`    | required  | Credential/configuration for the addressing service                 |
| `--hub-kubeconfig`     | required  | Credential/configuration for the federation hub                     |

### Installing the fabric role

Use `config/galactic-controller/fabric/` as the deployment base and supply the platform project and both credentials through the environment's overlay. Its default project is empty, so the base is not a complete deployment. Apply `hub-rbac.yaml` to the hub for the hub credential; the local ServiceAccount and lease remain in the deployment's own cluster.

The allocator reads network intent from the hub, requests identities through platform IPAM, and writes NetworkFabricIdentity there for distribution to cells. Keep these central credentials out of cell deployments. Verify identity objects and their propagation before migrating attachment writers, following the [migration sequence](../operations/migrations/galactic-api-consolidation.md#cutover-sequence).

## Further reading

- [Cell traffic-policy behavior](../traffic-policy/controller.md)
- [Node traffic-policy programming](../traffic-policy/node.md)
- [Generated cloud API](../api/cloud.md)
- [Generated policy and Edge API](../api/galactic.md)
