# Fabric routing process configuration

The controller compiles typed routing intent; the node agent chooses and
activates a configuration source. See [operations](operations.md) for the
rollout sequence and [API references](../api/README.md) for CRD fields.
Binary defaults below can be overridden by deployment manifests. Logging is
configured separately with [shared logging options](../observability/logging.md).

## `fabric-config-agent`

These flags are persistent on `init` and `watch`. For flags with an environment
variable, the variable supplies the default and an explicit flag takes precedence.

| Flag                 | Environment         | Default                        | Meaning                                                                                                                                     |
| -------------------- | ------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `--node-name`        | `NODE_NAME`         | required                       | Kubernetes node whose configuration is applied.                                                                                             |
| `--namespace`        | `POD_NAMESPACE`     | required                       | Namespace containing configuration objects.                                                                                                 |
| `--pod-name`         | `POD_NAME`          | empty                          | Pod name used for events.                                                                                                                   |
| `--pod-uid`          | `POD_UID`           | empty                          | Pod UID used for events.                                                                                                                    |
| `--legacy-configmap` | —                   | `fabric-config`                | Shared fallback ConfigMap with a `frr.conf.<node>` key; empty disables it.                                                                  |
| `--config-dir`       | —                   | `/etc/frr`                     | FRR configuration directory.                                                                                                                |
| `--defaults-dir`     | —                   | `/etc/frr-defaults`            | Image default FRR files.                                                                                                                    |
| `--vtysh`            | —                   | `/usr/bin/vtysh`               | `vtysh` executable.                                                                                                                         |
| `--frr-reload`       | —                   | `/usr/lib/frr/frr-reload.py`   | FRR reload executable.                                                                                                                      |
| `--activation`       | `FABRIC_ACTIVATION` | `false`                        | Act on the node's `FabricRouterDeployment` and its revisions. The environment default is enabled only by `true`.                            |
| `--configmaps`       | `FABRIC_CONFIGMAPS` | `true`                         | Read node configuration ConfigMaps. `false` requires activation and retires that path. The environment default is disabled only by `false`. |
| `--state-dir`        | —                   | `/var/lib/fabric-router/agent` | Host directory for the activation journal, identity and checkpoint.                                                                         |
| `--machine-id-file`  | —                   | `/etc/machine-id`              | Host machine identity file.                                                                                                                 |
| `--writer-lock`      | —                   | `/run/frr/fabric-agent.lock`   | Lock shared by node FRR writers.                                                                                                            |
| `--boot-record`      | —                   | `/run/frr/fabric-boot.json`    | Record of the source used at FRR startup.                                                                                                   |

`watch` also accepts `--metrics-bind-address` (default `:9343`, empty disables
its metrics listener) and `--detect-only` (default `false`, report IPv4-mapped
next hops without resetting sessions). `init` installs the initial
configuration; `watch` applies subsequent changes.

## `fabric-router-controller`

The `run` command accepts these options:

| Flag                          | Default           | Meaning                                               |
| ----------------------------- | ----------------- | ----------------------------------------------------- |
| `--metrics-bind-address`      | `:8080`           | Metrics listener.                                     |
| `--health-probe-bind-address` | `:8081`           | Health listener.                                      |
| `--leader-elect`              | `true`            | Elect one active replica.                             |
| `--leader-election-namespace` | `galactic-system` | Namespace of the leader-election Lease.               |
| `--rollout`                   | `false`           | Manage router deployments and release authorizations. |
| `--topology`                  | `false`           | Generate peers from topology and endpoint objects.    |
| `--topology-namespace`        | `galactic-system` | Only namespace served by topology generation.         |

Administrative commands have their own arguments: use `fabric-router-controller
<command> --help` for the complete invocation. [Operations commands](operations.md#commands)
explain the release, source, fencing, import, preview and diff workflows.
