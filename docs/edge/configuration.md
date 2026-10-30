# Galactic Edge agent configuration

`galactic-edge` programs node-local provider attachments. Set these command
options on the node agent; [shared logging](../observability/logging.md) has
its logging options. The [provider contract](provider-contract.md) explains
resource intent, lifecycle and MTU constraints.

| Flag                          | Environment | Default                                  | Meaning                                                                                                                                      |
| ----------------------------- | ----------- | ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `--node-name`                 | `NODE_NAME` | required                                 | Node hosting the agent. An explicit flag overrides the environment default.                                                                  |
| `--mtu`                       | —           | required                                 | Attachment link MTU. The supplied base manifest expands `GALACTIC_EDGE_MTU` into this flag; the binary does not read that variable directly. |
| `--pin-dir`                   | —           | `/sys/fs/bpf/galactic`                   | Directory of pinned uSID datapath maps and programs.                                                                                         |
| `--ownership-dir`             | —           | `/var/lib/galactic-edge/ownership`       | Persistent host directory for node writer fencing records.                                                                                   |
| `--cri-endpoint`              | —           | `unix:///run/containerd/containerd.sock` | CRI endpoint used to find provider pod network namespaces.                                                                                   |
| `--proc-sys-path`             | —           | `/proc/sys`                              | Writable procfs sysctl root for provider packet devices.                                                                                     |
| `--max-skew`                  | —           | `2s`                                     | Maximum clock error assumed for grant deadlines; must match the controller's `--edge-max-skew`.                                              |
| `--boot-id-path`              | —           | `/proc/sys/kernel/random/boot_id`        | File containing the node boot ID.                                                                                                            |
| `--metrics-bind-address`      | —           | `:9186`                                  | Metrics listener.                                                                                                                            |
| `--health-probe-bind-address` | —           | `:9187`                                  | Health and readiness listener.                                                                                                               |
