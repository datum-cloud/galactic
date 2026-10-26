# Galactic Edge conformance suite

`tests/edgeconformance` runs the failure-test matrix of
[the provider contract](../enhancements/networking/galactic-edge/contract.md#failure-test-matrix)
against a cell, using the reference provider in `examples/edge-provider`. That
provider is built outside the core. The suite also acts as a provider pod
through pod-bound tokens, to send the requests a well-behaved provider never
makes. It runs against one of two targets:

| Target  | Cell                                                                     | Command                                                             |
| ------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `kind`  | The containerlab lab's `dfw` cluster, after `task deploy:galactic-edge`  | `task verify:edge-conformance` in `deploy/containerlab`             |
| `talos` | A cell of real nodes: the target Talos/Cilium environment                | `task test:edge-conformance:talos` at the repository root           |

Both targets run every row the suite automates. Rows 12 (API isolation) and 23
(node reboot) need real nodes, so the `kind` target skips them. Rows 8, 9, 13b
and 22 run as real-kernel and envtest unit tests, not in this suite. A skipped
row is not a pass.

## What the talos target needs

The cell must already run the core, unchanged:

- One compute node and two edge nodes, each labeled
  `galactic.datumapis.com/galactic=router`, so each runs `galactic-cni` and
  `galactic-router`.
- `galactic-router` with `GALACTIC_ROUTER_TRAFFIC_POLICY=true` and the
  edge-ownership mount from `config/galactic-router/base`.
- `config/galactic-edge` applied, `galactic-controller --role=cell --edge`,
  and the `galactic-edge` agent on both edge nodes.
- Multus, and a `galactic-controller --role=fabric` that allocates VPC
  identifiers.
- A container runtime that lets unprivileged containers open `/dev/net/tun`
  ([node requirements](troubleshooting.md#node-requirements)).
- Pods in the namespace `edge-conformance-system` may run privileged, with
  the host's network and PID namespaces.

The suite brings everything else, and labels each object it creates
`app.kubernetes.io/part-of=galactic-edge-fixture`:

- **Node pods.** The DaemonSet `edge-conformance-node` in
  `edge-conformance-system` runs one privileged pod on each node under test.
  The suite runs every node-level step in that pod through `kubectl exec`:
  packet probes inside pods' network namespaces, signals, `nft` and the
  reboot. It copies its probe, `edgeprobe`, into each node pod.
- **Tenants.** The namespaces `edge-conformance-10` and `edge-conformance-20`
  each hold a VPC with its own workload network (`fd20:10::/64` or
  `fd20:20::/64`) and the same edge address space (`fd00:ed9e::/32`), so the
  two providers' attachments and routes overlap address for address. Each
  tenant has one client workload on each node under test. The VPC is the
  client's default network, on its own `VPCAttachment` and traffic policy
  binding.
- **Providers.** The `EdgeProvider`s `conf-a`, `conf-b`, `conf-u` and `conf-v`
  and their namespaces `edge-conf-*`, with the `EdgeService` grants in the
  tenants' namespaces.

## What the run does to the cell

Run it only in a cell whose edge nodes may lose traffic. These rows disrupt
more than the suite's own tenants:

| Row | Step                                                                                                  | Effect beyond the fixture                                                                                                                                           |
| --- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 12  | Drops the edge node's traffic to the API server: the API endpoints, the `kubernetes` Service and KubePrism | For up to 150 s, the node's kubelet and every component on it can't reach the API server. The node may turn `NotReady`. Packets keep flowing.                     |
| 14  | Stops `galactic-edge` on an edge node for 25 s                                                        | No other edge attachments on that node are programmed during the stop.                                                                                             |
| 16  | Stops `galactic-router` on an edge node for 25 s                                                      | The route reflector withdraws everything that node advertises, such as an egress shard's SID or a gateway's VIPs, until the router resumes.                          |
| 23  | Hard-reboots an edge node through `/proc/sysrq-trigger`, as on a power loss                           | Everything on the node stops until it boots again, which takes minutes on bare metal.                                                                               |

Row 12's `nft` rules live in the table `edgeconf_isolate`, in the node's
network namespace and the provider pod's. A process on the node deletes them
after 150 s even if the suite dies first.

## Running it

Pin both images by digest:

- **Provider image.** `ghcr.io/datum-cloud/galactic-edge-provider-example`,
  which `.github/workflows/publish.yaml` builds from `examples/edge-provider`
  on every push.
- **Tool image.** `ghcr.io/datum-cloud/galactic-debug`, or any image with
  `sh`, `nsenter`, `nft`, `ip`, `kill` and `tar`. The node pods and the
  tenant clients both run it.

```sh
export EDGE_CONFORMANCE_KUBECONFIG=<cell kubeconfig>
export EDGE_CONFORMANCE_NODES=<compute node>,<edge node 1>,<edge node 2>
export EDGE_CONFORMANCE_PROVIDER_IMAGE=ghcr.io/datum-cloud/galactic-edge-provider-example@sha256:<digest>
export EDGE_CONFORMANCE_TOOL_IMAGE=ghcr.io/datum-cloud/galactic-debug@sha256:<digest>
task test:edge-conformance:talos
```

The run takes about 50 minutes. At the end it deletes everything it created.
Set `EDGE_CONFORMANCE_KEEP=1` to leave the fixture in place for debugging.
Run `task test:edge-conformance:talos:clean` to delete a fixture left behind.

## Timing

Each bound in the matrix compares two times: for example, the last lease
renewal start and the last packet through a gate. The suite converts every
time to one reference clock before it compares them.

- **`kind` target:** the reference clock is the host's `CLOCK_BOOTTIME`. The
  Kind nodes share the host's kernel, so a lease's renew-start and a probe's
  timestamps are already on it.
- **`talos` target:** the reference clock is wall time. The suite maps each
  node's `CLOCK_BOOTTIME` to that node's wall clock (`edgeprobe clock`,
  re-read every 30 s), so a comparison across nodes depends on the nodes'
  time synchronization.

The suite allows 100 ms of clock difference between nodes in a cross-node
comparison. `summary.json` records each node's measured offset from the
runner's clock.

## Results

Results land in `bin/edge-conformance/`, or in `EDGE_CONFORMANCE_ARTIFACTS`
when it is set:

- **`summary.json`:** the commit and whether the tree was dirty, the versions
  under test, every measurement and whether the run failed. On the `talos`
  target, the versions are each node's OS, kernel, runtime and kubelet, and
  the image digest of every core, Cilium and provider container on the nodes
  under test.
- **One directory per row:** each probe's raw events, as JSON lines, with
  times on the node's `CLOCK_BOOTTIME`.

The `go test -v` output names each row as a subtest, `NN-description`, and
logs each measurement beside the bound it was checked against.
