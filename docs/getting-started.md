# Run the local networking lab

The ContainerLab environment builds Galactic from this checkout and runs three
Kind clusters connected through an SRv6 transit network. It is the repository's
worked example for workload attachment, tenant routing, ingress and egress.
Use a dedicated development host: deployment changes host sysctls and creates
privileged containers and network links.

For a smaller build/test loop, start with [development](development/README.md).
This walkthrough follows the lab's checked-in tasks; it does not certify a
production release or replace feature-specific acceptance tests.

## Prerequisites

- A Linux kernel supporting the lab's VRF, SRv6 and eBPF operations.
- Docker with a reachable daemon and permission to run privileged containers.
- ContainerLab, Kind, kubectl, jq and Task. See the
  [lab prerequisites](../deploy/containerlab/README.md#prerequisites).
- Go and clang for building the checkout, or the repository's
  [development container](../.devcontainer/galactic/).

The [ContainerLab development container](../.devcontainer/containerlab-dood/)
provides a Docker-out-of-Docker setup. Container networking still depends on
the Docker host's kernel and privileges.

## Build and deploy

From the repository root:

```sh
cd deploy/containerlab
task deploy
```

The task builds the images, creates the clusters, installs the networking
components and applies the lab scenarios. Allow it to finish before running
verification. If it fails, use the named failing task and the lab's
[layout](../deploy/containerlab/README.md#lab-layout) to locate the affected
component; repeating a destructive cleanup is not a diagnostic step.

## Verify connectivity

From the same directory:

```sh
task verify:underlay
task verify:scenarios
task verify:gateway
task verify:gateway-ingress
task verify:nat-datapath
```

Each task must exit successfully. Together these check underlay reachability,
VPC workload connectivity, gateway API readiness, real ingress traffic and a
translated egress round trip. API readiness alone does not prove a working
packet path.

Use the lab's [verification reference](../deploy/containerlab/README.md#verification)
for additional checks. Fault-injection and rollout tests can interrupt lab
traffic; run the checks required by the feature you changed rather than treating
every task as a harmless health probe.

## Inspect or remove the lab

```sh
task inspect
```

The task reports the lab containers. The generated `dfw.kubeconfig`,
`iad.kubeconfig` and `sjc.kubeconfig` files in the lab directory select its
clusters explicitly when using kubectl.

When finished, from the lab directory:

```sh
task destroy
```

This removes the lab containers and Kind clusters. `task clean` also removes
built images and lab artifacts. Use the [lab task reference](../deploy/containerlab/README.md#tasks)
for rebuild and feature-specific workflows.
