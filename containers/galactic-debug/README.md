# galactic-debug

An incident-response toolbox image, built on `nicolaka/netshoot` plus the
tools that debugging Galactic's datapath and routing needs and netshoot
doesn't already have: `bpftool`, `vtysh` (FRR client), `crictl`, `yq`, and
`galactic-usid` (this repo's base62/hex uSID codec, `cmd/galactic-usid`).
The image also ships `gobgp`, `kubectl` and `bpftrace`, which don't work
from a debug pod today (see [What doesn't work](#what-doesnt-work)).

Published as `ghcr.io/datum-cloud/galactic-debug`. Not deployed as a
standing workload: attach it on demand as a node debug pod.

## Pick the tag

Use the tag that matches the `galactic-kustomize` release the cluster
runs, so `galactic-usid` and the tools match the map layouts on the node.
Don't use `:latest`: it tracks the newest release, which can be ahead of
the cluster. Clusters that follow `main` use `v0.0.0-main`.

```
kubectl -n galactic-system get ocirepository galactic-kustomize \
  -o jsonpath='{.status.artifact.revision}'
```

The tag is the part before `@`.

## Start a node debug pod

```
kubectl debug node/<node> -n galactic-system --profile=sysadmin \
  --image=ghcr.io/datum-cloud/galactic-debug:<tag> -- sleep 3600
kubectl -n galactic-system exec -it <debug-pod> -- bash
```

- **Namespace.** A node debug pod is privileged, so its namespace must
  enforce the `privileged` Pod Security level. `galactic-system` does. A
  namespace at `baseline` refuses the pod. The `baseline` warning printed
  on creation is expected: `galactic-system` warns and audits at
  `baseline` but doesn't enforce it.
- **Profile.** `--profile=sysadmin` (kubectl 1.30 or newer) makes the pod
  privileged, with the host's network, PID and IPC namespaces and the host
  root mounted at `/host`.
- **Lifetime.** `kubectl debug node/` doesn't remove the pod. `sleep`
  bounds how long it runs, and the pod stays in `Completed` until someone
  deletes it. Delete it when you're done:

  ```
  kubectl -n galactic-system delete pod <debug-pod>
  ```

Run `kubectl` from your workstation, not from inside the pod.

## Inside the pod

The pod sits in the host network namespace, but its filesystem is the
image's. Host paths are under `/host`.

**Pinned eBPF maps** are under `/host/sys/fs/bpf`, not `/sys/fs/bpf`:
`galactic` (galactic-cni and shared maps), `galactic-nat`,
`galactic-edge` (gateway) and `galactic-xdp` (the XDP dispatcher). Don't
run `mount -t bpf` in the pod: it mounts a new, empty bpffs, and every
dump then looks empty.

```
ls /host/sys/fs/bpf/galactic
bpftool map dump pinned /host/sys/fs/bpf/galactic/locator_table
```

**crictl** has no `/etc/crictl.yaml` in the image. Point it at the host's
containerd socket:

```
export CONTAINER_RUNTIME_ENDPOINT=unix:///host/run/containerd/containerd.sock
crictl ps --name galactic-cni
```

**vtysh** needs fabric-router's FRR sockets, which are in its container
filesystem, not on the host:

```
vtysh --vty_socket /proc/$(pgrep -x bgpd)/root/var/run/frr -c 'show bgp summary'
```

**A pod's network namespace.** Find the pod sandbox's PID with crictl,
then enter its netns with `nsenter`:

```
crictl pods --namespace <namespace> --name '^<pod>$' -q
crictl inspectp <sandbox-id> | jq .info.pid
nsenter -t <pid> -n -- ip addr
```

Prefer this to `kubectl debug <pod>`. An ephemeral container stays in the
target pod's spec until the pod is deleted, and it shares the pod's
network namespace whether or not `--target` is set (`--target` only adds
the PID namespace). The node pod plus `nsenter` reaches the same netns
without changing the target pod. Some workloads (Kata, Unikraft) sit
behind a tap interface: from the host you see the host-side interface,
never the guest.

## What doesn't work

| Tool       | Why                                                                                                                                        | Tracked in                                                   |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| `gobgp`    | galactic-router's embedded GoBGP server has no gRPC API, so the CLI has nothing to connect to. Read BGPPeer status and router logs instead | [#1157](https://github.com/datum-cloud/galactic/issues/1157) |
| `kubectl`  | The pod runs as the namespace's `default` service account, which has no RBAC. Run `kubectl` from your workstation                          | [#1158](https://github.com/datum-cloud/galactic/issues/1158) |
| `bpftrace` | Needs tracefs, which the pod doesn't mount. Even with `mount -t tracefs tracefs /sys/kernel/tracing` it isn't verified to work             | [#1158](https://github.com/datum-cloud/galactic/issues/1158) |

## Known caveats to re-check every time

- **A service reachable through more than one region needs testing in
  each.** Testing from one client only exercises whichever region
  anycast/DNS happened to route to. Confirm each region explicitly with
  `curl --resolve host:port:[pod-ip]` against a throwaway pod inside that
  region's cluster, rather than trusting whatever the public DNS name
  returns.
- **A synthetic `curl`/fresh-connection test is not reliable alone.** Real
  traffic reuses pooled connections a synthetic test never gets, so a
  known-good destination can still fail a synthetic test. What's reliable:
  a genuinely broken destination shows a distinct, reproducible signal --
  a tight microsecond-interval redirect loop with an identical TCP
  sequence number and timestamp on every retransmit -- versus normal
  one-second-spaced retransmits for a healthy path. `tcpdump`/`tshark` are
  how you tell the two apart, not response codes alone.
- **A DaemonSet is not always the source of truth for what image is
  actually running.** A DaemonSet managed by an operator or by GitOps
  can be re-rendered faster than a direct edit
  survives -- check the running pod's digest, not just the manifest, and
  expect a floating tag to re-resolve to something new on every restart.

## Version pins

`gobgp` is pinned in the Dockerfile's `GOBGP_VERSION` build arg to match
the major version `galactic-router` embeds (`go.mod`'s
`github.com/osrg/gobgp/v4`). Bump it alongside any `go.mod` bump of that
dependency -- it is not vendored from this module's own `go.sum`, so it
does not drift automatically the way the embedded server does.

`KUBECTL_VERSION`/`CRICTL_VERSION`/`YQ_VERSION` build args pin the rest;
bump periodically, roughly tracking the Kubernetes minor version of the
Galactic edge clusters the image is used on.
