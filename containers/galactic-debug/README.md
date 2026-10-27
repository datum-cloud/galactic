# galactic-debug

An incident-response toolbox image, built on `nicolaka/netshoot` plus the
tools that debugging Galactic's datapath and routing needs and netshoot
doesn't already have: `bpftool`, `bpftrace`, `vtysh` (FRR client), the
`gobgp` CLI, `kubectl`, `crictl`, `yq`, and `galactic-usid` (this repo's
base62/hex uSID codec, `cmd/galactic-usid`).

Published as `ghcr.io/datum-cloud/galactic-debug`. Not deployed as a
standing workload -- attach it on demand with `kubectl debug`.

## Two usage modes

**Pod/proxy-level** (most incidents -- a specific backend or proxy is
failing):

```
kubectl debug -it <pod> --image=ghcr.io/datum-cloud/galactic-debug:latest --target=<container>
```

`--target` joins the ephemeral container to that container's process
namespace, so `nsenter -t <pid> -n -- <cmd>` works immediately against its
netns without a separate privileged pod. Use this when a proxy or backend
in one pod misbehaves: the container you actually want may not be
`hostNetwork` and can have its own dedicated per-pod attachment the host
can't see, so always confirm you're looking at the target's own netns, not
the host's, before trusting a "looks fine" result.

**Node-level** (eBPF map introspection, local FRR/GoBGP queries against
state that lives on the host, not in a pod netns):

```
kubectl debug node/<nodename> --image=ghcr.io/datum-cloud/galactic-debug:latest -it
```

Mounts the host root at `/host`. `bpftool`/pinned-map access under
`/sys/fs/bpf` needs `CAP_SYS_ADMIN`/`CAP_BPF`, which `kubectl debug node/`
does **not** grant by default. Use `--profile=sysadmin` if your `kubectl`
version supports it; otherwise fall back to a one-off privileged Pod
manifest targeting that node (`nodeName` + `hostPID`/`hostNetwork` +
`securityContext.privileged: true`) until every cluster's `kubectl` is new
enough for the profile flag.

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
clusters you debug.
