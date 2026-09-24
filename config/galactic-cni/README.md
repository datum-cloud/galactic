# galactic-cni manifests

Kustomize-composed production manifests for the `galactic-cni` CNI installer
DaemonSet. Apply with:

```
kubectl apply -k config/galactic-cni/
```

or as part of the whole platform with `kubectl apply -k config/`. This
DaemonSet opts in via the independent `galactic.datumapis.com/galactic:
router` label and runs on both compute and edge nodes (see
[docs/node-labels.md](../../docs/node-labels.md)).

## What's here

- `daemonset.yaml` — the installer DaemonSet. It has two containers:
  - `install-cni`, an initContainer that drops the plugin binaries into
    `/opt/cni/bin` and writes the conflist to `/etc/cni/net.d`.
  - `credential-refresh`, the long-running run container. It hosts the
    eBPF/TC-BPF uSID datapath's load/attach/pin control daemon and, in
    addition, serves an `ebpf-datapath` gRPC health sub-service used by
    the liveness/readiness/startup probes.
- `rbac.yaml`, `serviceaccount.yaml` — RBAC for the CNI plugin.
- `kustomization.yaml` — composes the above.

`config/galactic-cni` applies independently; the namespace
(`galactic-system`) is created by `config/galactic-system/`.

## Container privileges (BPF / PERFMON / NET_ADMIN / NET_RAW)

Because `credential-refresh` hosts the eBPF datapath's control daemon, its
securityContext grants `BPF`, `PERFMON`, `NET_ADMIN`, and `NET_RAW` (with
everything else dropped) plus a `bpf-fs` hostPath mount. The grant is
required **unconditionally**: the datapath is the only forwarding path, so
there is no flag to gate it behind, and it takes effect on every node
running this manifest. The rationale for each capability:

- **BPF / NET_ADMIN** — required by the binary's BPF loader dependencies to
  load, attach, and pin the datapath's programs and maps, and to create the
  VRF/tc state the datapath runs in.
- **NET_RAW** — used by `internal/plumbing/radv.RunActor`: it opens a raw
  ICMPv6 socket (`mdlayher/ndp`'s `Listen`, over ip6:ipv6-icmp) to send
  Router Advertisements and receive Router Solicitations on each tap
  attachment. Without it, `ndp.Listen` fails "operation not permitted" for
  every attachment on every node.
- **PERFMON** — required alongside BPF for the same reason the gateway and
  nat eBPF-loading containers document: the verifier only permits
  pointer+scalar arithmetic on packet data when the loading process is
  perfmon_capable(). Without it the verifier applies its unprivileged
  ruleset and rejects the program outright even when running as root —
  "R8 has pointer with unsupported alu operation, pointer arithmetic with
  it prohibited for !root". `usid.c` did not need it until the GRO-merged
  decap path began offsetting a packet pointer by a computed header length,
  so this container ran without it for as long as the program happened to
  stay inside what unprivileged BPF allows — luck rather than a property
  worth depending on.

## The `bpf-fs` hostPath mount

`/sys/fs/bpf` is the host's bpffs mount ("All maps pinned under
`/sys/fs/bpf/galactic/`"). `credential-refresh` pins the datapath's maps
under a `galactic/` subdirectory of this mount so a container restart
reuses maps already pinned there instead of recreating them empty
(pinned-map continuity).

`type: Directory` (not `DirectoryOrCreate`): bpffs must already be mounted
at this path by host/kubelet node setup for pinning to actually work.
Creating a plain directory if it were missing would silently produce a
regular filesystem path instead of a real bpf filesystem, and pinning
would then fail at load time with a real, actionable error instead of
appearing to succeed.

**SECURITY NOTE:** this mounts the host's entire `/sys/fs/bpf`, not just
the `galactic/` subtree this container actually uses — a Kubernetes
hostPath volume cannot mount a subdirectory that does not exist yet
(`galactic/` is created on first pin, not present beforehand). The
container therefore has read/write visibility into every other pinned BPF
object any other process on the host has placed under bpffs, not just its
own. This is an accepted, largely inherent tradeoff of bpffs pinning on
this platform, not an oversight — call it out explicitly to a security
reviewer rather than let it pass as a footnote.

## The `radv-state-dir` mount

`/var/lib/cni/ra` backs `internal/plumbing/radv.DefaultStateDir`. It is
read unprefixed by `credential-refresh`'s own `reconcileRadvActors` loop, unlike the other host dirs which are mounted
under `/host/...`: radv's constant is shared with `galactic-tap`, a
separate binary invoked directly on the host by the kubelet's own CNI exec
(never inside this or any other container), so it has to stay the real
host-absolute path `galactic-tap` itself sees. Mirroring `bpf-fs`, the
hostPath is mounted at its own literal path rather than relocated under
`/host/`. Without this mount, `reconcileRadvActors` lists an
empty/missing directory — every tap attachment `galactic-tap` records on
the host is invisible to it, so no RunActor ever starts and no guest gets
an RA or a Router Solicitation reply, silently, on every node.

The mount is writable, and covers only `/var/lib/cni/ra`, not the rest of the
host's CNI state. `reconcileRadvActors` removes the record of a tap whose
interface has been missing for 30 seconds, since nothing else would ever
remove it once that tap's DEL has been missed. On a read-only mount every
removal fails.

## Further reading

- `docs/cni/README.md` — the CNI docs entry point (env vars, conflist
  fields, sequence diagrams).
- `docs/cni/configuration.md`, `docs/cni/environment-variables.md` —
  plugin behavior and the `GALACTIC_CNI_EBPF_*` configuration.
- `docs/agents/ARCHITECTURE-CNI.md` — the CNI attach chain and the eBPF
  uSID TC-BPF datapath.
