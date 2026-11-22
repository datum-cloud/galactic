# Lab lifecycle

`task deploy` builds the images, publishes them, creates the clusters, and runs
one ordered baseline sequence in `scripts/lab-lifecycle.py`. Independent sites
run concurrently within each step; dependent steps retain their ordering.
Each site writes its own kubeconfig during creation; host contexts are merged
serially afterward. A failed site fails the step after all site workers have
finished.

## Prerequisites and image distribution

In addition to the lab's normal tools, the lifecycle needs Python 3 with PyYAML,
Helm, Go, a local rootful Docker daemon, and a free loopback TCP port 5001.
`tools:crane` installs crane v0.20.6
into the checkout's `bin/`. Run shared image builds, deployment, reset and
verification under the Containerlab manager reservation.

A `registry:3.0.0` container named `galactic-lab-registry` publishes on
`127.0.0.1:5001`. Kind nodes reach it through their Docker network. Its named
volume, `galactic-lab-registry`, survives `task destroy`, so repeated deployments
reuse layers. `task images:clean` removes the owned registry and its volume;
`task clean` includes that cleanup. Rebuilding the cache requires registry access.
A container with that name but without the lab ownership label is rejected. The
registry is a local development service, not a public endpoint.

Local images are pushed once. External images are discovered from the tenant,
TUN plugin, BMP and FRR exporter manifests, the pinned Cilium and cert-manager
charts, and the pinned Multus manifest. External tags are resolved once per
deployment and copied by digest. Chart archives and the Multus manifest are
cached in `bin/lab-images/`. Installation versions and prefetch versions share
`scripts/image-versions.sh`.

Chart image placement respects node selectors and untolerated scheduling taints.
Affinity is treated conservatively, so every eligible node retains the images.
Nodes pull the recorded digests with containerd, with at most twelve nodes
unpacking concurrently. Each image is then tagged with its original reference.
Images already visible through CRI with the expected config digest are reused.
Transport references are removed after canonical workload tags are verified,
so superseded image layers can be reclaimed by containerd.
Workload manifests and their pull policies are unchanged. Publication compares
Docker image IDs against the published index or platform config digest, according
to the Docker image store, and preserves external manifest digests. Node pulls
verify the platform config digest through CRI. The inventory in
`bin/lab-images/inventory.json` records those digests and target nodes.

After rebuilding an individual image, use `task deploy:images` to publish and
load the current images. `task images:load` loads the existing inventory without
publishing new tags; reset uses this path to restore the deployment's images.
A running pod still needs a rollout to use a rebuilt image with the same tag.

## Image-only node caches

`task destroy` recreates all cluster containers and Kubernetes state on the next
`task deploy`, but preserves verified image-only containerd stores. Each node has
an owned `galactic-lab-images-<node>` Docker volume. Only its containerd store is
mounted into the new node: kubelet state, credentials, pod logs and etcd are not
retained. Generated Kind configurations under `bin/lab-node-cache/` add that mount;
the committed workload manifests and Kind topology remain the source of truth.

Before cluster deletion, teardown stops kubelets, then ordinary pods while their
network agents remain available, then node agents with control-plane pods last.
It removes CRI containers and sandboxes and checks containerd namespaces and local
snapshotters for remaining runtime containers, tasks or writable snapshots. Stores
are marked reusable only after every node passes, containerd stops cleanly,
and all cluster node containers have been deleted.
Cleanup errors fail the destroy command, while cluster deletion still runs. The
stores remain dirty and cannot be reused on the next deployment.

A missing clean marker, incomplete create/destroy, incompatible cache format or
changed Kind base image causes the unused owned cache to be discarded and seeded
again. Cold initialization copies the base image's initial store and pulls and
unpacks the lab images. It incurs disk I/O that warm deployment avoids. Report
cold initialization separately from the three warm-cache fresh-cluster cycles;
these timings are not a cold-cache speed guarantee.

`task node-cache:clean` removes unused owned node caches and refuses mounted or
unowned stores. `task clean` includes it. Purge node caches after direct mutations
to containerd internals or immutable image snapshots; normal component image
updates are checked against their expected configuration digests and reloaded.
The registry helper image must remain available locally for teardown, including
offline teardown. To reclaim all cached image disk space, destroy the lab and
run `task node-cache:clean`.

## Reset

```bash
task reset
task baseline:twice
```

A successful deploy records a local checkpoint at
`bin/lab-lifecycle/baseline.json`. Reset requires that checkpoint, the same
source configuration and the same running Kind containers. A lab created by
an older checkout needs one full deploy before reset is available.

Before mutating the lab, reset checks every node for a Worker socket,
Worker-owned VPC fences and pending ownership transfers. It also checks the
system component inventory and fabric activation specifications. If any guard
fails, reset exits and instructs the caller to redeploy.

For supported checks that patch existing DaemonSets, Deployments, ConfigMaps,
node labels, taints or scheduling state, reset restores the complete saved
specifications, including removal of fields added by a patch. It restarts
Galactic components to discard containers using patched image tags, waits for
component readiness, deletes the baseline tenant namespaces and the known
`ns80-tap`, `gateway-local` and `nat-local` fixture namespaces, waits for their
normal teardown, and reruns deploy's baseline sequence. It neither force-removes
finalizers nor deletes ownership fences or pinned dataplane state.

Reset preserves clusters, etcd and the existing PKI. Checkpoint files stay local
and must not be committed or published. The checkpoint is invalidated before
reset's first mutation; a failed reset requires a full redeploy or an explicitly
verified recovery, rather than reuse of a stale checkpoint.

Use `task destroy` followed by `task deploy` after:

- lab deployment scripts, topology, Kind configuration, node image or production
  manifest changes;
- Worker ownership tests, including checks that leave VPC ownership behind;
- typed fabric activation changes or changes to the system component inventory;
- host, control-plane or Docker restarts that lose tmpfs etcd data;
- host networking, routing, BPF, credentials or other mutations outside reset's
  documented restoration scope.

Reset does not establish correctness after arbitrary lab mutations. The
post-reset `baseline:twice` comparison remains required before handing the lab
to another run. Do not regenerate the committed reference to make reset pass.

## Timing and acceptance evidence

Both lifecycle commands write `timings.tsv`, per-site observations under
`sites/`, and total elapsed seconds under `bin/lab-lifecycle/<timestamp>/`.
An explicit evidence directory must be new:

```bash
task deploy -- --output /tmp/lab-deploy-1
task baseline:twice -- /tmp/lab-baseline-1
```

The deploy total includes image builds and publication, cluster creation,
configuration and readiness. Report cache state alongside timings. A warmed
image build is not evidence for a cold build. Per-site durations overlap and
must not be added to obtain wall-clock time.

Issue #1469 requires three consecutive `task destroy`/`task deploy` cycles,
each at most 900 seconds, plus baseline checks after deployment and reset,
a timed reset after a component patch, and image/manifests equivalence with the
previous path. These are acceptance gates, not guarantees made by the scripts.

Run `task test:lifecycle` for offline regression coverage and the repository's
`task ci` checks. Offline tests do not establish deployment speed or dataplane
correctness.
