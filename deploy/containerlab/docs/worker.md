# Galactic Worker checks

`task worker:verify PROFILE=dedicated` and `PROFILE=combined` install
galactic-worker on dfw from this checkout's manifests
(`config/galactic-worker`, through `resources/galactic-worker/`), check its
diagnostics against injected failures, and remove it with the handback that
[operations](../../../docs/worker/operations.md#hand-scopes-back) describes.
They need `ns80` with dfw's second compute worker, `dfw-worker4`, and
`bpftool` through passwordless `sudo` on the host.

```bash
cd deploy/containerlab
task worker:images                       # build and load galactic-worker and the claim client
task worker:verify PROFILE=dedicated
task worker:verify PROFILE=combined      # also deploys ns80-tap on dfw-worker2, and removes it
task verify                              # the lab is unchanged
```

`scripts/verify-worker.sh` describes the claims, the failures it injects
(an unreachable route over the underlay route to `dfw-worker4`, a guest scaled
to zero, and, for combined, Local's `galactic_local_rx` filter removed), and
the stages it compares with the state before install: claims reconciled, a
second resync, a Worker restart, a drain of `dfw-worker3` and the uninstall.
It also checks Worker's effective capabilities and what its ServiceAccount may
and may not do. Evidence lands in `bin/worker-lab/<UTC timestamp>-<profile>/`
at the repository root, and every failed check is listed in its `failures`
file.

`scripts/worker-lab.sh` runs the steps by hand: `install SITE PROFILE`,
`inspect SITE NODE`, `uninstall SITE`, and the claim client pod
(`resources/galactic-worker/lab-client/`). `scripts/worker-fabric.sh` still
runs the binary without manifests for quick iteration.
