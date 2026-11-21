# Envoy socket checks

`task envoy:socket` proves that a real Envoy reaches tenant backends through
the `galactic-vrf` sidecar's Worker socket claims
([#1439](https://github.com/datum-cloud/galactic/issues/1439)). It runs on
`dfw-worker` against both of `ns80`'s VPCs, whose guests share one address.

It shows that:

- Envoy's upstream sockets, bound to each VPC's VRF in the pod with
  `SO_BINDTODEVICE`, send from the shared gateway `fd20:80:ff04::1` and reach
  the right VPC's backend, over fresh and pooled connections;
- a backend on the same node is reached over the claim's routed link, and a
  backend on another node through the sidecar's SRv6 encapsulation, with the
  reply returning over the routed link in both cases;
- neither VPC's traffic appears on the other VPC's link;
- the claims survive the loss of the VPC's last local tenant interface and a
  rollout of the Envoy pod, and leave nothing behind when the fixture goes.

## Running

```bash
cd deploy/containerlab
task deploy:ns80                 # if ns80 is not deployed
task envoy:socket                # or: task envoy:socket -- DIR
task verify:ns80 && task verify  # on the same deploy
```

`task envoy:socket` builds `galactic-vrf:lab` from this checkout and loads it
and the Envoy image into `dfw-worker`, starts Worker there only
(`scripts/worker-fabric.sh`, with an allowlist granting `ns80-envoy/galactic-vrf`
`local.socket` and `fabric.srv6`), deploys the fixture and the backends, runs
the windows below and removes everything again. Output lands in
`bin/envoy-socket/run/` at the repository root, or in the directory given
after `--`: `results.json`, `volatile.tsv` (ports, nonces, pod UIDs and
interface names), `pcap/<window>/` and `logs/`. It exits non-zero when any
check fails.

Worker runs here as a bare process inside `dfw-worker` (`worker-fabric.sh`),
not as the packaged DaemonSet. A packaged Worker needs the routed-link profile
Component for `local.socket` ([Worker operations](../../../docs/worker/operations.md#install)),
so the run records the process's effective capabilities and checks that they
include `NET_ADMIN`, `SYS_PTRACE`, `SYS_ADMIN` and `BPF`, and that the
sidecar's session reports `local.socket` and `fabric.srv6` available.

The lab runs galactic-controller from the integration branch, which does not
yet certify a proxy attachment's node from its pod. For the case it builds
this checkout's galactic-controller, sets it on dfw's Deployment, and puts the
recorded image back in its cleanup; the restore rows check the Deployment
matches its deployed spec again. The case records the Envoy pod in the proxy
attachments' `status.podName`, as NSO does, names a replacement pod on the same
attachments, and checks that the controller certifies both on `dfw-worker`.

Before it changes anything it checks that the lab runs, that `ns80` passes
`verify-ns80.sh`, that this checkout has `galactic-worker handback`, and that
no `ns80-envoy`, Worker, Worker-owned scope, Worker advertisement, Local link
or rig is left from an earlier run. When a check fails it writes the reason to
`precondition` and exits 0. It then records the deployed state it will
compare with: `ns80`'s Deployments and VPCAttachments, the `galactic-system`
DaemonSets and the images already on `dfw-worker`.

Its cleanup, which always runs, restores that state on the same deploy:

1. It removes the fixture, the backends, any patch to `ns80` and the rig, and
   scales `ns80`'s guest back.
2. It stops Worker, hands its VPC scopes back with `galactic-worker handback`,
   which also removes Local's links, pins and claims, restarts galactic-router
   on `dfw-worker` so it writes the tenant routes again, and removes Worker's
   files and the images the run imported from the node.
3. It checks, in the `restore` rows of `results.json`, that no fixture object,
   sidecar, backend, Worker process, socket, claim, Local pin, Worker-owned
   scope, Local link, gateway route or Worker advertisement is left, that the
   recorded Deployments, VPCAttachments and DaemonSets match their deployed
   spec, and that every one of them is ready.

`task verify:ns80` and `task verify` then run on that deploy. A fresh deploy
is not part of the run.

`task deploy:ns80-envoy` runs only the setup and leaves the fixture up;
`task delete:ns80-envoy` removes it, stops Worker and hands its scopes back. Neither is part of
`task deploy` or `task verify`.

## Remote backends

Remote backends are not supported yet
([#1487](https://github.com/datum-cloud/galactic/issues/1487)). The sidecar's
in-pod datapath sends their SRv6 packets out of the pod's `eth0` with the
node's SID as the outer source, and dfw's primary CNI, Cilium, drops them at
its source-address check. The run still sets up each VPC's remote backend,
and the cleanup still checks it, but it sends no request to it: it records
one `scope` row per remote path, and the `state` row for the remote node's
route back, as skipped with that reason. The `fresh`, `reused`, `sockets`,
`captures`, `move` and `replace` windows cover the local paths only.

`REMOTE` picks the remote backend of each VPC:

| `REMOTE`      | Remote backend                                    | Address               |
| ------------- | ------------------------------------------------- | --------------------- |
| `dfw-worker4` | `ns80`'s `guest-a2` and `guest-b2` on dfw-worker4 | `fd20:80:ff01::2:0:0` |
| `sjc`         | `ns80`'s guests on `sjc-worker`, mirrored         | `fd20:80:ff02::1:0:0` |

It defaults to `dfw-worker4` when that node runs `ns80`'s second guests
([#1460](https://github.com/datum-cloud/galactic/pull/1460)), and to `sjc`
otherwise.

Each lab site is its own Kind cluster, and the sidecar and Worker see only
their own cluster's objects. In `sjc` mode the run copies, into `ns80-envoy`
in dfw's cluster, the sjc EndpointSlice of each VPC's guest (SID annotation
kept, tenant identifier `<vpc>-s<vpc>`) and a VPCAttachment that records it on
`sjc-worker`. The mirror stands in for a single control plane. Worker on
`dfw-worker` cannot place `sjc-worker`, so it reports those destinations
unresolved or Fabric; the checks require only that the sidecar never routes
them over the routed link. `dfw-worker4` mode needs no mirror and shows a
Fabric destination as Worker resolves it.

## Fixture

`ns80-envoy` (`resources/envoy-socket/dfw/`) composes the production
`config/galactic-vrf` Component. `kubectl apply -k` loads nothing outside the
kustomization's root, so the run copies the Component into the fixture as
`galactic-vrf/` on the node, as `deploy-cni.sh` does for `config/galactic-cni`.

| Object                                | What it is                                                                                                                                                        |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Deployment `envoy`                    | Envoy v1.32.3, a `client` container (the lab debug image) and the `galactic-vrf` sidecar, pinned to `dfw-worker`; RollingUpdate, `maxSurge 1`, `maxUnavailable 0` |
| ConfigMap `envoy-config`              | An HTTPS listener on `[::]:8443` routing `/<vpc>/<local\|remote>/<pooled\|fresh>` to eight static clusters, each bound to its VPC's VRF                           |
| VPCAttachments `proxy-80`, `proxy-81` | The proxy's attachments, labelled `galactic.datumapis.com/proxy: envoy`, both with `fd20:80:ff04::1/128`; the run writes their status                             |
| Secret `envoy-tls`                    | A self-signed key generated for the run; none is committed                                                                                                        |

The backends run `scripts/envoy-backend.py`, an HTTP/1.1 keep-alive server on
port 8080 that answers with its VPC, site, the request's `X-Nonce` and the
source address and port it saw. Where `ns80`'s attachments have no
`spec.interface.addresses`, the run adds them for the run and removes them
after, since Worker takes a destination's addresses only from there.

## Windows

| Window     | Checks                                                                                                                                                                                                                                                     |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fresh`    | 5 requests per path, one `curl` each: every answer from the path's VPC and site, seen from the gateway; 5 new upstream connections per fresh cluster                                                                                                       |
| `reused`   | 5 requests per path in one `curl`: the same, over one upstream connection (one source port, `upstream_cx_total` +1, `upstream_rq_total` +5)                                                                                                                |
| `sockets`  | The pooled sockets in the pod: local address the gateway, bound device `G000000080V` or `G000000081V`, peer the path's backend                                                                                                                             |
| `captures` | During `fresh` and `reused`: local requests and replies only on their VPC's routed link and guest, none through the encapsulation pair or on the physical members; nothing of one VPC on the other's link, pair or guest   |
| `state`    | The pod VRF routes only the local backend through the link; the host VRF routes the gateway to the host end; one Worker advertisement per VPC for the gateway, naming the pod; the sidecar reports 2 ready claims (the remote node's route back is skipped, #1487) |
| `move`     | With VPC 80's local guest gone, its pod VRF drops the local route, the host VRF keeps the gateway route, and VPC 81's local path answers; the route and path come back with the guest                                                                         |
| `replace`  | A rollout: the new pod's claim state is recorded, the new pod becomes Ready, the links and advertisements follow it, every path answers, and `verify-ns80.sh` passes                                                                                       |
| `cleanup`  | With the fixture gone: no Worker advertisement, no Local link and no gateway route on `dfw-worker`; Worker stops                                                                                                                                           |

Capture points: the routed links' pod ends (`pod80`, `pod81`), the sidecar's
`ivs`/`ivp` pairs (`encap80`, `encap81`), the host ends (`host80`, `host81`),
the local guests' `eth0` (`guest80`, `guest81`), the pod's `eth0`, and
`dfw-worker`'s four bond members (`physical`). `scripts/envoy-pcap.py` counts
each path's requests and replies by nonce, reading inside SRv6.

## The rollout

The new pod's claims are refused with `ClaimHeldByAnotherPod` while the old
pod runs, and with `maxUnavailable 0` the old pod runs until the new one is
Ready. The run records whether the new pod became Ready within
`REPLACE_TIMEOUT` (120 s) while the old pod ran. If it did not, that check
fails, and the run sets `maxUnavailable 1` so the rollout can finish and the
remaining checks still run.
