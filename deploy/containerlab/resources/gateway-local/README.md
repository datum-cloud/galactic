# gateway-local: Local and Fabric VIP backends through each gateway

`task verify:gateway-local` runs this fixture
([#1438](https://github.com/datum-cloud/galactic/issues/1438)). It adds a
TAP-backed guest in `ns80`'s VPC 80 on each of dfw's edge nodes, so a gateway
node also hosts backends, and serves `ns80`'s `vpc-a` and `vpc-a2` as backends
too. galactic-worker runs on `dfw-worker2` and `dfw-worker3`, and each
gateway claims a `local.tap` handoff for the backends on its own node
([Worker contract](../../../../docs/worker/contract.md)). Through each gateway
in turn, the backend on that gateway's node is Local and the other three are
Fabric.

| Backend | Runs on       | Attachment             | Address               | VIPs                                   |
| ------- | ------------- | ---------------------- | --------------------- | -------------------------------------- |
| `w1`    | `dfw-worker`  | `ns80/vpc-a` (veth)    | `fd20:80:ff01::1:0:0` | `2001:db8:6060:1::11`, `198.51.100.11` |
| `w2`    | `dfw-worker2` | `ns80/gwlocal-w2` (88) | `fd20:80:ff01::4:0:0` | `2001:db8:6060:1::12`, `198.51.100.12` |
| `w3`    | `dfw-worker3` | `ns80/gwlocal-w3` (89) | `fd20:80:ff01::5:0:0` | `2001:db8:6060:1::13`, `198.51.100.13` |
| `w4`    | `dfw-worker4` | `ns80/vpc-a2` (veth)   | `fd20:80:ff01::2:0:0` | `2001:db8:6060:1::14`, `198.51.100.14` |
| pool    | all four      | port 81 on each        |                       | `2001:db8:6060:1::10`, `198.51.100.10` |

| Resource                    | Purpose                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `nad.yaml`                  | `gwlocal-w2` and `gwlocal-w3`, galactic-tap attachments 88 and 89 in VPC 80         |
| `vpcattachments.yaml`       | Their VPCAttachments, with addresses and the labels the services select             |
| `policies.yaml`             | PublicService both ways, any source (`64:ff9b::/96` too), plus `ns80`'s own grants  |
| `bindings.yaml`             | The edge guests' bindings to those policies                                         |
| `guests.yaml`               | The TAP guests: a hypervisor stand-in and a responder, pinned to one edge node each |
| `networkservices.yaml`      | A TCP and a UDP rule per backend, and the pool's                                    |
| `allowlist.yaml`            | Worker's allowlist: galactic-router's routes and galactic-gateway's `local.tap`     |
| `gateway-worker-patch.yaml` | Lab-only: the dfw gateways' Worker socket, token, and backend health on             |

For its duration the script also labels `vpc-a` and `vpc-a2` for the
services, binds them to this fixture's policies, and starts the same
responder in them. Each responder answers TCP and UDP on ports 80 and 81
with its backend's node name and the client address it saw, as `ns60`'s
backends do.

Worker needs no RBAC in the lab: it runs with the cluster's admin kubeconfig
(`scripts/worker-fabric.sh`), and its `--gateway-namespace` default,
`galactic-system`, is where the bindings it resolves backends from are.

The egress shards' counters carry no VPC label, so the isolation checks
compare each shard's totals and assume nothing else uses the shards while
the check runs. A rule whose only backend is reported Unhealthy keeps that
backend, so the failure steps send traffic to the pool rather than to `w2`'s
own VIP.

The public-path step also withdraws `dfw-worker2`'s FRR origination of the
site's VIP `/64` and `/26` (`network` in AS 65000), one family at a time,
with `vtysh` in its fabric-router pod; the fabric-router ConfigMap is not
edited. The gateway cannot withdraw that aggregate itself, since it is FRR
configuration rather than a BGPAdvertisement. The script's exit trap and
`--unpin` re-add both statements.

The check runs Worker, which takes over every VPC scope on its node and never
hands one back. It therefore ends with `task destroy`, `task deploy` and
`task baseline:twice`, which must match the committed reference.
