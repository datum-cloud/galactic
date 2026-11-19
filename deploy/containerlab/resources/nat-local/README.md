# nat-local: a local and a remote NAT shard for one VPC

`task verify:nat-local-shard` runs this fixture
([#1437](https://github.com/datum-cloud/galactic/issues/1437)). It adds a guest
to each `ns80` VPC on `dfw-worker2`, an edge node that also runs an egress
shard. The two guests have the same address. galactic-worker runs on
`dfw-worker2`, and galactic-nat claims a service-internal veth pair per VPC
there ([Local NAT shards](../../../../docs/worker/contract.md#local-nat-shards)).
The guests then reach `remote-host` through their own node's shard (Local) and
through `dfw-worker3`'s (Fabric).

| Resource                | Purpose                                                                      |
| ----------------------- | ---------------------------------------------------------------------------- |
| `nad.yaml`              | `vpc-a-edge` and `vpc-b-edge`, attachment 802 in VPC 80 and 81, one address  |
| `vpcattachments.yaml`   | Their VPCAttachments, with the address the Local pair returns to             |
| `bindings.yaml`         | Traffic policy for both, the same as the other `ns80` guests                 |
| `guests.yaml`           | The guests, pinned to `dfw-worker2` and tolerating its NAT taint             |
| `allowlist.yaml`        | Worker's allowlist: galactic-router's routes and galactic-nat's shard claims |
| `nat-worker-patch.yaml` | Lab-only: galactic-nat's Worker socket, projected token and flags            |

The check runs Worker, which takes over every VPC scope on its node and never
hands one back. It therefore ends with `task destroy`, `task deploy`,
`task deploy:ns80` and `task baseline:twice`, which must match the committed
reference.
