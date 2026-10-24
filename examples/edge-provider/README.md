# Reference edge provider

A minimal Galactic Edge provider built only on the
[provider contract](../../docs/enhancements/networking/galactic-edge/contract.md):
the `galactic.datumapis.com/v1alpha1` edge resources, its own ServiceAccount,
and the attachment `galactic-edge` programs into its pod. It is a separate Go
module that imports only `go.datum.net/galactic/api/v1alpha1`; its module path
is outside `go.datum.net/galactic`, so the compiler refuses any import of the
core's internal packages.

For each `EdgeService` it is configured with, it:

1. creates its pod's `EdgeInstance` and holds the instance's lease, renewing it
   every 5 s;
2. requests an `EdgeAttachment` and, once `galactic-edge` reports it
   `Programmed`, answers UDP on the attachment's address (`SocketAccess`) and
   sets `Ready`;
3. for `PacketAccess`, opens the attachment's TUN device and answers ICMPv6
   echo and UDP for every address in the prefixes it claims;
4. claims an `EdgeRoute` for each configured prefix while its lease is held.

Every UDP reply starts with `<provider>/<pod>/<service>`, so a client can tell
which instance answered. On SIGTERM it stops forwarding, then releases its
routes, deletes its attachments and releases its lease. SIGUSR1 freezes it: it
stops renewing and writing to the API while its data planes keep answering,
past its lease's deadline too.
The conformance suite uses that to show that `galactic-edge` stops forwarding
on its own.

## Build

From the repository root:

```sh
cd examples/edge-provider && go test ./... && cd -
docker build -t <registry>/edge-provider:<tag> -f examples/edge-provider/Dockerfile .
```

The image copies in only `api/` and the root module's `go.mod` and `go.sum`
beside the provider.

## What the cell needs

| Prerequisite | Why | Who |
| --- | --- | --- |
| `config/galactic-edge` applied, `galactic-controller --role=cell --edge`, and the `galactic-edge` DaemonSet on nodes labeled `galactic.datumapis.com/node=edge` and `galactic.datumapis.com/edge=enabled` | Admission, allocation, programming and the forwarding gate | Operator |
| A device plugin that gives pods `/dev/net/tun` as a resource | Kubernetes gives no unprivileged pod `/dev/net/tun`, and the contract gives a provider no hostPath or capability. Only `PacketAccess` needs it. | Operator |
| A workload of the VPC on the provider's node | An attachment joins the VPC's existing host VRF on its node; only CNI ADD creates that VRF | Tenant or platform |
| An `EdgeService` granting the VPC to the provider | Authorizes the attachment and its prefixes | Platform authority |

The containerlab lab's `deploy:galactic-edge` task sets all of this up on dfw;
see `deploy/containerlab/resources/galactic-edge/`, including the
`tun-device-plugin` it uses.

## Register the provider (operator)

`deploy/registration` holds the `EdgeProvider`. Overlay its name, the namespace
of its ServiceAccount, and the contract and capability versions it implements,
then approve it:

```sh
kubectl apply -k <your registration overlay>
kubectl patch edgeprovider <name> --subresource=status --type=merge -p '{"status":{"approved":true}}'
```

Approval makes `galactic-controller` bind the provider's ServiceAccounts to the
`galactic-edge-provider` role and admission policy. Until then, every write
the provider makes is refused.

## Configure

The provider reads `config.yaml`. A provider cannot read an `EdgeService`,
which lives in the VPC's namespace, so the deployer copies each service's UID
and its VPC's UID from the grant:

```yaml
provider: example-echo          # the EdgeProvider this pod runs as
port: 7777                      # UDP port of the attachment-address echo
services:
  - namespace: tenant-a         # the EdgeService's namespace
    name: echo
    uid: <kubectl get edgeservice echo -n tenant-a -o jsonpath='{.metadata.uid}'>
    vpcUID: <kubectl get vpc <vpc> -n tenant-a -o jsonpath='{.metadata.uid}'>
    capabilities: [SocketAccess, PacketAccess]
    prefixes: ["fd00:ed9e:100:1::/64"]   # inside the grant; needs PacketAccess
```

## Deploy (provider)

`deploy/provider` holds the ServiceAccount and Deployment. An overlay sets the
namespace, image and configuration, and requests the TUN device:

```yaml
namespace: edge-echo
resources:
  - <path to examples/edge-provider/deploy/provider>
images:
  - name: edge-provider
    newName: <registry>/edge-provider
    newTag: <tag>
configMapGenerator:
  - name: edge-provider-config
    files:
      - config.yaml
patches:
  - target:
      kind: Deployment
    patch: |-
      - op: add
        path: /spec/template/spec/containers/0/resources
        value: {limits: {devic.es/tun: "1"}}   # your device plugin's resource
```

The pod runs as 65532:65532 with every capability dropped, a read-only root
filesystem, and no host namespace or hostPath. If the cell taints its edge
nodes, the overlay also adds the tolerations they need; the Deployment
schedules only onto nodes labeled to run `galactic-edge`.

## Check it

```sh
kubectl -n edge-echo get edgeinstances,edgeattachments,edgeroutes
kubectl -n edge-echo logs deploy/edge-provider
```

An attachment is serving when `Programmed` and `Ready` are both True. A route
forwards once `Accepted` is True; the first route in a VPC waits about 16 s for
its index to settle. From a workload of the VPC, a UDP datagram to any address
in the prefix on port 7777 comes back prefixed with the provider's identity.

## Route names

Every instance of the provider must contend for a prefix through the same
`EdgeRoute`, so the name is derived the same way everywhere: `er-` and the first
16 bytes, in hex, of the SHA-256 of the VPC UID, a slash and the masked prefix.
Another provider may derive its names differently. An instance whose claim
another instance has replaced has nothing to release when it shuts down: the
other instance takes over once this one's gate is confirmed closed, which
deleting its attachment does. Core finds routes by their
spec, and its overlap check keeps two providers' routes for one prefix apart.

## Conformance

`tests/edgeconformance` runs the contract's failure-test matrix against this
provider in the containerlab lab: `task deploy:galactic-edge`, then
`task verify:edge-conformance` from `deploy/containerlab`.
