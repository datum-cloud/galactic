# Repository guidelines

## Start with the maintained docs

[docs/README.md](docs/README.md) is the human-facing documentation index.
[docs/overview.md](docs/overview.md) describes component and repository ownership.
Use the guide matching the subsystem you change:

| Subsystem                                  | Guide                                                                                             | Main source areas                                                                                             |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| CNI attach/detach, installer, IPAM         | [CNI architecture](docs/cni/architecture.md)                                                      | `cmd/galactic-{cni,veth,tap,ipam,bgp,route}`, `internal/cni*`, `internal/installer`                           |
| Tenant BGP/EVPN, route installation, GC    | [Router architecture](docs/router/architecture.md)                                                | `cmd/galactic-router`, `internal/controller`, `internal/reconcile`, `internal/runtime`, `internal/gc`         |
| Ingress VIPs, DSR, backend health          | [Gateway architecture](docs/gateway/architecture.md)                                              | `cmd/galactic-gateway`, `internal/gateway`, edge eBPF packages                                                |
| NAT66/NAT64, shard membership              | [NAT configuration](docs/nat/configuration.md), [active/active egress](docs/nat/active-active.md) | `cmd/galactic-nat`, `internal/installer/egressgroup.go`, NAT eBPF packages                                    |
| Cluster controllers and identity           | [Controller roles](docs/controller/README.md)                                                     | `cmd/galactic-controller`, `internal/cloud`, `internal/trafficpolicy`                                         |
| Provider attachments and gates             | [Edge contract](docs/edge/provider-contract.md)                                                   | `cmd/galactic-edge`, `internal/edge`                                                                          |
| Private service delivery                   | [Private services](docs/private-services/README.md)                                               | service-route controller and datapath packages                                                                |
| FRR configuration and typed fabric routing | [Fabric routing](docs/fabric-routing/README.md)                                                   | `cmd/fabric-config-agent`, `cmd/fabric-router-controller`, `internal/fabricconfig`, `internal/fabric/routing` |
| FRR diagnostics, probes, mTLS and queries  | [Fabric API architecture](docs/fabric-api/architecture.md)                                        | `cmd/fabric-api`, `internal/fabric`, `api/fabric`                                                             |

For tasks in `deploy/containerlab/`, also read its local `AGENTS.md`.

## Development and code standards

Follow [coding conventions](docs/development/conventions.md) and the
[development guide](docs/development/README.md). The Taskfile and workflows are
the source of truth for commands and tool versions.

```sh
task build          # regenerate eBPF, format, vet, build binaries
task test:unit      # race-enabled unit tests; privileged tests may skip
task test:unit-root # real-kernel tests in a privileged development environment
task test:e2e       # Kind lifecycle test
task test:alerts    # promtool alert tests
task lint          # Go and YAML checks
task ci            # required before every PR: lint, build, unit, e2e
```

Run the additional checks appropriate to the changed subsystem. Report skipped
or unavailable checks explicitly. The unprivileged suite does not establish
kernel datapath correctness, and a lab result does not establish production
qualification.

- Keep Go formatting and imports consistent with `.golangci.yaml`.
- Never hand-edit committed protobuf bindings (`*.pb.go`, `*_grpc.pb.go`).
- Regenerate CRDs, deepcopy methods and API references when their sources change.
- Use `.yaml`, never `.yml`.
- Align Markdown tables as required by the coding conventions.
- Use Conventional Commits. Keep the subject at most 72 characters.

## Ownership and deployment constraints

Galactic reads and writes the consolidated `galactic.datumapis.com` resources.
The NSO cell manager owns VPC/attachment/subnet reconciliation and NAD generation
when Galactic integration is enabled. Galactic's cell controller owns BGP status
projection, admission and traffic-policy resolution, with opt-in Edge controllers.
Its fabric role runs the central identity allocator separately with hub and IPAM
credentials. Check command registration before inferring ownership from package
names or historical documentation.

`config/kustomization.yaml` includes only the namespace, CNI and router resources.
Install CRDs first. Underlay, controllers, gateway, NAT, fabric diagnostics,
monitoring and Edge have separate prerequisites. Read their deployment guides
before changing composition; several top-level component Kustomizations apply
only RBAC and deliberately exclude bases requiring deployment-specific values.

[Node labels](docs/operations/node-labels.md) are the canonical placement rules.
`node=compute` and `node=edge` are roles; `galactic=router|control` and
`fabric=router|control` are independent mode enums. Gateway, NAT and Edge require
their own opt-ins on edge nodes. Sharing an uplink's XDP hook also requires the
correct dispatcher configuration; consult [XDP mode](docs/operations/xdp-attach-mode.md).

Production images and the configuration bundle are published by
`.github/workflows/publish.yaml` using per-component Dockerfiles. `task build`
does not publish a release. The CNI Dockerfile is also used by the e2e test.

## Documentation changes

Follow [documentation maintenance](docs/development/documentation.md). Update a
canonical guide instead of appending another copy of configuration tables or
incident history here. Keep current behavior, proposed work and dated evidence
distinct. Preserve useful compatibility links when moving pages, and regenerate
rendered diagrams with their sources.
