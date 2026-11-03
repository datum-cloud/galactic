# Galactic

[![CI](https://github.com/datum-cloud/galactic/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/datum-cloud/galactic/actions/workflows/ci.yaml)
[![Documentation](https://github.com/datum-cloud/galactic/actions/workflows/docs.yaml/badge.svg?branch=main)](https://github.com/datum-cloud/galactic/actions/workflows/docs.yaml)
[![Release](https://img.shields.io/github/v/release/datum-cloud/galactic)](https://github.com/datum-cloud/galactic/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/go.datum.net/galactic.svg)](https://pkg.go.dev/go.datum.net/galactic)
[![Go version](https://img.shields.io/github/go-mod/go-version/datum-cloud/galactic)](go.mod)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)

Galactic supplies SRv6 networking for multi-cloud VPC workloads on Kubernetes.
Its CNI plugins attach containers and VMs, its routing controllers distribute
EVPN paths, and optional edge components provide ingress load balancing,
NAT66/NAT64 egress and provider attachments.

## Start here

- [Documentation](docs/README.md): guides organized by task and component.
- [System overview](docs/overview.md): components, packet paths and ownership.
- [Local lab](docs/getting-started.md): build and exercise the multi-cluster topology.
- [Development](docs/development/README.md): build, test and contribution workflow.
- [API reference](docs/api/README.md): generated resource documentation.

## Build and test

Use a Linux development environment with the Go version in `go.mod`, Task,
clang/LLVM and the required kernel headers. The
[development container](.devcontainer/galactic/) provides a starting environment.

```sh
task build
task test:unit
```

Before opening a PR, run `task ci`. It includes a Kind lifecycle test and needs
Docker and the host networking prerequisites. Root-gated tests and feature
acceptance checks are additional tiers; see the [development guide](docs/development/README.md).

## Deployment

Reusable Kubernetes manifests live in [config/](config/). The root Kustomization
includes the namespace, CNI and both tenant-router roles. It does not install
CRDs or assemble the underlay, controllers, optional edge services and
observability into a complete production deployment.

Follow the [component guides](docs/README.md#component-guides) and
[shared operations](docs/operations/README.md) for prerequisites, node opt-ins
and per-site overlays. Existing installations changing API groups must follow
the [migration guide](docs/operations/migrations/galactic-api-consolidation.md).

## License

See [LICENSE](LICENSE).
