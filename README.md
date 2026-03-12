# Galactic

**Multi-cloud networking for Kubernetes, simplified.**

Galactic connects Kubernetes workloads across multiple clouds and regions as if they were on a single, unified network. It provides secure, isolated Virtual Private Clouds (VPCs) that span cloud boundaries—without vendor lock-in or complex configuration.

## The Problem

Modern organizations run workloads everywhere: AWS, Azure, GCP, on-premises, and edge locations. Each environment brings its own networking model, APIs, and constraints. The result is fragmented networks, operational complexity, and cloud provider lock-in.

## Our Approach

Galactic extends Kubernetes with two simple resources—VPCs and VPCAttachments—that let you define multi-cloud network topology declaratively:

```yaml
apiVersion: networking.datum.net/v1alpha1
kind: VPC
metadata:
  name: production
spec:
  ipv4CIDRBlocks:
    - 10.100.0.0/16
```

Any pod can join the VPC with a single annotation:

```yaml
metadata:
  annotations:
    networking.datum.net/vpc-attachment: us-west
```

That's it. Your pod now has an interface connected to the VPC, able to communicate with any other attached workload—regardless of which cloud or region it's running in.

Under the hood, Galactic uses Segment Routing over IPv6 (SRv6) for efficient, deterministic routing and Virtual Routing and Forwarding (VRF) for true network isolation at the kernel level.

## Why Galactic

**For Developers** — Attach to a VPC with a single annotation. No networking code, no cloud-specific APIs.

**For Platform Teams** — Manage multi-cloud networking from Kubernetes using GitOps workflows and standard tooling.

**For Organizations** — Move workloads between providers without network redesign. One networking model instead of N cloud-specific implementations.

## Getting Started

See the [`lab/`](./lab/) directory for example topologies and the [DevContainer](./.devcontainer/) for development environment setup.

## License

See [LICENSE](./LICENSE) for details.

---

*Galactic is developed by [Datum](https://datum.net).*
