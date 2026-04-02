# Galactic VPC Integration - Phase 1

This document outlines the work required to integrate Galactic VPC into the Datum Cloud platform and bring it to consumers.

## Dependencies (Not Yet Implemented)

- **Machine Accounts** - Non-human identity for connectors, gateways, and service components to authenticate to the platform
- **IPAM Platform Capability** - Address pool allocation system (enhancement exists, needs implementation)
- **Activity System** - Audit trail infrastructure for VPC operations
- **Quota Platform Capability** - Resource limit enforcement for VPCs, attachments, routes
- **BGP Infrastructure** - GoBGP deployment, route reflector topology (no existing implementation)

---

## Control Plane & Routing

- **Migrate from MQTT to BGP VPNv6** - Replace galactic-router MQTT-based distribution with GoBGP route reflectors for scalable, standards-based route distribution
- **Deploy route reflector topology** - HA route reflector cluster with peering to galactic-agents on each node
- **Implement BGP-based VPN signaling** - Use MP-BGP for VPNv4/VPNv6 route exchange with RT/RD for VPC isolation
- **Network Services Operator integration** - Connect to existing network services operator for programming VPC networks

## Ingress & Gateways

- **Envoy Gateway VPC attachment** - Attach Envoy Gateway pods to VPC networks for HTTP ingress from internet
- **MASQUE gateway integration** - Deploy MASQUE gateways as VPC ingress points for connector tunnels
- **Gateway API resource mapping** - Map HTTPRoute/TCPRoute to VPC backend services

## Egress & NAT

- **Egress gateway design** - Architecture for outbound internet connectivity from private VPC networks
- **NAT gateway implementation** - Source NAT for private VPC traffic with IPAM-allocated public IPs
- **Egress policy controls** - Define what destinations VPC workloads can reach

## Connectors & Client Access

- **Iroh + MASQUE client update** - Update desktop app to use Iroh transport with MASQUE tunneling
- **Headless datum-connect** - Server-deployable connector for private network integration
- **Connector authentication via Machine Accounts** - Connectors authenticate to platform using machine identity
- **ConnectorAdvertisement registration** - Register reachable networks through each connector instance
- **ConnectorAttachment for VPCs** - Associate connectors with specific VPC networks

## Security & Policy

- **Network Policy enforcement** - VPC-level traffic control via galactic-agent (eBPF or iptables)
- **Security Groups** - Stateful firewall rules per VPC attachment
- **IAM integration** - Role-based access for VPC/attachment/route operations
- **Audit logging** - Activity records for all VPC mutations (depends on Activity system)

## IPAM Integration

- **VPC CIDR allocation** - Allocate VPC network ranges from IPAM AddressPools
- **Subnet allocation** - Subdivide VPC CIDRs into subnets via hierarchical IPAM
- **Public IP allocation** - IPAM-managed public IPs for egress gateways and load balancers

## User Interface

- **VPC management console** - Create/manage VPCs, view topology and connectivity
- **Connector dashboard** - Status, advertisements, tunnel health
- **Gateway management** - HTTP routes, certificates, scaling configuration
- **Network visualization** - Topology graph showing VPCs, routes, peering

## Operational Maturity

- **Deployment automation** - Kustomize manifests, FluxCD GitOps, multi-cluster rollout
- **Observability stack** - Prometheus metrics, distributed tracing, log aggregation for all components
- **Route reflector HA** - Clustered BGP RRs with graceful restart
- **Health dashboards** - Grafana views for route convergence, connectivity, capacity
- **Alerting** - Route flapping, connectivity loss, BGP session failures

## Platform Alignment

- **VPC as platform capability** - Integrate with quota, telemetry, activity patterns
- **Managed service VPC isolation** - Separate service infrastructure from consumer VPCs
- **Multi-region VPC spanning** - VPCs that span clusters with region-aware routing
- **Traffic metering for billing** - Egress/ingress byte counts per VPC for consumption billing

---

## Enhancements Unblocked by VPC Integration

- **Service Connect** - Private connectivity between control planes now has underlying network transport; ServicePublication/ServiceEndpoint can route through VPC networks
- **Datum Connectors** - Connector resources can attach to VPCs; ConnectorAdvertisement/ConnectorAttachment patterns become functional
- **Functions (VPC access)** - Functions can access resources in consumer VPCs via Service Connect reverse direction
- **Workloads (multi-network)** - Workload instances can attach to VPC networks for isolated compute
- **Global Multi-Cluster Network Platform** - VPC provides the concrete implementation for the network abstraction layer
- **Network Services Research** - Edge services, Cloud Router, and VPC network concepts become implementable
- **Authoritative DNS (private zones)** - Private DNS zones per VPC for internal service discovery
