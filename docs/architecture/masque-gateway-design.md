# MASQUE Gateway Architecture

## Executive Summary

This document describes the MASQUE Gateway, an ingress component that bridges external clients to the SRv6-based Galactic VPC fabric. The gateway enables secure, NAT-traversing connectivity from diverse clients into VPC workloads using modern protocols.

### Design Philosophy

**Bet on the future, bridge to the present.**

- **MASQUE as the protocol standard** - IETF-standard tunneling (RFC 9484 CONNECT-IP)
- **Iroh for connectivity** - NAT traversal, hole punching, relay infrastructure
- **SRv6 as the underlay** - Internal VPC fabric routing
- **Extensible connectors** - Support multiple protocols through a common interface

### Key Insight: Iroh + MASQUE Convergence

Rather than choosing between Iroh and MASQUE, the architecture leverages both:

- **Iroh provides connectivity** - NAT traversal, hole punching, public key identity, relay infrastructure
- **MASQUE provides the protocol** - IETF standard, browser support, firewall traversal

This means Iroh relays can evolve to speak MASQUE, giving us the best of both worlds.

---

## Strategic Direction

### Protocol Convergence

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Current State                                    │
│                                                                         │
│  Iroh (custom protocol)          MASQUE (IETF standard)                 │
│  ├─ Great NAT traversal          ├─ HTTP/3 based                        │
│  ├─ Hole punching                ├─ Browser support (WebTransport)      │
│  ├─ Public key identity          ├─ Firewall friendly (port 443)        │
│  ├─ Relay infrastructure         ├─ Apple/Cloudflare proven             │
│  └─ Custom QUIC protocol         └─ IP tunneling (CONNECT-IP)           │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                        Future State                                     │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Iroh + MASQUE                                │    │
│  │                                                                 │    │
│  │  ┌────────────────────────────────────────────────────────────┐ │    │
│  │  │ MASQUE Protocol Layer (IETF standard)                      │ │    │
│  │  │  - CONNECT-IP for VPC ingress                              │ │    │
│  │  │  - CONNECT-UDP for relay                                   │ │    │
│  │  │  - CONNECT-TCP for HTTP proxying                           │ │    │
│  │  └────────────────────────────────────────────────────────────┘ │    │
│  │                              │                                  │    │
│  │  ┌────────────────────────────────────────────────────────────┐ │    │
│  │  │ Iroh Connectivity Layer                                    │ │    │
│  │  │  - NAT traversal / hole punching                           │ │    │
│  │  │  - Relay fallback (now speaking MASQUE)                    │ │    │
│  │  │  - Public key identity                                     │ │    │
│  │  │  - Connection migration                                    │ │    │
│  │  └────────────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why This Approach?

| Question | Answer |
|----------|--------|
| Why keep Iroh? | Best-in-class NAT traversal, P2P hole punching, you're already running relays |
| Why add MASQUE? | IETF standard, browser support, firewall traversal, IP-level tunneling |
| Why not just MASQUE? | Lose Iroh's P2P capabilities and relay infrastructure |
| Why not just Iroh? | Custom protocol, no browser support, HTTP-level only |

### Migration Path

1. **Today**: Iroh native protocol for HTTP proxying (dev tunnels)
2. **Next**: Add MASQUE CONNECT-IP capability for VPC ingress
3. **Future**: Iroh relays speak MASQUE, unifying the protocol stack

---

## System Architecture

### High-Level View

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            External Clients                             │
│                                                                         │
│  [Browser]    [Mobile App]    [CLI/Desktop]    [IoT Device]             │
│  WebTransport    MASQUE         Iroh/MASQUE      Iroh                   │
│                                                                         │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │    Iroh Relays        │
                    │  (MASQUE-speaking)    │
                    │                       │
                    │  - NAT traversal      │
                    │  - CONNECT-UDP relay  │
                    │  - Global distribution│
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │    MASQUE Gateway     │
                    │                       │
                    │  - CONNECT-IP termination
                    │  - Session management │
                    │  - SRv6 bridge        │
                    └───────────┬───────────┘
                                │
                    ┌───────────▼───────────┐
                    │    VPC Fabric         │
                    │      (SRv6)           │
                    │                       │
                    │  [Workloads]          │
                    └───────────────────────┘
```

### Components

| Component | Purpose |
|-----------|---------|
| **Iroh Relays** | NAT traversal, MASQUE CONNECT-UDP relay, global presence |
| **MASQUE Gateway** | CONNECT-IP termination, authentication, SRv6 bridging |
| **SRv6 Bridge** | Translate between client IP packets and VPC fabric |
| **Session Manager** | Track connections, enforce policies, allocate addresses |

---

## Protocol Stack

### MASQUE Protocol Family

| Protocol | RFC | Purpose |
|----------|-----|---------|
| CONNECT-IP | RFC 9484 | Full IP tunnel (VPN mode) - primary for VPC ingress |
| CONNECT-UDP | RFC 9298 | UDP proxying - used for relay |
| CONNECT-TCP | HTTP CONNECT | TCP proxying - HTTP-level access |

### Connection Flow

```
Client                     Relay                      Gateway                VPC
  │                          │                          │                     │
  │──Iroh hole punch────────►│                          │                     │
  │  (direct if possible)    │                          │                     │
  │                          │                          │                     │
  │──MASQUE CONNECT-UDP─────►│ (if relay needed)        │                     │
  │                          │                          │                     │
  │──────────────────────────┼──MASQUE CONNECT-IP──────►│                     │
  │                          │                          │                     │
  │◄─────────────────────────┼──ADDRESS_ASSIGN──────────│                     │
  │◄─────────────────────────┼──ROUTE_ADVERTISEMENT─────│                     │
  │                          │                          │                     │
  │══════════════════════════╪══IP Packets══════════════╪═════SRv6═══════════►│
  │                          │                          │                     │
```

---

## Resource Model

Aligned with the [Datum Connectors proposal](../../../enhancements/enhancements/networking/connectors/initial-proposal/README.md).

### Resource Relationships

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Control Plane                               │
│                                                                     │
│  ┌─────────────┐      ┌─────────────────────┐      ┌─────────────┐  │
│  │  Connector  │─────►│ ConnectorAttachment │◄─────│     VPC     │  │
│  │  (client)   │      │     (binding)       │      │  (network)  │  │
│  └─────────────┘      └─────────────────────┘      └─────────────┘  │
│        │                       │                          │         │
│        ▼                       ▼                          ▼         │
│  ┌─────────────┐      ┌─────────────────┐         ┌─────────────┐   │
│  │ Connector   │      │ VPCIngressPoint │         │VPCAccessPol │   │
│  │Advertisement│      │ (gateway config)│         │    icy      │   │
│  └─────────────┘      └─────────────────┘         └─────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Resources

| Resource | From | Purpose |
|----------|------|---------|
| `Connector` | Connectors proposal | Represents client device, defines capabilities |
| `ConnectorAdvertisement` | Connectors proposal | Networks reachable through connector (outbound) |
| `ConnectorAttachment` | This design | Binds connector to VPC (inbound) |
| `VPCIngressPoint` | This design | Gateway configuration per VPC |
| `VPCAccessPolicy` | This design | Fine-grained authorization rules |

### Example: Connector with MASQUE Capability

```yaml
apiVersion: networking.datumapis.com/v1alpha1
kind: Connector
metadata:
  name: developer-laptop
spec:
  connectorClassName: datum-connect
  capabilities:
    - type: MASQUE
      enabled: true
    - type: CONNECT-IP
      enabled: true
    - type: CONNECT-UDP
      enabled: true
status:
  connectionDetails:
    type: PublicKey
    publicKey:
      id: 2ovpybgj3snjmchns44pfn6dbwmdiu4ogfd66xyu72ghexllv6hq
      homeRelay: https://relay.datum.net
```

### Example: Attaching Connector to VPC

```yaml
apiVersion: networking.datumapis.com/v1alpha1
kind: ConnectorAttachment
metadata:
  name: developer-to-vpc
spec:
  connectorRef:
    name: developer-laptop
  vpcRef:
    name: production-vpc
  ipAllocation:
    mode: Dynamic
  allowedRoutes:
    - 10.0.0.0/16
status:
  assignedIP: 10.0.100.50
  phase: Connected
```

---

## SRv6 Integration

### Bridge Operation

The gateway translates between client IP packets and SRv6-encapsulated packets:

```
Client IP Packet                    SRv6 Packet (to VPC)
┌─────────────────┐                 ┌─────────────────────────┐
│ src: 10.0.100.50│      SRv6       │ IPv6: fc00::gateway     │
│ dst: 10.0.2.100 │  ──────────►    │        → fc00::vpc:node │
│ [payload]       │    Bridge       │ SRH: [fc00::vpc:node]   │
└─────────────────┘                 │ [original IP packet]    │
                                    └─────────────────────────┘
```

### Bridge Modes

| Mode | Performance | Use Case |
|------|-------------|----------|
| Kernel (VRF + seg6) | Good | Default, universal compatibility |
| eBPF/XDP | High | Production gateways |
| AF_XDP | Highest | Maximum throughput requirements |

---

## Current Iroh Architecture Integration

### Today's Architecture (datum-connect)

```
                    ┌─────────────────────────┐
                    │     Iroh Relay          │
                    │  (iroh native protocol) │
                    └───────────┬─────────────┘
                                │
┌──────────────┐                │                ┌──────────────┐
│ datum-connect│◄═══════════════╪═══════════════►│    Envoy     │
│  (desktop)   │  Iroh QUIC     │                │   Gateway    │
│              │                │                │              │
│ ListenNode   │                │                │ Iroh Gateway │
│              │                │                │  (sidecar)   │
└──────────────┘                │                └──────────────┘
                                │
                           HTTP Proxying
                        (absolute-form requests)
```

### Evolution to MASQUE

```
                    ┌─────────────────────────┐
                    │     Iroh Relay          │
                    │  (MASQUE CONNECT-UDP)   │  ◄── Protocol change
                    └───────────┬─────────────┘
                                │
┌──────────────┐                │                ┌──────────────┐
│ datum-connect│◄═══════════════╪═══════════════►│   MASQUE     │
│              │  MASQUE        │                │   Gateway    │
│              │  CONNECT-IP    │                │              │
│ + VPC attach │                │                │ + SRv6 bridge│
└──────────────┘                │                └──────────────┘
                                │
                        IP Tunneling + HTTP Proxying
```

### What Changes

| Component | Current | Future |
|-----------|---------|--------|
| Relay protocol | Iroh native | MASQUE CONNECT-UDP |
| Application protocol | Iroh HTTP-connect | MASQUE CONNECT-IP/TCP |
| Gateway | Iroh Gateway (HTTP proxy) | MASQUE Gateway (IP tunnel + HTTP) |
| Client | datum-connect (Iroh only) | datum-connect (MASQUE capability) |
| VPC integration | None | ConnectorAttachment + SRv6 |

### What Stays

| Capability | Preserved |
|------------|-----------|
| NAT traversal | Yes - Iroh's hole punching |
| Relay infrastructure | Yes - your relays, new protocol |
| Public key identity | Yes - connection details unchanged |
| P2P direct connections | Yes - hole punch when possible |
| Control plane integration | Yes - same Connector CRD |

---

## Client SDK (datum-connect)

### Capabilities

The datum-connect client gains MASQUE capability:

```yaml
# Connector status shows available capabilities
status:
  capabilities:
    - type: MASQUE
      conditions:
        - type: Ready
          status: "True"
    - type: CONNECT-IP      # VPC ingress
      conditions:
        - type: Ready
          status: "True"
    - type: CONNECT-TCP     # HTTP proxying (current)
      conditions:
        - type: Ready
          status: "True"
```

### CLI Usage

```bash
# Current: HTTP proxying (unchanged)
datum-connect tunnel --local 8080 --name my-tunnel

# New: VPC attachment
datum-connect attach --vpc production-vpc

# Show status
datum-connect status
# Connector: developer-laptop (Ready)
# Protocol: MASQUE
# VPC Attachments:
#   - production-vpc: 10.0.100.50 (Connected)
# HTTP Tunnels:
#   - my-tunnel: localhost:8080 → https://my-tunnel.example.com
```

---

## Implementation Phases

### Phase 1: Foundation

- MASQUE CONNECT-IP listener in gateway
- `ConnectorAttachment` and `VPCIngressPoint` CRDs
- Kernel-mode SRv6 bridge
- MASQUE capability in datum-connect

### Phase 2: Relay Evolution

- Iroh relays speak MASQUE CONNECT-UDP
- Unified protocol stack
- Browser connectivity via WebTransport

### Phase 3: Production

- eBPF/XDP bridge acceleration
- Multi-gateway HA
- Mobile SDKs

---

## Open Questions

1. **Iroh upstream changes**: Does Iroh need modifications to support MASQUE, or can we layer it?

2. **Relay protocol migration**: How do we migrate existing relays from Iroh-native to MASQUE?

3. **Browser path**: WebTransport speaks HTTP/3 - is that sufficient, or do we need full MASQUE in browsers?

4. **Gateway base**: Build on quic-go (lightweight) or Envoy (battle-tested)?

---

## References

### Internal
- [Datum Connectors Proposal](../../../enhancements/enhancements/networking/connectors/initial-proposal/README.md)
- [Galactic VPC v2 Architecture](./v2-design.md)

### MASQUE
- [RFC 9484: CONNECT-IP](https://datatracker.ietf.org/doc/rfc9484/)
- [RFC 9298: CONNECT-UDP](https://datatracker.ietf.org/doc/rfc9298/)
- [Cloudflare: Zero Trust WARP with MASQUE](https://blog.cloudflare.com/zero-trust-warp-with-a-masque/)

### Connectivity
- [Iroh Documentation](https://www.iroh.computer/docs)
- [Datum Connect](https://github.com/datum-cloud/datum-connect)

### SRv6
- [RFC 8986: SRv6 Network Programming](https://datatracker.ietf.org/doc/html/rfc8986)
