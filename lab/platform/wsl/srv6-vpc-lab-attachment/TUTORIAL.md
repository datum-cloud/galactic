# Datum Galactic VPC Lab Tutorial
## The Complete Guide to SRv6, Kubernetes Networking, and Datum Cloud

---

**Author:** Sajjad Ahmed  
**Company:** Multi Naturals Inc.  
**Created:** January 2026  
**Version:** 1.2.0

---

> *"This guide is designed to be the definitive reference for anyone learning SRv6, Kubernetes networking, and Datum's Galactic VPC architecture. Clean, crisp, and comprehensive."*

---

## Table of Contents

1. [Scope & Target Audience](#scope--target-audience)
2. [Critical: Docker in WSL vs Docker Desktop](#critical-docker-in-wsl-vs-docker-desktop)
3. [Why This Setup? Benefits & Use Cases](#why-this-setup-benefits--use-cases)
4. [Understanding VPC (Virtual Private Cloud)](#understanding-vpc-virtual-private-cloud)
5. [Understanding SRv6](#understanding-srv6)
6. [Architecture Overview](#architecture-overview)
7. [Geo-Location & BGP Path Selection](#geo-location--bgp-path-selection)
8. [Prerequisites](#prerequisites)
9. [Step 1: Install WSL2](#step-1-install-wsl2)
10. [Step 2: Install Ubuntu](#step-2-install-ubuntu)
11. [Step 3: Install Docker (in WSL)](#step-3-install-docker)
12. [Step 4: Install Containerlab](#step-4-install-containerlab)
13. [Step 5: Install Netlab](#step-5-install-netlab)
14. [Step 6: Install K3s](#step-6-install-k3s)
15. [Step 7: Create the Topology](#step-7-create-the-topology)
16. [Step 8: Run the Lab](#step-8-run-the-lab)
17. [Step 9: Verify the Setup](#step-9-verify-the-setup)
18. [Step 10: Deploy Galactic-Agent](#step-10-deploy-galactic-agent)
19. [Step 11: Connect to Datum Cloud](#step-11-connect-to-datum-cloud-infrastructure)
20. [Step 12: Running the Lab with Python Scripts](#step-12-running-the-lab-with-python-scripts)
21. [MQTT Message Formats](#mqtt-message-formats)
22. [Troubleshooting](#troubleshooting)
23. [Reference Commands](#reference-commands)
24. [About the Author](#about-the-author)

---

## Scope & Target Audience

### Who This Guide Is For

- **Network Engineers** learning SRv6 and modern routing
- **DevOps/Platform Engineers** exploring Kubernetes networking
- **Students** preparing for network certifications (CCNP, JNCIE)
- **Developers** needing multi-region network simulation
- **Anyone with a Windows laptop** wanting to learn Datum Galactic VPC

### Prerequisites

- **Windows 10/11 laptop** with WSL2 support
- **8GB+ RAM** (16GB recommended)
- **Basic Linux command-line knowledge**
- **No prior SRv6 or Kubernetes experience required**

### What You Will Learn

1. SRv6 fundamentals and packet flow
2. ISIS and BGP routing protocols
3. Kubernetes networking with K3s
4. Datum Galactic VPC architecture
5. MQTT-based control plane communication

---

## Critical: Docker in WSL vs Docker Desktop

> **⚠️ IMPORTANT: You MUST install Docker inside WSL, NOT Docker Desktop for Windows!**

### Why Docker Desktop Won't Work

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Docker Desktop vs Docker in WSL                          │
│                                                                             │
│   Docker Desktop (Windows):                                                 │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Windows Host                                                        │   │
│   │    │                                                                │   │
│   │    ├── Docker Desktop (Hyper-V/WSL2 backend)                        │   │
│   │    │      │                                                         │   │
│   │    │      └── Containers run in separate VM                         │   │
│   │    │             ❌ Routes NOT visible to WSL Linux kernel         │    │
│   │    │             ❌ brctl/bridge commands don't work               │    │
│   │    │             ❌ SRv6 encapsulation fails                       │    │
│   │    │                                                                │   │
│   │    └── WSL Ubuntu                                                   │   │
│   │           ❌ Cannot see Docker networks                            │   │
│   │           ❌ Cannot program routes to containers                   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Docker in WSL (Correct):                                                  │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Windows Host                                                        │  │
│   │    │                                                                │  │
│   │    └── WSL Ubuntu                                                   │  │
│   │           │                                                         │  │
│   │           └── Docker Engine (native Linux)                          │  │
│   │                  │                                                  │  │
│   │                  └── Containers                                     │  │
│   │                         ✅ Routes visible in WSL kernel            │  │
│   │                         ✅ brctl/bridge commands work              │  │
│   │                         ✅ SRv6 encapsulation works                │  │
│   │                         ✅ galactic-agent can program routes       │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### If You Have Docker Desktop Installed

```bash
# Check which Docker context is active
docker context ls

# Example output:
# NAME            DESCRIPTION                               DOCKER ENDPOINT                             ERROR
# default         Current DOCKER_HOST based configuration   unix:///var/run/docker.sock
# desktop-linux   Docker Desktop                            npipe:////./pipe/dockerDesktopLinuxEngine
# native *                                                  unix:///run/docker.sock

# The asterisk (*) shows the ACTIVE context
# ✅ GOOD: "native *" or "default *" with unix:///var/run/docker.sock
# ❌ BAD:  "desktop-linux *" - Docker Desktop is active

# If desktop-linux is active, switch to native:
docker context use native
# Or use default:
docker context use default
```

---

## Why This Setup? Benefits & Use Cases

### Cost Savings

| Traditional Approach          | WSL Lab Approach               |
|-------------------------------|------------------------------- |
| $10,000+ for physical routers | **$0** - Uses existing laptop  |
| $500+/month for cloud VMs     | **$0** - Runs locally          |
| Weeks to procure hardware     | **Minutes** to deploy          |
| Limited to office/lab         | **Portable** - demo anywhere   |

### Real-World Use Cases

1. **Learning & Datum Certification Prep**
   - Practice SRv6, ISIS, BGP without expensive equipment
   - Safe sandbox to experiment and break things
   - Prepare for Datum Certification

2. **Network Design Validation**
   - Test topology changes before production deployment
   - Validate failover scenarios and routing policies
   - Prototype new architectures risk-free

3. **CI/CD for Network Automation**
   - Test Ansible playbooks against virtual routers
   - Integration testing for network-as-code
   - Automated regression testing

4. **Sales Engineering & Demos**
   - Portable demo environment on a laptop
   - Show customers SRv6/VPC concepts live
   - No dependency on production systems

5. **Development Environment**
   - Develop applications requiring multi-region networking
   - Test microservices across simulated data centers
   - Debug network-dependent code locally

---

## Understanding VPC (Virtual Private Cloud)

### What is a VPC?

A **Virtual Private Cloud (VPC)** is an isolated, private network within a shared infrastructure. Think of it as your own private section of the internet where only your traffic flows.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SHARED PHYSICAL INFRASTRUCTURE                               │
│                    (Datum's Global SRv6 Network)                                │
│                                                                                 │
│   ┌─────────────────────────────┐    ┌─────────────────────────────┐            │
│   │     CUSTOMER A's VPC        │    │     CUSTOMER B's VPC        │            │
│   │     (VPC ID: 000000001)     │    │     (VPC ID: 000000002)     │            │
│   │                             │    │                             │            │
│   │  ┌─────────┐  ┌─────────┐   │    │  ┌─────────┐  ┌─────────┐   │            │
│   │  │ SJC POP │  │ AMS POP │   │    │  │ IAD POP │  │ FRA POP │   │            │
│   │  │ Attach  │  │ Attach  │   │    │  │ Attach  │  │ Attach  │   │            │
│   │  │  0001   │  │  0002   │   │    │  │  0001   │  │  0002   │   │            │
│   │  └────┬────┘  └────┬────┘   │    │  └────┬────┘  └────┬────┘   │            │
│   │       │            │        │    │       │            │        │            │
│   │       └─────┬──────┘        │    │       └─────┬──────┘        │            │
│   │             │               │    │             │               │            │
│   │    VRF Table 100            │    │    VRF Table 200            │            │
│   │    192.168.1.0/24           │    │    10.0.0.0/8               │            │
│   │    192.168.2.0/24           │    │    172.16.0.0/12            │            │
│   │                             │    │                             │            │
│   │    ✅ COMPLETELY ISOLATED  |    │    ✅ COMPLETELY ISOLATED   │            │
│   │    Cannot see Customer B    │    │    Cannot see Customer A    │            │
│   └─────────────────────────────┘    └─────────────────────────────┘            │
│                                                                                 │
│   Same physical routers, same cables, but LOGICALLY SEPARATED!                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### How Datum Implements VPC

Datum uses **VRF (Virtual Routing and Forwarding)** combined with **SRv6** to implement VPCs:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    DATUM VPC IMPLEMENTATION                                     │
│                                                                                 │
│   1. VPC ID (48 bits)           2. VPCAttachment ID (16 bits)                   │
│      Identifies the customer       Identifies the POP location                  │
│      Example: 000000000001         Example: 0001 (SJC), 0002 (AMS)              │
│                                                                                 │
│   3. Combined into SRv6 Endpoint:                                               │
│      fc00:0000:0000:0000:VVVV:VVVV:VVVV:AAAA                                    │
│                         └─────VPC ID─────┘└─Attach─┘                            │
│                                                                                 │
│      Example: fc00::0000:0000:0001:0001                                         │
│               = VPC 000000000001, Attachment 0001 (SJC)                         │
│                                                                                 │
│   4. VRF Interface Created:                                                     │
│      G{vpc_base62}{attachment_base62}V                                          │
│      Example: G000000001001V (table 100)                                        │
│                                                                                 │
│   5. Routes programmed into VRF:                                                │
│      ip -6 route add 192.168.2.0/24 encap seg6 ... table 100                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### SRv6 Segments: Global vs Per-VPC

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    SRv6 SEGMENT TYPES                                           │
│                                                                                 │
│   GLOBAL SEGMENTS (Underlay)              PER-VPC SEGMENTS (Overlay)            │
│   ─────────────────────────               ──────────────────────────            │
│   Shared by ALL customers                 Unique to EACH customer               │
│                                                                                 │
│   fc00:0:1::/48 → SJC POP                fc00::0000:0000:0001:0001              │
│   fc00:0:2::/48 → IAD POP                = Customer A, SJC attachment           │
│   fc00:0:3::/48 → AMS POP                                                       │
│                                           fc00::0000:0000:0002:0001             │
│   These are the "roads"                   = Customer B, SJC attachment          │
│   Everyone uses the same                                                        │
│   physical paths                          These are the "destinations"          │
│                                           Each customer has unique ones         │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                                                                         │   │
│   │   Customer A packet:                                                    │   │
│   │   ┌──────────────────────────────────────────────────────────────────┐  │   │
│   │   │ IPv6 Header: Dst = fc00::0000:0000:0001:0002 (Customer A, AMS)   │  │   │
│   │   │ SRH: Segments = [fc00:0:3::] (Global: use AMS POP)               │  │   │
│   │   │ Payload: Customer A's data                                       │  │   │
│   │   └──────────────────────────────────────────────────────────────────┘  │   │
│   │                                                                         │   │
│   │   Customer B packet (same physical path, different VPC):                │   │
│   │   ┌──────────────────────────────────────────────────────────────────┐  │   │
│   │   │ IPv6 Header: Dst = fc00::0000:0000:0002:0002 (Customer B, AMS)   │  │   │
│   │   │ SRH: Segments = [fc00:0:3::] (Global: use AMS POP)               │  │   │
│   │   │ Payload: Customer B's data                                       │  │   │
│   │   └──────────────────────────────────────────────────────────────────┘  │   │
│   │                                                                         │   │
│   │   Both use fc00:0:3:: (AMS) but end up in DIFFERENT VRFs!               │   │
│   │                                                                         │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### VPC Isolation in Action

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    HOW VPC ISOLATION WORKS                                      │
│                                                                                 │
│   STEP 1: Packet arrives at POP with SRv6 destination                           │
│   ─────────────────────────────────────────────────────                         │
│   Dst: fc00::0000:0000:0001:0002 (Customer A, AMS attachment)                   │
│                                                                                 │
│   STEP 2: galactic-agent decodes the SRv6 endpoint                              │
│   ─────────────────────────────────────────────────────                         │
│   VPC ID:        000000000001 (from bits 16-63)                                 │
│   Attachment ID: 0002 (from bits 0-15)                                          │
│                                                                                 │
│   STEP 3: Agent looks up VRF interface                                          │
│   ─────────────────────────────────────────────────────                         │
│   VRF Name: G000000001002V                                                      │
│   VRF Table: 100                                                                │
│                                                                                 │
│   STEP 4: Packet delivered to Customer A's isolated network                     │
│   ─────────────────────────────────────────────────────                         │
│   Route lookup happens in TABLE 100 only                                        │
│   Customer B's routes (TABLE 200) are INVISIBLE                                 │
│                                                                                 │
│   RESULT: Complete network isolation on shared infrastructure!                  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Why This Matters

| Feature | Traditional VPN | Datum VPC with SRv6 |
|---------|-----------------|---------------------|
| **Isolation** | Encryption-based | VRF + SRv6 encoding |
| **Scalability** | Limited by tunnels | Millions of VPCs |
| **Performance** | Encryption overhead | Native IPv6 forwarding |
| **Flexibility** | Static tunnels | Dynamic segment routing |
| **Multi-tenancy** | Complex | Built into addressing |

---

## Understanding SRv6

### What is SRv6?

**Segment Routing over IPv6 (SRv6)** is a modern network architecture that uses IPv6 addresses as instructions for packet forwarding.

```
Traditional Routing:          SRv6 Routing:
┌─────────────────────┐       ┌─────────────────────────────────────┐
│ Packet: Dst=10.1.1.3│       │ Packet: Dst=fc00:0:3::1 (SRv6 SID)  │
│                     │       │ Payload: Original packet            │
│ Router looks up     │       │                                     │
│ routing table       │       │ SID = Segment ID = Instruction      │
│ at EVERY hop        │       │ "Deliver to node 3"                 │
└─────────────────────┘       └─────────────────────────────────────┘
```

### SRv6 Key Concepts

| Term | Definition |
|------|------------|
| **SID** | Segment ID - An IPv6 address that encodes a network instruction |
| **Locator** | The prefix portion of a SID (e.g., `fc00:0:1::/48`) identifying a node |
| **Function** | The suffix portion of a SID specifying what action to take |
| **Segment List** | Ordered list of SIDs defining the packet's path |
| **Encapsulation** | Wrapping original packet with SRv6 header |

### SRv6 SID Structure

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         SRv6 SID (128 bits)                              │
├────────────────────────────────┬─────────────────────────────────────────┤
│         Locator (48 bits)      │        Function + Args (80 bits)        │
│         fc00:0:1::             │        e000::                           │
├────────────────────────────────┼─────────────────────────────────────────┤
│ Identifies the NODE            │ Identifies the ACTION                   │
│ "Route to SJC"                 │ "End.X = forward to next-hop"           │
└────────────────────────────────┴─────────────────────────────────────────┘
```

### Common SRv6 Behaviors

| Behavior | Code | Description |
|----------|------|-------------|
| **End** | uN | Endpoint - decapsulate and process |
| **End.X** | uA | Endpoint with L3 cross-connect to next-hop |
| **End.DT4** | - | Decapsulate and lookup in IPv4 table |
| **End.DT6** | - | Decapsulate and lookup in IPv6 table |
| **H.Encaps** | - | Headend encapsulation with SRv6 header |

### How SRv6 Works in This Topology

```
Step 1: Packet arrives at SJC destined for 192.168.2.0/24 (AMS network)

Step 2: SJC looks up route, finds SRv6 encapsulation rule
        "To reach 192.168.2.0/24, encap with SID fc00:0:3::"

Step 3: Original packet wrapped with SRv6 header
        ┌─────────────────────────────────────────┐
        │ IPv6 Header: Dst = fc00:0:3::           │
        │ SRH: Segments = [fc00:0:3::]            │
        │ ┌─────────────────────────────────────┐ │
        │ │ Original IPv4: Dst = 192.168.2.1    │ │
        │ └─────────────────────────────────────┘ │
        └─────────────────────────────────────────┘

Step 4: Packet forwarded based on IPv6 destination (fc00:0:3::)
        IAD sees fc00:0:3:: → forwards to AMS

Step 5: AMS receives, sees its own locator (fc00:0:3::)
        Decapsulates, delivers original packet to 192.168.2.1
```

---

## Architecture Overview

### Lab Topology with Linux Bridge

Containerlab creates **Linux bridges** to connect FRR containers. There are two bridges:
1. **galactic_v_1** - VPC backbone bridge (MTU 9500 for jumbo frames)
2. **br-9b819b05be4c** (netlab_mgmt) - Management network

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Galactic VPC Topology with Bridges                       │
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │           VPC Backbone Bridge: galactic_v_1                     │      │
│    │           MTU: 9500 (Jumbo frames for SRv6)                     │      │
│    │                                                                 │      │
│    │   Interfaces: bni0n1i1 (SJC), bni0n2i1 (IAD), bni0n3i1 (AMS)    │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         │ bni0n1i1                 │ bni0n2i1      bni0n3i1   │             │
│         ▼                          ▼                          ▼             │
│    ┌─────────┐              ┌─────────┐              ┌─────────┐            │
│    │   SJC   │              │   IAD   │              │   AMS   │            │
│    │ San Jose│◄────────────►│N.Virginia│◄────────────►│Amsterdam│           │
│    │ (FRR)   │   L2 Bridge  │ (FRR)   │   L2 Bridge  │ (FRR)   │            │
│    └────┬────┘              └────┬────┘              └────┬────┘            │
│         │                        │                        │                 │
│    ┌────┴────┐              ┌────┴────┐              ┌────┴────┐            │
│    │ eth1    │              │ eth1    │              │ eth1    │            │
│    │10.1.1.1 │              │10.1.1.2 │              │10.1.1.3 │            │
│    │ (VPC)   │              │ (VPC)   │              │ (VPC)   │            │
│    └─────────┘              └─────────┘              └─────────┘            │
│         │                                                 │                 │
│    ┌────┴────┐                                       ┌────┴────┐            │
│    │ eth2    │                                       │ eth2    │            │
│    │Service  │                                       │Service  │            │
│    │Prefix   │                                       │Prefix   │            │
│    │192.168. │                                       │192.168. │            │
│    │1.0/24   │                                       │2.0/24   │            │
│    └─────────┘                                       └─────────┘            │
│                                                                             │
│    SRv6 Locators:                                                           │
│    • SJC: fc00:0:1::/48                                                     │
│    • IAD: fc00:0:2::/48                                                     │
│    • AMS: fc00:0:3::/48                                                     │
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │           Management Bridge: br-9b819b05be4c (netlab_mgmt)      │      │
│    │           For container management (SSH, etc.)                  │      │
│    │           Interfaces: veth8648c65, vetheca1b2e, veth92620a8     │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How the Bridges Work

```bash
# View all bridges
brctl show

# Actual output from this lab:
# bridge name          bridge id              STP    interfaces
# galactic_v_1         8000.523d321b1e67      no     bni0n1i1 (SJC eth1)
#                                                    bni0n2i1 (IAD eth1)
#                                                    bni0n3i1 (AMS eth1)
# br-9b819b05be4c      8000.9aa6737085b4      no     veth8648c65
#                                                    vetheca1b2e
#                                                    veth92620a8
#                                                    vethfdf346d

# View bridge interfaces with MTU
ip link show galactic_v_1
# 23: galactic_v_1: <BROADCAST,MULTICAST,UP> mtu 9500 ...

# View management network
docker network ls | grep netlab
# 9b819b05be4c   netlab_mgmt   bridge    local
```

**Key Points:**
- **galactic_v_1** is the VPC backbone with **MTU 9500** for SRv6 jumbo frames
- **bni0n1i1, bni0n2i1, bni0n3i1** are veth pairs connecting containers to the bridge
- **netlab_mgmt** (br-9b819b05be4c) is for management traffic only
- ISIS discovers neighbors via the galactic_v_1 L2 segment
- SRv6 packets are encapsulated and forwarded over galactic_v_1

### Software Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Windows Host                                   │
│                         (Windows 11/10 Build 26200+)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                              WSL2 (v2.6.3.0)                                │
│                         Linux Kernel 6.6.87.2-1                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                          Ubuntu 22.04.5 LTS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Docker    │  │ Containerlab│  │   Netlab    │  │   Ansible   │         │
│  │   28.2.2    │  │   0.72.0    │  │   (latest)  │  │   2.17.14   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────────────────────┤
│                          FRRouting Containers                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                          │
│  │     SJC     │  │     IAD     │  │     AMS     │                          │
│  │ FRR 10.5.0  │  │ FRR 10.5.0  │  │ FRR 10.5.0  │                          │
│  │192.168.121. │  │192.168.121. │  │192.168.121. │                          │
│  │    101      │  │    102      │  │    103      │                          │
│  └─────────────┘  └─────────────┘  └─────────────┘                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Geo-Location & BGP Path Selection

### How Nearest POP is Selected

Datum uses **Anycast + BGP** to automatically route users to the nearest POP:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Geo-Location POP Selection                              │
│                                                                             │
│   User in Europe                                                            │
│        │                                                                    │
│        │ 1. DNS Query: app.datum.net                                        │
│        ▼                                                                    │
│   ┌─────────────┐                                                           │
│   │ Datum DNS   │ Returns Anycast IP: 185.x.x.x                             │
│   │ (GeoDNS)    │ (Same IP advertised from ALL POPs)                        │
│   └──────┬──────┘                                                           │
│          │                                                                  │
│          │ 2. User connects to 185.x.x.x                                    │
│          ▼                                                                  │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    Internet BGP Routing                             │   │
│   │                                                                     │   │
│   │   All POPs advertise: 185.x.x.x/24 via BGP                          │   │
│   │   Internet routers select SHORTEST AS PATH                          │   │
│   │   (Automatically routes to geographically nearest POP)              │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│          │                                                                  │
│          │ 3. BGP selects AMS (shortest path from Europe)                   │
│          ▼                                                                  │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                       │
│   │  SJC PoP    │   │  IAD PoP    │   │  AMS PoP    │ ◄── User lands here   │
│   │ (Far)       │   │ (Medium)    │   │ (Nearest)   │                       │
│   └─────────────┘   └─────────────┘   └─────────────┘                       │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### BGP Best Path Selection Algorithm

BGP uses a multi-step algorithm to select the best path:

| Step | Attribute | Description |
|------|-----------|-------------|
| 1 | **Weight** | Cisco-specific, highest wins (local to router) |
| 2 | **Local Preference** | Highest wins (within AS) |
| 3 | **Locally Originated** | Prefer routes originated by this router |
| 4 | **AS Path Length** | **Shortest wins** (most important for geo) |
| 5 | **Origin** | IGP > EGP > Incomplete |
| 6 | **MED** | Lowest wins (between ASes) |
| 7 | **eBGP vs iBGP** | Prefer eBGP |
| 8 | **IGP Metric** | Lowest cost to next-hop |
| 9 | **Router ID** | Lowest wins (tiebreaker) |

### How It Works in This Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     BGP + ISIS Integration                                  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         ISIS (Underlay)                             │   │
│   │                                                                     │   │
│   │   • Fast convergence (sub-second)                                   │   │
│   │   • Advertises SRv6 locators via TLV extensions                     │   │
│   │   • Provides next-hop reachability for BGP                          │   │
│   │   • Level-2 only (flat routing domain)                              │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    │ Route redistribution                   │
│                                    ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         BGP (Overlay)                               │   │
│   │                                                                     │   │
│   │   • iBGP mesh between all POPs (AS 65000)                           │   │
│   │   • Advertises service prefixes (192.168.x.0/24)                    │   │
│   │   • Policy control (route-maps, communities)                        │   │
│   │   • VPN services (VPNv4/VPNv6 address families)                     │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Route Flow:                                                               │
│   1. ISIS discovers topology, advertises SRv6 locators                      │
│   2. BGP learns service prefixes from each POP                              │
│   3. BGP uses ISIS next-hops for forwarding                                 │
│   4. Traffic encapsulated with SRv6 based on BGP next-hop                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### End-to-End Packet Flow Example

This shows how a packet travels from SJC to AMS in this topology:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│           E2E Packet Flow: SJC (192.168.1.1) → AMS (192.168.2.1)            │
│                                                                             │
│   STEP 1: Application sends packet                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ SJC Container (192.168.1.x)                                         │   │
│   │    │                                                                │   │
│   │    │ Original Packet: Src=192.168.1.10, Dst=192.168.2.20            │   │
│   │    ▼                                                                │   │
│   │ FRR Routing Table lookup:                                           │   │
│   │    192.168.2.0/24 → next-hop 10.255.0.3 (AMS loopback)              │   │
│   │    → Resolved via ISIS: fc00:0:3::/48                               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│   STEP 2: SRv6 Encapsulation at SJC                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ ┌─────────────────────────────────────────────────────────────────┐ │   │
│   │ │ Outer IPv6 Header                                               │ │   │
│   │ │   Src: 2001:10:1:1::1 (SJC)                                     │ │   │
│   │ │   Dst: fc00:0:3:: (AMS SRv6 Locator)                            │ │   │
│   │ ├─────────────────────────────────────────────────────────────────┤ │   │
│   │ │ SRv6 Header (SRH)                                               │ │   │
│   │ │   Segments Left: 0                                              │ │   │
│   │ │   Segment List: [fc00:0:3::]                                    │ │   │
│   │ ├─────────────────────────────────────────────────────────────────┤ │   │
│   │ │ Original IPv4 Packet                                            │ │   │
│   │ │   Src: 192.168.1.10, Dst: 192.168.2.20                          │ │   │
│   │ └─────────────────────────────────────────────────────────────────┘ │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│   STEP 3: Transit via Linux Bridge                                          │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                                                                     │   │
│   │   SJC ──────► Linux Bridge (br-netlab) ──────► IAD ──────► AMS      │   │
│   │   eth1        (L2 switching)                   eth1       eth1      │   │
│   │                                                                     │   │
│   │   Packet forwarded based on IPv6 dst: fc00:0:3::                    │   │
│   │   ISIS provides the path: SJC → IAD → AMS (or direct if L2)         │   │
│   │                                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│   STEP 4: SRv6 Decapsulation at AMS                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ AMS receives packet with Dst: fc00:0:3::                            │   │
│   │    │                                                                │   │
│   │    │ fc00:0:3:: matches AMS's SRv6 locator                          │   │
│   │    │ → Execute END behavior (decapsulate)                           │   │
│   │    ▼                                                                │   │
│   │ Original packet extracted: Src=192.168.1.10, Dst=192.168.2.20       │   │
│   │    │                                                                │   │
│   │    │ Route lookup: 192.168.2.0/24 is directly connected (eth2)      │   │
│   │    ▼                                                                │   │
│   │ Packet delivered to destination container                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   SUMMARY:                                                                  │
│   • Original packet: 192.168.1.10 → 192.168.2.20 (IPv4)                     │
│   • SRv6 tunnel: SJC (fc00:0:1::) → AMS (fc00:0:3::) (IPv6)                 │
│   • Encap at ingress (SJC), Decap at egress (AMS)                           │
│   • Transit nodes (IAD) just forward based on IPv6 dst                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### ISIS-BGP Synchronization

In this topology, ISIS and BGP work together:

```
SJC Router:
┌─────────────────────────────────────────────────────────────────────────────┐
│ ISIS Routing Table:                                                         │
│   10.255.0.2/32 → via 10.1.1.2 (IAD loopback)                               │
│   10.255.0.3/32 → via 10.1.1.3 (AMS loopback)                               │
│   fc00:0:2::/48 → via 2001:10:1:1::2 (IAD SRv6 locator)                     │
│   fc00:0:3::/48 → via 2001:10:1:1::3 (AMS SRv6 locator)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ BGP Routing Table:                                                          │
│   192.168.2.0/24 → next-hop 10.255.0.3 (AMS)                                │
│                    AS Path: 65000 (iBGP)                                    │
│                    → Resolved via ISIS to 10.1.1.3                          │
│                    → SRv6 encap: fc00:0:3::                                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- **Windows 10** (Build 19041+) or **Windows 11**
- **Administrator access** on your Windows machine
- **8GB+ RAM** recommended
- **Internet connection** for downloading packages

---

## Step 1: Install WSL2

### 1.1 Enable WSL

Open **PowerShell as Administrator** and run:

```powershell
wsl --install
```

This installs WSL2 with Ubuntu by default.

### 1.2 Restart Your Computer

After installation, restart your computer.

### 1.3 Verify WSL Installation

```powershell
wsl --version
```

**Expected Output:**
```
WSL version: 2.6.3.0
Kernel version: 6.6.87.2-1
WSLg version: 1.0.71
MSRDC version: 1.2.6353
Direct3D version: 1.611.1-81528511
DXCore version: 10.0.26100.1-240331-1435.ge-release
Windows version: 10.0.26200.7623
```

---

## Step 2: Install Ubuntu

### 2.1 Install Ubuntu 22.04

If not installed automatically:

```powershell
wsl --install -d Ubuntu-22.04
```

### 2.2 Launch Ubuntu

Open **Ubuntu** from the Start menu. Create a username and password when prompted.

### 2.3 Update Ubuntu

```bash
sudo apt update && sudo apt upgrade -y
```

### 2.4 Verify Ubuntu Version

```bash
lsb_release -a
```

**Expected Output:**
```
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.5 LTS
Release:        22.04
Codename:       jammy
```

---

## Step 3: Install Docker

### 3.1 Install Docker

```bash
# Install prerequisites
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io
```

### 3.2 Add User to Docker Group

```bash
sudo usermod -aG docker $USER
```

**Important:** Log out and log back in (or restart WSL) for this to take effect.

### 3.3 Start Docker Service

```bash
sudo service docker start
```

### 3.4 Verify Docker Installation

```bash
docker --version
```

**Expected Output:**
```
Docker version 28.2.2, build 28.2.2-0ubuntu1~22.04.1
```

Test Docker:
```bash
docker run hello-world
```

---

## Step 4: Install Containerlab

### 4.1 Install Containerlab

```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
```

### 4.2 Verify Containerlab Installation

```bash
containerlab version
```

**Expected Output:**
```
  ____ ___  _   _ _____  _    ___ _   _ _____ ____  _       _
 / ___/ _ \| \ | |_   _|/ \  |_ _| \ | | ____|  _ \| | __ _| |__
| |  | | | |  \| | | | / _ \  | ||  \| |  _| | |_) | |/ _` | '_ \
| |__| |_| | |\  | | |/ ___ \ | || |\  | |___|  _ <| | (_| | |_) |
 \____\___/|_| \_| |_/_/   \_\___|_| \_|_____|_| \_\_|\__,_|_.__/

    version: 0.72.0
     commit: 60c9eee8a
       date: 2025-12-03T12:31:48Z
     source: https://github.com/srl-labs/containerlab
 rel. notes: https://containerlab.dev/rn/0.72/
```

---

## Step 5: Install Netlab

### 5.1 Install Python Dependencies

```bash
sudo apt install -y python3-pip python3-venv
```

### 5.2 Install Netlab

```bash
pip3 install networklab
```

### 5.3 Add to PATH

Add the following to your `~/.bashrc`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### 5.4 Install Ansible

```bash
pip3 install ansible
```

### 5.5 Verify Installations

```bash
# Netlab
netlab help

# Ansible
ansible --version
```

**Expected Ansible Output:**
```
ansible [core 2.17.14]
  config file = /home/sonic/datum/galantic-vpc/ansible.cfg
  configured module search path = ['/home/sonic/.ansible/plugins/modules', '/usr/share/ansible/plugins/modules']
  ansible python module location = /home/sonic/.local/lib/python3.10/site-packages/ansible
  ansible collection location = /home/sonic/.ansible/collections:/usr/share/ansible/collections
  executable location = /home/sonic/.local/bin/ansible
  python version = 3.10.12 (main, Jan  8 2026, 06:52:19) [GCC 11.4.0] (/usr/bin/python3)
  jinja version = 3.1.6
  libyaml = True
```

---

## Step 6: Install K3s

K3s is a lightweight Kubernetes distribution perfect for WSL. It's required for running galactic-agent.

### 6.1 Install K3s

```bash
# Install K3s (lightweight Kubernetes)
curl -sfL https://get.k3s.io | sh -

# Wait for K3s to start
sudo systemctl start k3s
```

### 6.2 Configure kubectl Access

```bash
# Copy kubeconfig to user directory
mkdir -p ~/.kube
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER:$USER ~/.kube/config
export KUBECONFIG=~/.kube/config

# Add to bashrc for persistence
echo 'export KUBECONFIG=~/.kube/config' >> ~/.bashrc
```

### 6.3 Verify K3s Installation

```bash
kubectl get nodes
```

**Expected Output:**
```
NAME                         STATUS   ROLES           AGE   VERSION
galactic-dev-control-plane   Ready    control-plane   11h   v1.27.3
```

### 6.4 Essential K3s/Kubectl Commands

| Command | Description |
|---------|-------------|
| `kubectl get nodes` | List all nodes in the cluster |
| `kubectl get pods -A` | List all pods in all namespaces |
| `kubectl get svc -A` | List all services |
| `kubectl describe pod <name>` | Show detailed pod information |
| `kubectl logs <pod-name>` | View pod logs |
| `kubectl apply -f <file.yaml>` | Apply a manifest file |
| `kubectl delete -f <file.yaml>` | Delete resources from manifest |
| `sudo systemctl status k3s` | Check K3s service status |
| `sudo systemctl restart k3s` | Restart K3s |

---

## Step 7: Create the Topology

### 7.1 Create Project Directory

```bash
mkdir -p ~/datum/galantic-vpc
cd ~/datum/galantic-vpc
```

### 6.2 Create topology.yaml

Create the file `topology.yaml` with the following content:

```yaml
# =============================================================================
# DATUM GALACTIC VPC - NETLAB TOPOLOGY
# Translated from K8s VPC/VPCAttachment manifests
# Source: https://www.datum.net/docs/galactic-vpc/#galactic-agent
# =============================================================================
#
# K8s VPC Network: 10.1.1.0/24, 2001:10:1:1::/64
# VPCAttachment IPs:
#   - sjc: 10.1.1.1/24, 2001:10:1:1::1/64
#   - iad: 10.1.1.2/24, 2001:10:1:1::2/64
#   - ams: 10.1.1.3/24, 2001:10:1:1::3/64
#
# Routes from K8s manifests:
#   - sjc routes: 192.168.1.0/24 via 10.1.1.1, 192.168.2.0/24 via 10.1.1.3
#   - ams routes: 192.168.2.0/24 via 10.1.1.3, 192.168.1.0/24 via 10.1.1.1
# =============================================================================

name: galactic_vpc
module: [ isis, srv6 ]

defaults:
  device: frr
  provider: clab
  isis.area: "49.0001"

# SRv6 configuration - use ISIS only, disable BGP
srv6:
  locator_pool: "fc00::/48"
  igp: [ isis ]
  bgp: false


# -----------------------------------------------------------------------------
# NODES: Matching K8s Pod nodeSelector regions
# -----------------------------------------------------------------------------
nodes:
  # Pod: my-test-pod-sjc (topology.kubernetes.io/region: sjc)
  # Routes 192.168.1.0/24 and 2001:1::/64 to other regions
  sjc:
    id: 1
    loopback:
      ipv4: 10.255.0.1/32
      ipv6: 'fc00:ffff::1/128'
    srv6:
      locator: "fc00:0:1::/48"

  # Pod: my-test-pod-iad (topology.kubernetes.io/region: iad)
  # No additional routes - only VPC backbone connectivity
  iad:
    id: 2
    loopback:
      ipv4: 10.255.0.2/32
      ipv6: 'fc00:ffff::2/128'
    srv6:
      locator: "fc00:0:2::/48"

  # Pod: my-test-pod-ams (topology.kubernetes.io/region: ams)
  # Routes 192.168.2.0/24 and 2001:2::/64 to other regions
  ams:
    id: 3
    loopback:
      ipv4: 10.255.0.3/32
      ipv6: 'fc00:ffff::3/128'
    srv6:
      locator: "fc00:0:3::/48"

# -----------------------------------------------------------------------------
# LINKS: VPC Network (10.1.1.0/24, 2001:10:1:1::/64)
# Matching VPCAttachment interface addresses exactly
# -----------------------------------------------------------------------------
links:
  # VPC backbone - addresses from VPCAttachment specs
  # my-test-vpc-sjc: 10.1.1.1/24, 2001:10:1:1::1/64
  # my-test-vpc-iad: 10.1.1.2/24, 2001:10:1:1::2/64
  # my-test-vpc-ams: 10.1.1.3/24, 2001:10:1:1::3/64
  - sjc: { ipv4: 10.1.1.1/24, ipv6: '2001:10:1:1::1/64' }
    iad: { ipv4: 10.1.1.2/24, ipv6: '2001:10:1:1::2/64' }
    ams: { ipv4: 10.1.1.3/24, ipv6: '2001:10:1:1::3/64' }
    isis: {}
    mtu: 1600

  # Service prefix for sjc region (from VPCAttachment routes)
  # Route destination: 192.168.1.0/24 via 10.1.1.1
  - sjc: { ipv4: 192.168.1.1/24, ipv6: '2001:1::1/64' }
    type: stub
    isis: {}

  # Service prefix for ams region (from VPCAttachment routes)
  # Route destination: 192.168.2.0/24 via 10.1.1.3
  - ams: { ipv4: 192.168.2.1/24, ipv6: '2001:2::1/64' }
    type: stub
    isis: {}
```

---

## Step 7: Run the Lab

### 7.1 Create Lab Configuration

```bash
cd ~/datum/galantic-vpc
netlab create topology.yaml
```

**Expected Output:**
```
[CREATED] provider configuration file: clab.yml
[MAPPED]  clab_files/sjc/daemons to sjc:/etc/frr/daemons
[MAPPED]  clab_files/-shared-hosts to sjc:/etc/hosts:ro
[MAPPED]  clab_files/iad/daemons to iad:/etc/frr/daemons
[MAPPED]  clab_files/-shared-hosts to iad:/etc/hosts:ro
[MAPPED]  clab_files/ams/daemons to ams:/etc/frr/daemons
[MAPPED]  clab_files/-shared-hosts to ams:/etc/hosts:ro
[CREATED] transformed topology dump in YAML format in netlab.snapshot.yml
[CREATED] pickled transformed topology data into netlab.snapshot.pickle
[GROUPS]  group_vars for all
[GROUPS]  group_vars for modules
[GROUPS]  group_vars for frr
[HOSTS]   host_vars for sjc
[HOSTS]   host_vars for iad
[HOSTS]   host_vars for ams
[CREATED] minimized Ansible inventory hosts.yml
[CREATED] Ansible configuration file: ansible.cfg
```

### 7.2 Start the Lab

```bash
netlab up
```

This will:
1. Start Docker containers for each node (sjc, iad, ams)
2. Configure networking between containers
3. Apply FRR configuration via Ansible

### 7.3 Verify Containers are Running

```bash
containerlab inspect -a
```

**Expected Output:**
```
╭──────────┬──────────────┬───────────────────────┬──────────────────────────────┬─────────┬─────────────────╮
│ Topology │   Lab Name   │          Name         │          Kind/Image          │  State  │  IPv4/6 Address │
├──────────┼──────────────┼───────────────────────┼──────────────────────────────┼─────────┼─────────────────┤
│ clab.yml │ galactic_vpc │ clab-galactic_vpc-ams │ linux                        │ running │ 192.168.121.103 │
│          │              │                       │ quay.io/frrouting/frr:10.5.0 │         │ N/A             │
│          │              ├───────────────────────┼──────────────────────────────┼─────────┼─────────────────┤
│          │              │ clab-galactic_vpc-iad │ linux                        │ running │ 192.168.121.102 │
│          │              │                       │ quay.io/frrouting/frr:10.5.0 │         │ N/A             │
│          │              ├───────────────────────┼──────────────────────────────┼─────────┼─────────────────┤
│          │              │ clab-galactic_vpc-sjc │ linux                        │ running │ 192.168.121.101 │
│          │              │                       │ quay.io/frrouting/frr:10.5.0 │         │ N/A             │
╰──────────┴──────────────┴───────────────────────┴──────────────────────────────┴─────────┴─────────────────╯
```

---

## Step 8: Verify the Setup

### 8.1 Connect to a Node

```bash
docker exec -it clab-galactic_vpc-sjc vtysh
```

### 8.2 Check ISIS Neighbors

```
sjc# show isis neighbor
```

**Expected Output:**
```
Area Gandalf:
 System Id           Interface   L  State         Holdtime SNPA
 iad                 eth1        2  Up            28       aac1.abd1.8c9e
 ams                 eth1        2  Up            28       aac1.ab9d.6f20
```

### 8.3 Check SRv6 Locator

```
sjc# show segment-routing srv6 locator
```

**Expected Output:**
```
Locator:
Name                 ID      Prefix                   Status
-------------------- ------- ------------------------ -------
sjc                        1 fc00:0:1::/48            Up
```

### 8.4 Check SRv6 SIDs

```
sjc# show segment-routing srv6 sid
```

**Expected Output:**
```
 SID              Behavior    Context             Daemon/Instance    Locator    AllocationType
 ---------------------------  ------------------  -----------------  ---------  ----------------
 fc00:0:1::       uN          -                   isis(0)            sjc        dynamic
 fc00:0:1:e000::  uA          Interface 'eth1'    isis(0)            sjc        dynamic
 fc00:0:1:e001::  uA          Interface 'eth1'    isis(0)            sjc        dynamic
```

### 8.5 Check IP Routes

```
sjc# show ip route
```

**Expected Output:**
```
IPv4 unicast VRF default:
I   10.1.1.0/24 [115/20] via 10.1.1.2, eth1 inactive, weight 1
                         via 10.1.1.3, eth1 inactive, weight 1
C>* 10.1.1.0/24 is directly connected, eth1, weight 1
L>* 10.1.1.1/32 is directly connected, eth1, weight 1
C>* 10.255.0.1/32 is directly connected, lo, weight 1
I>* 10.255.0.2/32 [115/20] via 10.1.1.2, eth1, weight 1
I>* 10.255.0.3/32 [115/20] via 10.1.1.3, eth1, weight 1
C>* 192.168.1.0/24 is directly connected, eth2, weight 1
L>* 192.168.1.1/32 is directly connected, eth2, weight 1
I>* 192.168.2.0/24 [115/20] via 10.1.1.3, eth1, weight 1
```

### 8.6 Check ISIS Database

```
sjc# show isis database
```

**Expected Output:**
```
Area Gandalf:
IS-IS Level-2 link-state database:
LSP ID                  PduLen  SeqNumber   Chksum  Holdtime  ATT/P/OL
sjc.00-00            *    323   0x00000005  0x50bc    1621    0/0/0
sjc.0f-00            *     62   0x00000001  0xad01    1684    0/0/0
iad.00-00                 301   0x00000005  0x75ae    1652    0/0/0
ams.00-00                 323   0x00000005  0xd61f    1596    0/0/0
    4 LSPs
```

### 8.7 Test Connectivity

```bash
# From host, ping between nodes
docker exec -it clab-galactic_vpc-sjc ping -c 3 10.1.1.3
docker exec -it clab-galactic_vpc-sjc ping -c 3 192.168.2.1
```

---

## Step 10: Deploy Galactic-Agent

The galactic-agent connects your local netlab POPs to Datum's cloud infrastructure via MQTT.

### 10.1 Install Go 1.23+ (Required)

The galactic-agent requires Go 1.23 or later. Ubuntu's apt package is too old.

```bash
# Download and install Go 1.23
wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz

# Add to PATH
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
# Expected: go version go1.23.4 linux/amd64
```

### 10.2 Clone Galactic-Agent Repository

```bash
# Clone into your galantic-vpc directory (keeps everything together for git)
cd ~/datum/galantic-vpc
git clone https://github.com/datum-cloud/galactic-agent.git
cd galactic-agent
```

### 10.3 Build the Agent

```bash
# Download dependencies and build
go mod download
go build -o galactic-agent .

# Verify binary was created
ls -la galactic-agent
# Expected: -rwxr-xr-x 1 sonic sonic 20196174 Jan 14 14:05 galactic-agent
```

### 10.4 Install MQTT Broker (Mosquitto)

For local testing, install a local MQTT broker:

```bash
# Install Mosquitto
sudo apt install -y mosquitto mosquitto-clients

# Start the service
sudo service mosquitto start

# Verify it's running
sudo service mosquitto status
```

### 10.5 Create Agent Configuration

```bash
# Create config file
cat > config.yaml << 'EOF'
# Galactic Agent Configuration for WSL Lab
# Author: Sajjad Ahmed, Multi Naturals Inc.

# SRv6 network prefix - must match your topology
srv6_net: "fc00::/48"

# Unix socket for CNI communication
socket_path: "/var/run/galactic/agent.sock"

# MQTT Configuration - Local testing
mqtt_url: "tcp://localhost:1883"
mqtt_clientid: "galactic-agent-wsl"
mqtt_username: ""
mqtt_password: ""
mqtt_qos: 1
mqtt_topic_receive: "galactic/routes/wsl"
mqtt_topic_send: "galactic/register"
EOF
```

### 10.6 Create Required Interface

The galactic-agent requires a dummy loopback interface named `lo-galactic` for SRv6 encapsulation:

```bash
# Create the lo-galactic dummy interface (required by agent)
sudo ip link add lo-galactic type dummy
sudo ip link set lo-galactic up

# Verify it exists
ip link show lo-galactic
# Expected: lo-galactic: <BROADCAST,NOARP,UP,LOWER_UP> mtu 1500 ...
```

### 10.7 Run the Agent

```bash
# Create socket directory
sudo mkdir -p /var/run/galactic
sudo chmod 777 /var/run/galactic

# Run the agent (requires sudo for NET_ADMIN capability)
sudo ./galactic-agent --config config.yaml
```

**Expected Output:**
```
2026/01/14 15:14:52 Using config file: config.yaml
2026/01/14 15:14:52 MQTT connecting
2026/01/14 15:14:52 gRPC listening: unix:///var/run/galactic/agent.sock
2026/01/14 15:14:52 MQTT connected
2026/01/14 15:14:52 MQTT subscribed: galactic/routes/wsl
```

The agent is now running and waiting for:
- CNI registrations via Unix socket
- Route updates via MQTT

### 10.8 Test MQTT Communication

Open a **new terminal** and test message flow:

```bash
# Fix PATH if needed
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH

# Subscribe to all galactic topics (watch messages)
mosquitto_sub -t "galactic/#" -v
```

Open a **third terminal** and publish a test message:

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH

# Send a test message
mosquitto_pub -t "galactic/routes/wsl" -m "test message"
```

**Expected Results:**
- **Subscriber terminal**: Shows `galactic/routes/wsl test message`
- **Agent terminal**: Shows `MQTT ReceiveHandler failed: proto: cannot parse invalid wire-format data`

The error is expected because we sent plain text, not protobuf. This confirms the agent is receiving messages.

### 10.9 Test Protobuf Route Injection

We provide a Go script that sends properly encoded protobuf messages:

```bash
cd ~/datum/galantic-vpc
go run test-mqtt-route.go
```

**Expected Agent Output:**
```
ROUTE: status='ADD', network='192.168.2.0/24', srv6_endpoint='fc00::0000:0000:0001:0001', srv6_segments='[fc00::0000:0000:0001:0001]'
MQTT ReceiveHandler failed: routeegress add failed: could not find VRF ID for interface: G000000001001V
```

**Understanding the Errors:**

| Error Message | Meaning | Solution |
|---------------|---------|----------|
| `Link not found` | `lo-galactic` interface missing | Create: `sudo ip link add lo-galactic type dummy && sudo ip link set lo-galactic up` |
| `could not find VRF ID for interface: G...V` | VRF interface not created | Create VRF: `sudo ip link add G000000001001V type vrf table 100 && sudo ip link set G000000001001V up` |
| `operation not supported` | WSL2 kernel doesn't support SRv6 seg6 encapsulation | **Kernel limitation** - see note below |

**WSL2 Kernel Limitation:**

The WSL2 kernel (6.x) does not have full SRv6 `seg6` encapsulation support compiled in. This means:
- ✅ VRF interfaces work
- ✅ MQTT message parsing works
- ✅ Agent receives and decodes routes correctly
- ❌ `ip -6 route add ... encap seg6` fails with "operation not supported"

**This is expected behavior for WSL2.** The FRR containers in this lab handle SRv6 routing internally via ISIS, which works because they run in their own network namespace with full kernel support.

For full SRv6 agent testing, use:
- Native Linux (Ubuntu 22.04+ with kernel 5.15+)
- A VM with a standard Linux kernel
- Datum's production Kubernetes environment

### 10.10 Manual SRv6 Route Injection (Alternative)

To test SRv6 encapsulation without the agent, add routes directly to the kernel:

```bash
# Add SRv6 encapsulated route to AMS (fc00:0:3::)
# This encapsulates IPv6 traffic destined for fc00:0:3::/48 with SRv6
sudo ip -6 route add fc00:0:3::/48 encap seg6 mode encap segs fc00:0:3:: dev lo-galactic

# Verify the route was added
ip -6 route show | grep 'encap seg6'
# Expected: fc00:0:3::/48 encap seg6 mode encap segs 1 [ fc00:0:3:: ] dev lo-galactic

# Test from FRR container (SJC to AMS)
docker exec -it clab-galactic_vpc-sjc ping -c 3 fc00:0:3::1
```

This demonstrates the SRv6 encapsulation mechanism that the agent would use in production.

### 10.11 Galactic-Agent Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Galactic-Agent Components                               │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                    galactic-agent (Go binary)                       │  │
│   │                                                                     │  │
│   │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐           │  │
│   │   │ Local gRPC  │    │    MQTT     │    │   Netlink   │           │  │
│   │   │   Server    │    │   Client    │    │   Handler   │           │  │
│   │   │             │    │             │    │             │           │  │
│   │   │ Listens on  │    │ Connects to │    │ Programs    │           │  │
│   │   │ Unix socket │    │ Datum MQTT  │    │ Linux kernel│           │  │
│   │   │ for CNI     │    │ broker      │    │ SRv6 routes │           │  │
│   │   └──────┬──────┘    └──────┬──────┘    └──────┬──────┘           │  │
│   │          │                  │                  │                   │  │
│   └──────────┼──────────────────┼──────────────────┼───────────────────┘  │
│              │                  │                  │                      │
│              ▼                  ▼                  ▼                      │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│   │ galactic-cni    │  │ Datum Cloud     │  │ Linux Kernel    │         │
│   │ (CNI plugin)    │  │ MQTT Broker     │  │ Routing Table   │         │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.12 Key Agent Functions

| Function | Description |
|----------|-------------|
| `RegisterHandler` | Handles VPC registration from CNI, encodes to SRv6 |
| `DeregisterHandler` | Removes VPC registration when container stops |
| `ReceiveHandler` | Processes route updates from galactic-router |
| `EncodeVPCToSRv6Endpoint` | Converts VPC ID to SRv6 address |

### 10.13 Agent Configuration

```yaml
# Configuration via environment variables or config file
srv6_net: "fc00::/56"                    # Base SRv6 network
socket_path: "/var/run/galactic/agent.sock"  # Unix socket for CNI
mqtt_url: "tcp://mqtt.datum.net:1883"    # MQTT broker URL
mqtt_topic_receive: "galactic/routes"    # Topic for receiving routes
mqtt_topic_send: "galactic/register"     # Topic for sending registrations
```

### 10.14 Verify Agent is Working

```bash
# Check agent logs
kubectl logs -n galactic-system -l app=galactic-agent

# Check if agent socket exists
ls -la /var/run/galactic/agent.sock
```

---

## MQTT Message Formats

### Protocol Buffer Definitions

The galactic-agent uses Protocol Buffers for message serialization:

```protobuf
// remote.proto - Messages between agent and router
message Envelope {
  oneof kind {
    Register   register   = 1;
    Deregister deregister = 2;
    Route      route      = 3;
  }
}

message Register {
  string network = 1;        // VPC network identifier
  string srv6_endpoint = 2;  // SRv6 SID for this endpoint
}

message Route {
  enum Status { ADD = 0; DELETE = 1; }
  string network = 1;                 // VPC network
  string srv6_endpoint = 2;           // Destination SRv6 SID
  repeated string srv6_segments = 3;  // Segment list
  Status status = 4;                  // ADD or DELETE
}
```

### Message Flow Examples

**1. Agent → MQTT (Registration)**
```json
{
  "register": {
    "network": "my-test-vpc",
    "srv6_endpoint": "fc00:0:1:1::1"
  }
}
```
*Meaning: "I am node with SRv6 endpoint fc00:0:1:1::1, joining network my-test-vpc"*

**2. MQTT → Agent (Route Push)**
```json
{
  "route": {
    "network": "my-test-vpc",
    "srv6_endpoint": "fc00:0:2:1::1",
    "srv6_segments": ["fc00:0:2::1"],
    "status": "ADD"
  }
}
```
*Meaning: "To reach fc00:0:2:1::1, encapsulate with segment list [fc00:0:2::1]"*

**3. Agent → Kernel (Netlink)**
```bash
# Equivalent command executed via Netlink API:
ip -6 route add fc00:0:2:1::1/128 encap seg6 mode encap segs fc00:0:2::1 dev eth0
```

### Complete Message Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Complete Message Flow                             │
│                                                                             │
│   Pod Created                                                               │
│        │                                                                    │
│        │ 1. CNI calls galactic-agent via Unix socket                       │
│        ▼                                                                    │
│   ┌─────────────┐                                                          │
│   │ galactic-   │  RegisterRequest {                                       │
│   │ agent       │    vpc: "my-test-vpc"                                    │
│   │             │    vpcattachment: "my-test-vpc-sjc"                      │
│   │             │    networks: ["10.1.1.0/24"]                             │
│   └──────┬──────┘  }                                                       │
│          │                                                                  │
│          │ 2. Agent publishes to MQTT                                      │
│          ▼                                                                  │
│   ┌─────────────┐                                                          │
│   │ MQTT Broker │  Topic: galactic/register/node-1                         │
│   │             │  Envelope { register: {...} }                            │
│   └──────┬──────┘                                                          │
│          │                                                                  │
│          │ 3. Router receives, computes routes                             │
│          ▼                                                                  │
│   ┌─────────────┐                                                          │
│   │ galactic-   │  For each other node in VPC:                             │
│   │ router      │  - Calculate segment list                                │
│   │             │  - Publish Route message                                 │
│   └──────┬──────┘                                                          │
│          │                                                                  │
│          │ 4. Route pushed to all agents                                   │
│          ▼                                                                  │
│   ┌─────────────┐                                                          │
│   │ galactic-   │  Topic: galactic/routes/node-1                           │
│   │ agent       │  Envelope { route: {...} }                               │
│   └──────┬──────┘                                                          │
│          │                                                                  │
│          │ 5. Agent programs kernel via Netlink                            │
│          ▼                                                                  │
│   ┌─────────────┐                                                          │
│   │ Linux       │  ip -6 route add fc00:0:2::/48 encap seg6 ...           │
│   │ Kernel      │                                                          │
│   └─────────────┘                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Step 11: Connect to Datum Cloud Infrastructure

To connect your local WSL lab to Datum's production infrastructure, update the agent configuration.

### 11.1 Update Agent Configuration for Datum Cloud

```bash
cd ~/datum/galantic-vpc/galactic-agent

# Create production config
cat > config-datum.yaml << 'EOF'
# Galactic Agent Configuration for Datum Cloud
# Author: Sajjad Ahmed, Multi Naturals Inc.

srv6_net: "fc00::/48"
socket_path: "/var/run/galactic/agent.sock"

# Datum Cloud MQTT Broker
mqtt_url: "tcp://mqtt.datum.net:1883"
mqtt_clientid: "galactic-agent-wsl-YOUR_UNIQUE_ID"
mqtt_username: "YOUR_DATUM_USERNAME"
mqtt_password: "YOUR_DATUM_API_KEY"
mqtt_qos: 1
mqtt_topic_receive: "galactic/routes/YOUR_NODE_ID"
mqtt_topic_send: "galactic/register"
EOF
```

### 11.2 Get Datum Credentials

1. Sign up at [https://www.datum.net](https://www.datum.net)
2. Navigate to **Settings → API Keys**
3. Create a new API key for your WSL lab
4. Update `config-datum.yaml` with your credentials

### 11.3 Run Agent with Datum Cloud

```bash
# Stop local agent if running (Ctrl+C)
# Run with Datum config
sudo ./galactic-agent --config config-datum.yaml
```

### 11.4 End-to-End Architecture with Datum Cloud

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    End-to-End: WSL Lab to Datum Cloud                       │
│                                                                             │
│   YOUR WSL LAPTOP                           DATUM CLOUD                     │
│   ┌─────────────────────────────────┐      ┌─────────────────────────────┐ │
│   │                                 │      │                             │ │
│   │  ┌─────────────────────────┐   │      │  ┌─────────────────────┐   │ │
│   │  │ Netlab Topology         │   │      │  │ Datum POPs          │   │ │
│   │  │ (SJC, IAD, AMS)         │   │      │  │ (Global Edge)       │   │ │
│   │  │ FRR + SRv6              │   │      │  │                     │   │ │
│   │  └───────────┬─────────────┘   │      │  │  SJC ─── IAD ─── AMS│   │ │
│   │              │                 │      │  │   │       │       │ │   │ │
│   │              │ SRv6 Routes     │      │  │  (Real POPs)       │   │ │
│   │              ▼                 │      │  └──────────┬──────────┘   │ │
│   │  ┌─────────────────────────┐   │      │             │              │ │
│   │  │ galactic-agent          │   │      │             │              │ │
│   │  │ (Programs SRv6 routes)  │   │      │             │              │ │
│   │  └───────────┬─────────────┘   │      │             │              │ │
│   │              │                 │      │             │              │ │
│   │              │ MQTT            │      │             │              │ │
│   │              │ (Protobuf)      │      │             │              │ │
│   └──────────────┼─────────────────┘      │             │              │ │
│                  │                        │             │              │ │
│                  │ Internet               │             │              │ │
│                  ▼                        │             ▼              │ │
│   ┌──────────────────────────────────────────────────────────────────┐ │ │
│   │                     Datum MQTT Broker                            │ │ │
│   │                   (mqtt.datum.net:1883)                          │ │ │
│   └──────────────────────────────────────────────────────────────────┘ │ │
│                  │                        │             │              │ │
│                  │                        │             ▼              │ │
│                  │                        │  ┌─────────────────────┐   │ │
│                  │                        │  │ galactic-router     │   │ │
│                  │                        │  │ (Route Calculator)  │   │ │
│                  │                        │  └─────────────────────┘   │ │
│                  │                        │                             │ │
│                  │                        └─────────────────────────────┘ │
│                  │                                                        │
│   TRAFFIC FLOW:                                                          │
│   1. Your WSL agent registers with Datum MQTT broker                    │
│   2. galactic-router learns about your WSL node                         │
│   3. Router calculates routes and pushes to all agents                  │
│   4. Your WSL can now reach Datum's global POPs via SRv6               │
│   5. Traffic: WSL → SRv6 encap → Internet → Datum POP → Destination    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.5 Verify Datum Cloud Connection

```bash
# Check agent logs for successful registration
# You should see:
# - MQTT connected
# - MQTT subscribed
# - REGISTER messages being sent
# - ROUTE messages being received from Datum

# Check kernel routes programmed by agent
ip -6 route show | grep seg6
```

---

## Troubleshooting

### Docker Service Not Running

```bash
sudo service docker start
```

### Permission Denied on Docker

```bash
sudo usermod -aG docker $USER
# Then log out and log back in
```

### Netlab Command Not Found

```bash
export PATH="$HOME/.local/bin:$PATH"
source ~/.bashrc
```

### Lab Already Running

```bash
# Stop existing lab
netlab down

# Or destroy with containerlab
containerlab destroy -a
```

### Check Docker Logs

```bash
docker logs clab-galactic_vpc-sjc
```

---

## Reference Commands

### Netlab Commands

| Command | Description |
|---------|-------------|
| `netlab create topology.yaml` | Generate lab configuration files |
| `netlab up` | Start the lab |
| `netlab down` | Stop the lab |
| `netlab connect sjc` | SSH to a node |
| `netlab help` | Show available commands |

### Containerlab Commands

| Command | Description |
|---------|-------------|
| `containerlab inspect -a` | Show all running labs |
| `containerlab destroy -a` | Destroy all labs |
| `containerlab graph` | Generate topology graph |

### Docker Commands

| Command | Description |
|---------|-------------|
| `docker ps` | List running containers |
| `docker exec -it <container> vtysh` | Connect to FRR CLI |
| `docker logs <container>` | View container logs |

### FRR Show Commands

| Command | Description |
|---------|-------------|
| `show isis neighbor` | Display ISIS neighbors |
| `show isis database` | Display ISIS LSDB |
| `show isis interface` | Display ISIS interfaces |
| `show ip route` | Display IPv4 routing table |
| `show ipv6 route` | Display IPv6 routing table |
| `show segment-routing srv6 locator` | Display SRv6 locators |
| `show segment-routing srv6 sid` | Display SRv6 SIDs |

---

## Generated Files

After running `netlab create`, the following files are generated:

| File                   | Description                              |
|----------------------- |----------------------------------------  |
| `clab.yml            ` | Containerlab topology definition         |
| `ansible.cfg`          | Ansible configuration                    |
| `hosts.yml`            | Ansible inventory                        |
| `host_vars/`           | Per-node Ansible variables               |
| `group_vars/`          | Group Ansible variables                  |
| `clab_files/`          | Container bind mounts (daemons, hosts)   |
| `netlab.snapshot.yml`  | Full topology snapshot                   |

### Example clab.yml

```yaml
name: galactic_vpc
prefix: "clab"

mgmt:
  network: netlab_mgmt
  ipv4-subnet: 192.168.121.0/24

topology:
  nodes:
    sjc:
      mgmt-ipv4: 192.168.121.101
      kind: linux
      image: quay.io/frrouting/frr:10.5.0
      binds:
      - clab_files/sjc/daemons:/etc/frr/daemons
      - clab_files/-shared-hosts:/etc/hosts:ro
    iad:
      mgmt-ipv4: 192.168.121.102
      kind: linux
      image: quay.io/frrouting/frr:10.5.0
      binds:
      - clab_files/iad/daemons:/etc/frr/daemons
      - clab_files/-shared-hosts:/etc/hosts:ro
    ams:
      mgmt-ipv4: 192.168.121.103
      kind: linux
      image: quay.io/frrouting/frr:10.5.0
      binds:
      - clab_files/ams/daemons:/etc/frr/daemons
      - clab_files/-shared-hosts:/etc/hosts:ro

    galactic_v_1:
      kind: bridge

  links:
  - endpoints:
    - "sjc:eth1"
    - "galactic_v_1:bni0n1i1"
  - endpoints:
    - "iad:eth1"
    - "galactic_v_1:bni0n2i1"
  - endpoints:
    - "ams:eth1"
    - "galactic_v_1:bni0n3i1"
  - type: dummy
    endpoint:
      node: "sjc"
      interface: "eth2"
  - type: dummy
    endpoint:
      node: "ams"
      interface: "eth2"
```

---

## Version Summary

| Component       | Version     |
|-----------------|-------------|
| WSL             | 2.6.3.0     |
| Linux Kernel    | 6.6.87.2-1  |
| Ubuntu          | 22.04.5 LTS |
| Docker          | 28.2.2      |
| Containerlab    | 0.72.0      |
| Ansible         | 2.17.14     |
| Python          | 3.10.12     |
| FRRouting       | 10.5.0      |

---

## Step 12: Running the Lab with Python Scripts

For convenience, we provide Python scripts to automate lab setup and demo execution.

### 12.1 Automated Setup (Windows)

Run from **Windows PowerShell as Administrator**:

```powershell
# Navigate to the project directory
cd C:\Users\start\Desktop\Sajjad\neelProject\intecom\datum

# Install the complete lab environment
python setup_wsl_lab.py
```

**What `setup_wsl_lab.py` does:**
1. Checks Windows version and prerequisites
2. Enables WSL2 feature (if not already enabled)
3. Installs Ubuntu 22.04 in WSL
4. Installs Docker Engine inside WSL (NOT Docker Desktop)
5. Installs Containerlab and Netlab
6. Installs Go 1.23+ for galactic-agent
7. Clones and builds galactic-agent
8. Installs Mosquitto MQTT broker
9. Copies topology files to WSL

### 12.2 Run the Interactive Demo

```powershell
# Run the full interactive demo
python run_lab_demo.py
```

**Demo Output:**

```
╔══════════════════════════════════════════════════════════════════════╗
║           Datum Galactic VPC Lab - Demo Runner                       ║
║           Author: Sajjad Ahmed, Multi Naturals Inc.                  ║
╚══════════════════════════════════════════════════════════════════════╝

======================================================================
 Datum Galactic VPC - Full Demo
======================================================================

    This demo will:
    1. Show the lab topology
    2. Start the lab (if not running)
    3. Verify ISIS adjacencies
    4. Run connectivity tests
    5. Test MQTT route injection
    6. Open interactive shell

    Press Ctrl+C at any time to stop the demo.
```

### 12.3 Lab Topology Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Galactic VPC Topology (SRv6)                             │
│                                                                             │
│    ┌─────────────────────────────────────────────────────────────────┐      │
│    │           VPC Backbone Bridge: galactic_v_1                     │      │
│    │           MTU: 9500 (Jumbo frames for SRv6)                     │      │
│    └─────────────────────────────────────────────────────────────────┘      │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         │                          │                          │             │
│         ▼                          ▼                          ▼             │
│    ┌─────────┐              ┌─────────┐              ┌─────────┐            │
│    │   SJC   │              │   IAD   │              │   AMS   │            │
│    │San Jose │◄────────────►│N.Virginia│◄────────────►│Amsterdam│           │
│    │ (FRR)   │   ISIS/BGP   │ (FRR)   │   ISIS/BGP   │ (FRR)   │            │
│    └────┬────┘              └────┬────┘              └────┬────┘            │
│         │                        │                        │                 │
│    Loopback:               Loopback:               Loopback:                │
│    10.255.0.1              10.255.0.2              10.255.0.3               │
│                                                                             │
│    SRv6 Locators:                                                           │
│    • SJC: fc00:0:1::/48                                                     │
│    • IAD: fc00:0:2::/48                                                     │
│    • AMS: fc00:0:3::/48                                                     │
│                                                                             │
│    Service Prefixes:                                                        │
│    • SJC: 192.168.1.0/24                                                    │
│    • AMS: 192.168.2.0/24                                                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 12.4 Demo Runner Commands

| Command | Description |
|---------|-------------|
| `python run_lab_demo.py` | Run full interactive demo |
| `python run_lab_demo.py --start` | Start lab only |
| `python run_lab_demo.py --stop` | Stop lab |
| `python run_lab_demo.py --status` | Check lab status |
| `python run_lab_demo.py --test` | Run connectivity tests |
| `python run_lab_demo.py --mqtt` | Test MQTT route injection |
| `python run_lab_demo.py --topology` | Show topology diagram |
| `python run_lab_demo.py --shell` | Open interactive WSL shell |

### 12.5 Test MQTT Route Injection

The demo includes testing MQTT route injection using protobuf messages:

```bash
# In WSL, run the Go test script
cd ~/datum/galantic-vpc
go run test-mqtt-route.go
```

**Expected Output:**

```
======================================================================
 Galactic Agent MQTT Route Injection Test
 Author: Sajjad Ahmed, Multi Naturals Inc.
======================================================================

📤 TEST 1: Add route to AMS
   Network:       192.168.2.0/24
   SRv6 Endpoint: fc00:0:3:: (AMS)
   Segments:      [fc00:0:3::]
   Status:        ADD (0)
   Binary (hex):  1a2a0a0e3139322e3136382e322e302f3234...
   Binary size:   44 bytes
   ✅ Published to topic: galactic/routes/wsl

📤 TEST 2: Add route to IAD
   Network:       192.168.3.0/24
   SRv6 Endpoint: fc00:0:2:: (IAD)
   Segments:      [fc00:0:2::]
   Status:        ADD (0)
   ✅ Published to topic: galactic/routes/wsl

======================================================================
🔍 VERIFICATION: Run these commands to check if routes were added:
======================================================================
   ip -6 route show | grep -E '192.168.2|192.168.3'
   ip -6 route show table all | grep 'encap seg6'
======================================================================
```

---

## Next Steps

1. **Connect to Datum Cloud** - Install galactic-agent to connect your local lab to Datum's public infrastructure
2. **Add more nodes** - Extend the topology with additional POPs
3. **Configure BGP** - Add BGP peering between nodes
4. **Test SRv6 policies** - Implement traffic engineering with SRv6

---

## About the Author

### Sajjad Ahmed

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/er-sajjad-ahmed/)

**Senior Network Architect & Open Source Contributor**  
**Company:** Multi Naturals Inc.

Sajjad Ahmed is a seasoned network architect with extensive experience in carrier-grade network operating systems and next-generation networking technologies.

### Professional Experience

| Platform | Description |
|----------|-------------|
| **SONiC NOS** | Open-source network operating system for data center switches |
| **IPOS (Ericsson)** | Carrier-grade router operating system |
| **XROS** | High-performance routing platform |
| **SAOS (Ciena)** | Service-aware operating system for packet-optical networks |
| **IPI** | Network infrastructure platforms |
| **Broadcom Memory Chipsets** | Memory chipset series |

### Areas of Expertise

- **Network Architecture Design** - Enterprise and carrier-grade network solutions
- **Open Source SONiC NOS** - Development, customization, and deployment
- **SRv6 & Segment Routing** - Modern traffic engineering and VPN services
- **Quantum-Safe Communications** - IPsec, mTLS, ETSI QKD standards
- **Broadcom Memory Chipsets** - Memory series ASIC programming and integration

### Contact

For inquiries regarding:
- Network architecture design and consulting
- SONiC NOS development and integration
- SRv6/Segment Routing implementations
- Quantum-safe communication solutions
- Carrier-grade NOS expertise (IPOS, XROS, SAOS)

**Connect on LinkedIn:** [https://www.linkedin.com/in/er-sajjad-ahmed/](https://www.linkedin.com/in/er-sajjad-ahmed/)


*Document generated from Datum Galactic VPC Lab - January 2026*
*This project is maintained by Sajjad Ahmed. Contributions and feedback are welcome.*
