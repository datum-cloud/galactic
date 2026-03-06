# Datum Galactic VPC Deployment

**Author:** Sajjad Ahmed  
**Company:** Multi Naturals Inc.  
**Version:** 1.2.0

---

This directory contains the netlab topology for simulating a Galactic VPC across three regions with SRv6, which can be connected to Datum's public infrastructure.

> **📚 New to this setup?** See [TUTORIAL.md](TUTORIAL.md) for the complete guide covering:
> - SRv6 fundamentals and how it works
> - WSL, Docker, Containerlab, Netlab installation
> - Galactic-agent deployment and testing
> - MQTT message formats and protocol details
> - Geo-location and BGP path selection

## Quick Start (Windows)

### Option 1: Automated Setup (Recommended)

Run from **Windows PowerShell as Administrator**:

```powershell
# Install the complete lab environment
python setup_wsl_lab.py

# Run the interactive demo
python run_lab_demo.py
```

### Option 2: Manual Setup

See [TUTORIAL.md](TUTORIAL.md) for step-by-step manual installation.

## Files

| File                          | Purpose                                                                       |
|-------------------------------|-------------------------------------------------------------------------------|
| `setup_wsl_lab.py`            | **Windows installer** - Sets up WSL, Docker, Containerlab, Go, galactic-agent |
| `run_lab_demo.py`             | **Demo runner** - Interactive demo with connectivity tests and MQTT injection |
| `topology.yaml`               | Netlab topology with SRv6, ISIS, and BGP (heavily commented)                  |
| `galactic-agent-config.yaml`  | Agent configuration with detailed comments and testing instructions           |
| `test-mqtt-route.go`          | Go script to inject protobuf routes into MQTT broker                          |
| `TUTORIAL.md`                 | Complete installation, SRv6 education, and Datum integration guide            |
| `CHANGELOG.md`                | Version history and changes                                                   |

## Lab Topology (SRv6)

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

## Demo Runner Output

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

## Demo Runner Commands

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

## Manual Installation (WSL)

If you prefer manual setup instead of using `setup_wsl_lab.py`:

### Prerequisites
- Windows 10 (Build 19041+) or Windows 11
- WSL2 with Ubuntu 22.04
- Docker Engine installed in WSL (NOT Docker Desktop)
- Containerlab and Netlab installed
- Go 1.23+ installed

### Steps
```bash
# Navigate to the directory
cd ~/datum/galantic-vpc

# Start the lab
sudo netlab up

# Connect to nodes
docker exec -it clab-galactic_vpc-sjc vtysh
docker exec -it clab-galactic_vpc-iad vtysh
docker exec -it clab-galactic_vpc-ams vtysh

# Verify connectivity (from sjc)
ping 10.255.0.3  # Ping AMS loopback

# Start galactic-agent (in another terminal)
cd ~/datum/galantic-vpc/galactic-agent
sudo ./galactic-agent --config ../galactic-agent-config.yaml

# Test MQTT route injection (in another terminal)
cd ~/datum/galantic-vpc
go run test-mqtt-route.go

# Cleanup
sudo netlab down
```

## Option 2: Connect Netlab to Datum's Public Infrastructure

The goal is to connect your local netlab/containerlab simulation to Datum's Galactic VPC 
so your local nodes can communicate with Datum's global edge network.

### Approach: Galactic Agent on K3s

Since you have k3s installed in WSL, you can run the galactic-agent locally to connect 
your containerlab nodes to Datum's SRv6 underlay.

### Prerequisites
1. **Datum Account** - Sign up at https://www.datum.net
2. **k3s running in WSL** - Your local Kubernetes cluster
3. **Galactic components** from Datum's galactic-lab repository

### Setup Steps

```bash
# 1. Clone the galactic-lab repository
git clone https://github.com/datum-cloud/galactic-lab.git
cd galactic-lab

# 2. Install Galactic CRDs and operator on k3s
kubectl apply -f deploy/crds/
kubectl apply -f deploy/operator/

# 3. Install galactic-agent as DaemonSet
kubectl apply -f deploy/agent/

# 4. Start your netlab topology
cd ~/datum/galantic-vpc
netlab up

# 5. Create VPCAttachment to connect containerlab nodes to Datum
# The galactic-agent will configure SRv6 tunnels to Datum's PoPs
```

### How It Works

1. **Netlab creates FRR containers** with SRv6 configuration
2. **Galactic-agent on k3s** connects to Datum's MQTT broker
3. **SRv6 tunnels** are established between your WSL and Datum's PoPs
4. **Traffic flows** through the SRv6 underlay to reach public internet

### Network Flow
```
Your WSL (netlab)  <--SRv6-->  Datum PoP (sjc/iad/ams)  <-->  Public Internet
```

## How It Works

### SRv6 Underlay
The Galactic VPC uses **Segment Routing over IPv6 (SRv6)** to encapsulate traffic between regions. Each node gets a unique SRv6 locator:
- SJC: `fc00:0:1::/48`
- IAD: `fc00:0:2::/48`
- AMS: `fc00:0:3::/48`

### Components Flow
1. **galactic-operator** watches for VPC/VPCAttachment CRDs
2. Creates Multus NetworkAttachmentDefinition for CNI
3. **galactic-cni** creates `galactic0` interface in pods
4. **galactic-agent** registers endpoints with galactic-router via MQTT
5. **galactic-router** computes routes and pushes to all agents
6. Traffic is encapsulated in SRv6 and routed across the underlay

## Exposing to Public Internet

Once deployed on Datum's infrastructure, you can expose services via:

1. **Kubernetes Services** (LoadBalancer type)
2. **Ingress Controllers** with public IPs
3. **Datum's edge network** for global anycast

Contact Datum support for public IP allocation and DNS configuration.

---

## About the Author

### Sajjad Ahmed

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/er-sajjad-ahmed/)

**Senior Network Architect & Open Source Contributor**  
**Company:** Multi Naturals Inc.

Sajjad Ahmed is a seasoned network architect with extensive experience in carrier-grade network operating systems and next-generation networking technologies.

### Professional Experience

| Platform                      | Description                                                   |
|-------------------------------|---------------------------------------------------------------|
| **SONiC NOS**                 | Open-source network operating system for data center switches |
| **IPOS (Ericsson)**           | Carrier-grade router operating system                         |
| **XROS**                      | High-performance routing platform                             |
| **SAOS (Ciena)**              | Service-aware operating system for packet-optical networks    |
| **IPI**                       | Network infrastructure platforms                              |
| **Broadcom Memory Chipsets**  | Memory chipset series                                         |
| **Broadcom Jericho Chipsets** | Jericho series ASIC programming and integration               |

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

---

*Document generated from Datum Galactic VPC Lab (https://www.datum.net/docs/galactic-vpc/#galactic-agent) - January 2026*  
*This WSL based Datum project is maintained by Sajjad Ahmed. Contributions and feedback are welcome.*
