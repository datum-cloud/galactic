# Changelog

All notable changes to the Datum Galactic VPC project.

**Author:** Sajjad Ahmed  
**Company:** Multi Naturals Inc.

---

## [1.2.3] - 2026-01-14

### Added
- **Comprehensive topology diagram** in `run_lab_demo.py`
  - Separated Control Plane and Data Plane visualization
  - Shows MQTT ↔ Agent ↔ Kernel ↔ Bridge ↔ FRR nodes flow
  - Added MQTT Message Flow section with Protobuf examples
  - Added "Communication Flow Details" explaining 4-step process:
    1. MQTT Subscription (Agent ← Broker)
    2. Kernel Route Programming (Agent → Linux Kernel)
    3. Packet Forwarding (Kernel → FRR Nodes via Bridge)
    4. Agent Registration (Agent → Broker)
  - Added "Lab Testing: Protobuf Route Injection" section
    - How test-mqtt-route.go works
    - Example RouteUpdate Protobuf message
    - Verification commands
    - Alternative manual MQTT publish method
- **Exit instructions** in interactive shell
  - Shows `exit` and `Ctrl+D` options to return to demo

---

## [1.2.2] - 2026-01-14

### Added
- **Enhanced topology diagram** in `run_lab_demo.py`
  - Added MQTT Broker and Galactic Agent to the diagram
  - Shows connection between MQTT and Agent for route updates
  - Displays real-time status of MQTT broker and galactic-agent
  - Provides startup instructions if either service is not running
- **New helper functions** in `run_lab_demo.py`
  - `check_mqtt_running()` - Detects Mosquitto service or Docker container
  - `check_agent_running()` - Detects running galactic-agent process

---

## [1.2.1] - 2026-01-14

### Fixed
- **PATH environment issue** in `run_lab_demo.py`
  - Interactive shell now uses `bash --login` to preserve PATH
  - Fixes issue where `netlab` command was not found after exiting containers
  - Ensures `~/.local/bin` (where netlab is installed) remains in PATH

### Added
- **`.gitignore` file** for cleaner repository
  - Excludes generated `.bin` files (route_ams.bin, route_iad.bin)
  - Excludes `netlab.lock` and netlab snapshot files
  - Excludes `clab-*/` containerlab directories
  - Excludes Ansible generated files (host_vars/, group_vars/, hosts.yml)
  - Excludes test output files, Python cache, Go build artifacts

---

## [1.2.0] - 2026-01-14

### Added
- **Python automation scripts**
  - `setup_wsl_lab.py` - Windows installer for complete WSL lab setup
  - `run_lab_demo.py` - Interactive demo runner with connectivity tests
  - `test-mqtt-route.go` - Protobuf route injection test script
- **lo-galactic interface requirement** documented
  - Agent requires dummy loopback interface for SRv6 encapsulation
  - Added creation instructions in Step 10.6
- **SRv6 endpoint encoding** explained
  - VPC ID (48 bits) and VPCAttachment ID (16 bits) format
  - How galactic-agent decodes endpoints
- **Manual SRv6 route injection** (Step 10.10)
  - Alternative to agent for testing SRv6 encapsulation
  - Direct kernel route programming commands
- **Scope & Target Audience** section in TUTORIAL.md
  - Who this guide is for (Network Engineers, DevOps, Students)
  - Prerequisites and what you will learn
- **Critical: Docker in WSL vs Docker Desktop** section
  - Diagram explaining why Docker Desktop won't work
  - Instructions to check and fix Docker context
- **Linux Bridge explanation** in Lab Topology diagram
  - How containerlab creates bridges
  - brctl show commands and examples
  - veth pair connectivity explanation
- **Go 1.23+ installation** (Step 10.1)
  - Ubuntu apt Go is too old for galactic-agent
  - Manual Go installation from go.dev
- **Complete galactic-agent workflow** (Step 10)
  - Clone into galantic-vpc directory (unified git repo)
  - Build with go mod download && go build
  - Install Mosquitto MQTT broker for local testing
  - Create config.yaml with detailed comments
  - Run agent and verify MQTT connection
  - Test MQTT communication with mosquitto_pub/sub
- **Step 11: Connect to Datum Cloud Infrastructure**
  - Production config template with Datum MQTT broker
  - How to get Datum credentials
  - End-to-End architecture diagram (WSL to Datum Cloud)
  - Traffic flow explanation
- **End-to-End Packet Flow Example** diagram
  - 4-step packet journey from SJC to AMS
  - SRv6 encapsulation/decapsulation details
  - Linux bridge transit explanation
- **Step 12: Running the Lab with Python Scripts**
  - Automated setup and demo instructions
  - Lab topology diagram
  - Demo runner command reference

### Changed
- Fixed `--config` flag (was `-config`) in all documentation
- Updated Table of Contents with 22 sections
- Improved Lab Topology diagram with bridge details
- Expanded galactic-agent section from basic to comprehensive
- Added version 1.2.0 to reflect major documentation update

### Technical Details
- Go 1.23.4 required (Ubuntu apt only has 1.18)
- Mosquitto MQTT broker for local testing
- galactic-agent moved into galantic-vpc for unified git management
- Agent requires VRF interfaces from CNI registration (documented limitation)
- lo-galactic dummy interface required for route programming
- **WSL2 Kernel Limitation**: SRv6 seg6 encapsulation not supported (documented)
- VRF interface naming: `G{vpc}{attachment}V` (e.g., `G000000001001V`)

### New Section: Understanding VPC
- What is a VPC (Virtual Private Cloud)
- How Datum implements VPC using VRF + SRv6
- Global vs Per-VPC SRv6 segments diagram
- VPC isolation step-by-step flow
- Comparison: Traditional VPN vs Datum VPC

---

## [1.1.0] - 2026-01-14

### Added
- Comprehensive SRv6 education section in TUTORIAL.md
  - What is SRv6, SID structure, behaviors
  - Step-by-step packet flow explanation
- Geo-Location & BGP Path Selection section
  - Anycast routing explanation
  - BGP best path algorithm
  - ISIS-BGP synchronization details
- K3s installation guide (Step 6)
  - Installation commands
  - kubectl configuration
  - Essential K3s commands reference
- Galactic-Agent deployment guide (Step 10)
  - Clone, build, deploy instructions
  - Agent architecture diagram
  - Key functions explanation
  - Configuration reference
- MQTT Message Formats section
  - Protocol Buffer definitions
  - Message flow examples (Register, Route, Netlink)
  - Complete message flow diagram
- Benefits & Use Cases section
  - Cost savings comparison
  - Real-world use cases (learning, CI/CD, demos, development)

### Changed
- `topology.yaml` - Complete rewrite with comprehensive comments
  - Added author header (Sajjad Ahmed, Multi Naturals Inc.)
  - Added BGP module for ISIS-BGP synchronization
  - Detailed comments explaining every section
  - SRv6 architecture explanation in header
  - Verification commands in footer
- `TUTORIAL.md` - Major expansion
  - Added author header
  - Restructured table of contents
  - Added 200+ lines of new content
  - Added "About the Author" section with LinkedIn contact
- `README.md` - Added "About the Author" section
  - Professional experience (SONiC, IPOS, XROS, SAOS, IPI, Broadcom Jericho)
  - Areas of expertise (Network Architecture, SRv6, Quantum-Safe Communications)
  - LinkedIn contact: https://www.linkedin.com/in/er-sajjad-ahmed/

### Technical Details
- Added BGP AS 65000 for iBGP mesh between POPs
- ISIS remains primary IGP for SRv6 segment advertisement
- BGP used for route policy and external connectivity

---

## [1.0.0] - 2026-01-14

### Added
- Initial `topology.yaml` for Galactic VPC with SRv6
  - 3 nodes: sjc (San Jose), iad (Northern Virginia), ams (Amsterdam)
  - ISIS routing with SRv6 locators
  - VPC backbone: 10.1.1.0/24, 2001:10:1:1::/64
  - Service prefixes: 192.168.1.0/24 (sjc), 192.168.2.0/24 (ams)
  - SRv6 locators: fc00:0:1::/48, fc00:0:2::/48, fc00:0:3::/48

- `TUTORIAL.md` - Comprehensive installation guide
  - WSL2 installation on Windows
  - Ubuntu 22.04 setup
  - Docker installation
  - Containerlab installation
  - Netlab installation
  - Step-by-step lab creation and verification
  - Architecture diagrams
  - Reference commands for FRR, containerlab, netlab

- `README.md` - Project overview and quick start guide
  - Architecture diagram
  - Local testing instructions
  - Datum integration approach

### Technical Details
- Tested on:
  - WSL 2.6.3.0
  - Ubuntu 22.04.5 LTS
  - Docker 28.2.2
  - Containerlab 0.72.0
  - Ansible 2.17.14
  - FRRouting 10.5.0

### Notes
- SRv6 requires `bgp: false` in netlab config (FRR doesn't support BGP+SRv6 in netlab)
- Uses ISIS as the only IGP for SRv6 segment advertisement
