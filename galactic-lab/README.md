# Galactic Lab

A testing and demonstration environment for [Galactic VPC](https://www.datum.net/docs/galactic-vpc/), a multi-cloud networking solution. This lab demonstrates multi-region Kubernetes cluster connectivity using SRv6 (Segment Routing over IPv6) packet routing.

There are different approaches to use this lab:
1. Using [Multipass](#approach-1-multipass-vm) if you'd like to run the lab in a dedicated VM.
2. Using [Dev Container](#approach-2-dev-container) is well suited if you use VS Code as your IDE.
3. Using _"Your own choice of Hypervisor"_ if you already have a way to run a Ubuntu/Debian VM. \
   In this case simply follow from step 2 in the [Multipass](#approach-1-multipass-vm) instructions.
4. If you are running Ubuntu/Debian Linux on your workstation - we _discourage_ running directly inside of it without a VM or Containers for isolation. \
   Netlab/Containerlab heavily modify the network configuration of the system, which may break your network connectivity. There be dragons.

No matter which approach you choose, Galactic relies on the SRv6 and VRF modules in the Linux kernel. This means the system where you install Galactic must have those modules available.


## Approach 1: Multipass VM

This approach creates an isolated Ubuntu VM using Multipass.

### Prerequisites
- [Multipass](https://documentation.ubuntu.com/multipass/latest/how-to-guides/install-multipass/)

### Steps

1. **Launch and enter the Multipass VM**

   Create a new Ubuntu VM with the required resources and mount the project directory:
   ```bash
   multipass launch -c 4 -d 50G -m 8G -n galactic-lab --mount .:/galactic-lab
   multipass shell galactic-lab
   sudo -s
   ```

2. **Install Netlab and dependencies**

   ```bash
   cd /galactic-lab
   export PIP_OPTIONS="--break-system-packages"
   sudo apt update && sudo apt install -y python3-pip
   python3 -m pip install $PIP_OPTIONS git+https://github.com/ipspace/netlab
   netlab install -y ubuntu ansible containerlab
   ```

3. **You're ready!** Proceed to the [Building the Custom Kind Node](#building-the-custom-kind-node) section below.


## Approach 2: Dev Container

This approach uses VS Code's Dev Container feature to provide a fully configured development environment with all dependencies pre-installed.

### Prerequisites
- [Visual Studio Code](https://code.visualstudio.com/)
- [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
- [Orbstack](https://orbstack.dev/)
  - Ensure you are using Orbstack: `docker context use orbstack`
  - Read the [Containerlab docs for MacOS](https://containerlab.dev/macos/) for details why Docker Desktop will not work here

### Steps

1. **Open the galactic-lab folder in VS Code**

2. **Reopen in Container**
   - Press `Cmd/Ctrl+Shift+P`
   - Type and select: `Dev Containers: Reopen in Container`
   - Wait for the container to build (first time only, ~5-10 minutes)
   - Press `Cmd/Ctrl+Shift+P`
   - Type and select: `Terminal: Create New Terminal`

3. **You're ready!** Proceed to the [Building the Custom Kind Node](#building-the-custom-kind-node) section below.


## Building the Custom Kind Node

Both approaches above prepare your host environment. Now you need to build the custom Kubernetes-in-Docker (Kind) node image with Galactic components pre-installed.

```bash
cd kindest-node-galactic
docker build . -t kindest/node:galactic
```

## Approach 3: WSL (Windows Subsystem for Linux)

Run the lab inside WSL2 on Windows using Docker Engine installed in WSL.

### Prerequisites
- Windows 10/11 with WSL2 enabled and Ubuntu installed
- Docker Engine running inside WSL (systemd or `sudo service docker start`)
- Python 3.10+, Go 1.20+, build-essential
- Ensure `~/.local/bin` is in PATH for pip user installs

### Steps
1. **Prepare WSL environment**
   ```bash
   sudo apt update && sudo apt install -y python3-pip git curl build-essential
   # Ensure ~/.local/bin is on PATH for this shell and future logins
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile
   source ~/.profile
   ```

2. **Clone the repo**
   ```bash
   git clone https://github.com/datum-cloud/galactic-lab.git
   cd galactic-lab
   ```

3. **Install Netlab and dependencies (inside WSL)**
   ```bash
   export PIP_OPTIONS="--break-system-packages"
   python3 -m pip install --user $PIP_OPTIONS git+https://github.com/ipspace/netlab
   netlab install -y ubuntu ansible containerlab
   ```

4. **Build or run the lab**
   - Build custom Kind node (if following Kind path):
     ```bash
     cd kindest-node-galactic
     docker build . -t kindest/node:galactic
     ```
   - Or run the WSL SRv6 lab (if using `platform/wsl` contents):
     ```bash
     cd platform/wsl
     netlab up
     ```

5. **Verify tooling**
   ```bash
   which netlab
   docker ps
   ```

More details and step-by-step WSL setup are in:
- `platform/wsl/srv6-vpc-lab-attachment/README.md` (WSL lab usage)
- `platform/wsl/srv6-vpc-lab-attachment/TUTORIAL.md` (full walkthrough)
- `platform/wsl/srv6-vpc-lab-attachment/setup_wsl_lab.py` (automated setup)
- `platform/wsl/srv6-vpc-lab-attachment/run_lab_demo.py` (run the demos)

Proceed to the [Building the Custom Kind Node](#building-the-custom-kind-node) section below or to WSL-specific workflows under `platform/wsl`.


## Next Steps

With your environment set up and the custom Kind node built, you're ready to deploy a [basic lab topology](basic/README.md) or a [geographic lab topology](geo/README.md).
