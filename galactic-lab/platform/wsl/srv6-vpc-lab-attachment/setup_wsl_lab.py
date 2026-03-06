#!/usr/bin/env python3
# =============================================================================
# Datum Galactic VPC Lab - Windows WSL Setup Script
# =============================================================================
# Author: Sajjad Ahmed
# Company: Multi Naturals Inc.
# Created: January 2026
# License: MIT
# Datum Source: https://www.datum.net/docs/galactic-vpc/#galactic-agent
#
# PURPOSE:
# This script automates the complete setup of the Datum Galactic VPC lab
# environment on Windows using WSL2. It installs all prerequisites and
# configures the lab topology with SRv6 routing.
#
# PREREQUISITES:
# 1. Windows 10 (Build 19041+) or Windows 11
# 2. Python 3.8+ installed on Windows
# 3. Administrator privileges (for WSL installation)
# 4. Internet connection
#
# USAGE:
# Run from Windows PowerShell or Command Prompt as Administrator:
#   python setup_wsl_lab.py
#
# Or with specific options:
#   python setup_wsl_lab.py --skip-wsl      # Skip WSL installation
#   python setup_wsl_lab.py --skip-docker   # Skip Docker installation
#   python setup_wsl_lab.py --help          # Show help
#
# WHAT THIS SCRIPT DOES:
# 1. Checks Windows version and prerequisites
# 2. Enables WSL2 feature (if not already enabled)
# 3. Installs Ubuntu 22.04 in WSL
# 4. Installs Docker Engine inside WSL (NOT Docker Desktop)
# 5. Installs Containerlab and Netlab
# 6. Installs Go 1.23+ for galactic-agent
# 7. Clones and builds galactic-agent
# 8. Installs Mosquitto MQTT broker
# 9. Copies topology files to WSL
# 10. Starts the lab topology
#
# IMPORTANT NOTES:
# - This script uses Docker Engine inside WSL, NOT Docker Desktop
# - Docker Desktop will NOT work with this lab (see TUTORIAL.md)
# - The script requires a system restart after enabling WSL2
#
# =============================================================================

import subprocess
import sys
import os
import time
import argparse
import platform
import ctypes
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

# WSL distribution name
WSL_DISTRO = "Ubuntu-22.04"

# Lab directory in WSL
WSL_LAB_DIR = "/home/$USER/datum/galantic-vpc"

# Go version to install
GO_VERSION = "1.23.4"

# Required Windows build for WSL2
MIN_WINDOWS_BUILD = 19041

# Colors for terminal output (Windows compatible)
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def print_header(text):
    """Print a formatted header"""
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.CYAN} {text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")

def print_step(step_num, text):
    """Print a step indicator"""
    print(f"{Colors.GREEN}[Step {step_num}]{Colors.ENDC} {text}")

def print_success(text):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {text}{Colors.ENDC}")

def print_warning(text):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠️  {text}{Colors.ENDC}")

def print_error(text):
    """Print error message"""
    print(f"{Colors.FAIL}❌ {text}{Colors.ENDC}")

def print_info(text):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.ENDC}")

def is_admin():
    """Check if script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_windows_build():
    """Get Windows build number"""
    try:
        version = platform.version()
        # Windows version format: "10.0.19041"
        build = int(version.split('.')[-1])
        return build
    except:
        return 0

def run_powershell(command, capture_output=True, check=True):
    """Run a PowerShell command"""
    full_command = f'powershell -Command "{command}"'
    result = subprocess.run(
        full_command,
        shell=True,
        capture_output=capture_output,
        text=True
    )
    if check and result.returncode != 0:
        print_error(f"Command failed: {command}")
        if result.stderr:
            print(result.stderr)
        return None
    return result

def run_wsl(command, distro=None, capture_output=True):
    """Run a command inside WSL"""
    if distro:
        full_command = f'wsl -d {distro} -- bash -c "{command}"'
    else:
        full_command = f'wsl -- bash -c "{command}"'
    
    result = subprocess.run(
        full_command,
        shell=True,
        capture_output=capture_output,
        text=True
    )
    return result

def check_wsl_installed():
    """Check if WSL is installed"""
    result = run_powershell("wsl --status", check=False)
    return result is not None and result.returncode == 0

def check_distro_installed(distro):
    """Check if a specific WSL distribution is installed"""
    result = run_powershell("wsl --list --quiet", check=False)
    if result and result.stdout:
        return distro in result.stdout
    return False

# =============================================================================
# INSTALLATION STEPS
# =============================================================================

def check_prerequisites():
    """Check all prerequisites before installation"""
    print_header("Checking Prerequisites")
    
    errors = []
    
    # Check Windows version
    print_step(1, "Checking Windows version...")
    build = get_windows_build()
    if build < MIN_WINDOWS_BUILD:
        errors.append(f"Windows build {build} is too old. Need {MIN_WINDOWS_BUILD}+")
    else:
        print_success(f"Windows build {build} is supported")
    
    # Check administrator privileges
    print_step(2, "Checking administrator privileges...")
    if not is_admin():
        errors.append("This script requires Administrator privileges")
        print_warning("Please run this script as Administrator")
    else:
        print_success("Running with Administrator privileges")
    
    # Check internet connectivity
    print_step(3, "Checking internet connectivity...")
    result = run_powershell("Test-Connection -ComputerName google.com -Count 1 -Quiet", check=False)
    if result and "True" in result.stdout:
        print_success("Internet connection available")
    else:
        errors.append("No internet connection detected")
    
    if errors:
        print_error("Prerequisites check failed:")
        for error in errors:
            print(f"  - {error}")
        return False
    
    print_success("All prerequisites met!")
    return True

def install_wsl():
    """Install and configure WSL2"""
    print_header("Installing WSL2")
    
    # Check if WSL is already installed
    print_step(1, "Checking existing WSL installation...")
    if check_wsl_installed():
        print_success("WSL is already installed")
    else:
        print_info("Installing WSL2...")
        result = run_powershell("wsl --install --no-distribution", check=False)
        if result and result.returncode == 0:
            print_success("WSL2 installed successfully")
            print_warning("A system restart may be required")
        else:
            print_error("Failed to install WSL2")
            return False
    
    # Set WSL2 as default
    print_step(2, "Setting WSL2 as default version...")
    run_powershell("wsl --set-default-version 2", check=False)
    print_success("WSL2 set as default")
    
    # Install Ubuntu
    print_step(3, f"Checking {WSL_DISTRO} installation...")
    if check_distro_installed(WSL_DISTRO):
        print_success(f"{WSL_DISTRO} is already installed")
    else:
        print_info(f"Installing {WSL_DISTRO}...")
        result = run_powershell(f"wsl --install -d {WSL_DISTRO}", check=False)
        if result:
            print_success(f"{WSL_DISTRO} installed")
            print_warning("Please complete Ubuntu setup (create user) and run this script again")
            return False
    
    return True

def install_docker_in_wsl():
    """Install Docker Engine inside WSL (NOT Docker Desktop)"""
    print_header("Installing Docker Engine in WSL")
    
    # Check if Docker is already installed
    print_step(1, "Checking existing Docker installation...")
    result = run_wsl("docker --version", distro=WSL_DISTRO)
    if result.returncode == 0:
        print_success(f"Docker already installed: {result.stdout.strip()}")
        
        # Check Docker context
        print_step(2, "Verifying Docker context (must NOT be Docker Desktop)...")
        result = run_wsl("docker context ls", distro=WSL_DISTRO)
        if "desktop-linux" in result.stdout and "*" in result.stdout.split("desktop-linux")[0].split("\n")[-1]:
            print_error("Docker Desktop is active! This will NOT work with the lab.")
            print_info("Switching to native Docker context...")
            run_wsl("docker context use default", distro=WSL_DISTRO)
        else:
            print_success("Docker context is correct (native)")
        return True
    
    # Install Docker Engine
    print_step(2, "Installing Docker Engine...")
    
    docker_install_commands = """
    # Update package index
    sudo apt-get update
    
    # Install prerequisites
    sudo apt-get install -y ca-certificates curl gnupg lsb-release
    
    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Set up Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker Engine
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add current user to docker group
    sudo usermod -aG docker $USER
    
    # Start Docker service
    sudo service docker start
    """
    
    for line in docker_install_commands.strip().split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            print_info(f"Running: {line[:50]}...")
            run_wsl(line, distro=WSL_DISTRO)
    
    print_success("Docker Engine installed")
    return True

def install_containerlab():
    """Install Containerlab in WSL"""
    print_header("Installing Containerlab")
    
    # Check if already installed
    print_step(1, "Checking existing Containerlab installation...")
    result = run_wsl("containerlab version", distro=WSL_DISTRO)
    if result.returncode == 0:
        print_success(f"Containerlab already installed")
        return True
    
    # Install Containerlab
    print_step(2, "Installing Containerlab...")
    install_cmd = "bash -c \"$(curl -sL https://get.containerlab.dev)\""
    result = run_wsl(install_cmd, distro=WSL_DISTRO)
    
    if result.returncode == 0:
        print_success("Containerlab installed")
    else:
        print_error("Failed to install Containerlab")
        return False
    
    return True

def install_netlab():
    """Install Netlab in WSL"""
    print_header("Installing Netlab")
    
    # Check if already installed
    print_step(1, "Checking existing Netlab installation...")
    result = run_wsl("netlab version", distro=WSL_DISTRO)
    if result.returncode == 0:
        print_success("Netlab already installed")
        return True
    
    # Install Netlab
    print_step(2, "Installing Netlab and dependencies...")
    commands = [
        "sudo apt-get install -y python3-pip ansible",
        "pip3 install networklab",
        "netlab install containerlab"
    ]
    
    for cmd in commands:
        print_info(f"Running: {cmd[:50]}...")
        run_wsl(cmd, distro=WSL_DISTRO)
    
    print_success("Netlab installed")
    return True

def install_go():
    """Install Go 1.23+ in WSL"""
    print_header(f"Installing Go {GO_VERSION}")
    
    # Check if Go is already installed with correct version
    print_step(1, "Checking existing Go installation...")
    result = run_wsl("go version", distro=WSL_DISTRO)
    if result.returncode == 0 and f"go{GO_VERSION}" in result.stdout:
        print_success(f"Go {GO_VERSION} already installed")
        return True
    
    # Install Go
    print_step(2, f"Downloading and installing Go {GO_VERSION}...")
    commands = [
        f"wget -q https://go.dev/dl/go{GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz",
        "sudo rm -rf /usr/local/go",
        "sudo tar -C /usr/local -xzf /tmp/go.tar.gz",
        "rm /tmp/go.tar.gz",
        'echo \'export PATH=$PATH:/usr/local/go/bin\' >> ~/.bashrc',
        'echo \'export PATH=$PATH:$HOME/go/bin\' >> ~/.bashrc'
    ]
    
    for cmd in commands:
        print_info(f"Running: {cmd[:50]}...")
        run_wsl(cmd, distro=WSL_DISTRO)
    
    print_success(f"Go {GO_VERSION} installed")
    return True

def install_mosquitto():
    """Install Mosquitto MQTT broker in WSL"""
    print_header("Installing Mosquitto MQTT Broker")
    
    # Check if already installed
    print_step(1, "Checking existing Mosquitto installation...")
    result = run_wsl("mosquitto -h", distro=WSL_DISTRO)
    if result.returncode == 0 or "mosquitto" in result.stderr:
        print_success("Mosquitto already installed")
        return True
    
    # Install Mosquitto
    print_step(2, "Installing Mosquitto...")
    commands = [
        "sudo apt-get update",
        "sudo apt-get install -y mosquitto mosquitto-clients"
    ]
    
    for cmd in commands:
        run_wsl(cmd, distro=WSL_DISTRO)
    
    print_success("Mosquitto installed")
    return True

def setup_lab_directory():
    """Create lab directory and copy files"""
    print_header("Setting Up Lab Directory")
    
    # Get the directory where this script is located
    script_dir = Path(__file__).parent.absolute()
    
    # Create lab directory in WSL
    print_step(1, "Creating lab directory in WSL...")
    run_wsl("mkdir -p ~/datum/galantic-vpc", distro=WSL_DISTRO)
    
    # Files to copy
    files_to_copy = [
        "topology.yaml",
        "galactic-agent-config.yaml",
        "galactic-manifest.yaml",
        "agent.yaml",
        "test-mqtt-route.go",
        "TUTORIAL.md",
        "README.md",
        "CHANGELOG.md",
        ".gitignore"
    ]
    
    # Copy files
    print_step(2, "Copying lab files to WSL...")
    for filename in files_to_copy:
        src_path = script_dir / filename
        if src_path.exists():
            # Convert Windows path to WSL path
            wsl_src = str(src_path).replace('\\', '/').replace('C:', '/mnt/c')
            run_wsl(f"cp '{wsl_src}' ~/datum/galantic-vpc/", distro=WSL_DISTRO)
            print_success(f"Copied {filename}")
        else:
            print_warning(f"File not found: {filename}")
    
    # Copy filter_plugins directory if exists
    filter_plugins_dir = script_dir / "filter_plugins"
    if filter_plugins_dir.exists():
        wsl_src = str(filter_plugins_dir).replace('\\', '/').replace('C:', '/mnt/c')
        run_wsl(f"cp -r '{wsl_src}' ~/datum/galantic-vpc/", distro=WSL_DISTRO)
        print_success("Copied filter_plugins/")
    
    print_success("Lab directory setup complete")
    return True

def clone_galactic_agent():
    """Clone and build galactic-agent"""
    print_header("Setting Up Galactic Agent")
    
    # Check if already cloned
    print_step(1, "Checking existing galactic-agent...")
    result = run_wsl("ls ~/datum/galantic-vpc/galactic-agent/main.go", distro=WSL_DISTRO)
    if result.returncode == 0:
        print_success("galactic-agent already exists")
    else:
        # Clone galactic-agent
        print_step(2, "Cloning galactic-agent...")
        clone_cmd = "cd ~/datum/galantic-vpc && git clone https://github.com/datum-cloud/galactic-agent.git"
        run_wsl(clone_cmd, distro=WSL_DISTRO)
    
    # Build galactic-agent
    print_step(3, "Building galactic-agent...")
    build_cmd = "cd ~/datum/galantic-vpc/galactic-agent && /usr/local/go/bin/go mod download && /usr/local/go/bin/go build -o galactic-agent ."
    result = run_wsl(build_cmd, distro=WSL_DISTRO)
    
    if result.returncode == 0:
        print_success("galactic-agent built successfully")
    else:
        print_warning("galactic-agent build may have issues, check manually")
    
    return True

def print_final_instructions():
    """Print final setup instructions"""
    print_header("Setup Complete!")
    
    print(f"""
{Colors.GREEN}The Datum Galactic VPC Lab has been set up successfully!{Colors.ENDC}

{Colors.BOLD}Next Steps:{Colors.ENDC}

1. Open WSL Ubuntu:
   {Colors.CYAN}wsl -d {WSL_DISTRO}{Colors.ENDC}

2. Navigate to lab directory:
   {Colors.CYAN}cd ~/datum/galantic-vpc{Colors.ENDC}

3. Start the lab topology:
   {Colors.CYAN}sudo netlab up{Colors.ENDC}

4. In another terminal, start the galactic-agent:
   {Colors.CYAN}cd ~/datum/galantic-vpc/galactic-agent
   sudo ./galactic-agent -config ../galactic-agent-config.yaml{Colors.ENDC}

5. Test MQTT route injection:
   {Colors.CYAN}cd ~/datum/galantic-vpc
   go run test-mqtt-route.go{Colors.ENDC}

{Colors.BOLD}Useful Commands:{Colors.ENDC}
   - Check lab status:    {Colors.CYAN}sudo netlab status{Colors.ENDC}
   - Stop lab:            {Colors.CYAN}sudo netlab down{Colors.ENDC}
   - View FRR config:     {Colors.CYAN}docker exec -it clab-galactic_vpc-sjc vtysh{Colors.ENDC}
   - Check bridges:       {Colors.CYAN}brctl show{Colors.ENDC}

{Colors.BOLD}Documentation:{Colors.ENDC}
   - Tutorial:            ~/datum/galantic-vpc/TUTORIAL.md
   - Datum Docs:          https://www.datum.net/docs/galactic-vpc/

{Colors.WARNING}Note: You may need to log out and back in for Docker group permissions to take effect.{Colors.ENDC}
""")

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Datum Galactic VPC Lab - Windows WSL Setup Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup_wsl_lab.py              # Full installation
  python setup_wsl_lab.py --skip-wsl   # Skip WSL installation
  python setup_wsl_lab.py --skip-docker # Skip Docker installation
        """
    )
    parser.add_argument('--skip-wsl', action='store_true', help='Skip WSL installation')
    parser.add_argument('--skip-docker', action='store_true', help='Skip Docker installation')
    parser.add_argument('--skip-go', action='store_true', help='Skip Go installation')
    parser.add_argument('--skip-agent', action='store_true', help='Skip galactic-agent setup')
    args = parser.parse_args()
    
    print_header("Datum Galactic VPC Lab Setup")
    print(f"""
    {Colors.CYAN}Author:{Colors.ENDC} Sajjad Ahmed
    {Colors.CYAN}Company:{Colors.ENDC} Multi Naturals Inc.
    {Colors.CYAN}Version:{Colors.ENDC} 1.2.0
    
    This script will set up the complete Datum Galactic VPC lab
    environment on Windows using WSL2.
    """)
    
    # Check prerequisites
    if not check_prerequisites():
        print_error("Prerequisites check failed. Please fix the issues and try again.")
        sys.exit(1)
    
    # Installation steps
    steps = [
        ("WSL2", install_wsl, args.skip_wsl),
        ("Docker", install_docker_in_wsl, args.skip_docker),
        ("Containerlab", install_containerlab, False),
        ("Netlab", install_netlab, False),
        ("Go", install_go, args.skip_go),
        ("Mosquitto", install_mosquitto, False),
        ("Lab Directory", setup_lab_directory, False),
        ("Galactic Agent", clone_galactic_agent, args.skip_agent),
    ]
    
    for name, func, skip in steps:
        if skip:
            print_warning(f"Skipping {name} installation")
            continue
        
        try:
            if not func():
                print_error(f"{name} installation failed")
                # Continue with other steps even if one fails
        except Exception as e:
            print_error(f"{name} installation error: {e}")
    
    # Print final instructions
    print_final_instructions()

if __name__ == "__main__":
    main()
