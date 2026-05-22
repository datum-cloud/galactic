#!/usr/bin/env bash
set -euo pipefail

echo "Starting post-create setup for containerlab-dood environment..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
esac

# Upgrade/install packages
echo "Upgrading/installing Debian packages..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y

# Install Claude Code
echo "Installing Claude Code..."
curl -fsSL https://claude.ai/install.sh | bash

# Install kubectl
echo "Installing kubectl..."
KUBECTL_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH}/kubectl" \
    | sudo tee /usr/local/bin/kubectl > /dev/null
sudo chmod +x /usr/local/bin/kubectl

# Install kind for local Kubernetes
echo "Installing Kind..."
go install sigs.k8s.io/kind@latest

# Install crane for pulling container images (Docker binaries in this environment
# panic on TLS 1.3 to Docker Hub due to an msft-golang/OpenSSL bug on ARM64)
echo "Installing crane..."
CRANE_VERSION=$(curl -fsSL https://api.github.com/repos/google/go-containerregistry/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
curl -fsSL "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${ARCH}.tar.gz" \
    | sudo tar xz -C /usr/local/bin crane

# Verify installations
echo ""
echo "Verifying installations..."
echo "Go version: $(go version)"
echo "kubectl version: $(kubectl version --client 2>/dev/null || echo 'kubectl not installed')"
echo "kind version: $(kind version)"
echo "Docker version: $(docker --version)"

echo ""
echo "Post-create setup completed successfully!"
