#!/usr/bin/env bash
set -euo pipefail

echo "Starting post-create setup for Galactic containerlab environment..."

# Install packages
echo "Installing Debian packages..."
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y
# Install Claude
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm install -g @anthropic-ai/claude-code

# Install kubectl
echo "Installing kubectl..."
KUBECTL_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/arm64/kubectl" \
    | sudo tee /usr/local/bin/kubectl > /dev/null
sudo chmod +x /usr/local/bin/kubectl

# Install kind for local Kubernetes
echo "Installing Kind..."
GO111MODULE=on go install sigs.k8s.io/kind@latest

# Install crane for pulling container images (Docker binaries in this environment
# panic on TLS 1.3 to Docker Hub due to an msft-golang/OpenSSL bug on ARM64)
echo "Installing crane..."
CRANE_VERSION=$(curl -fsSL https://api.github.com/repos/google/go-containerregistry/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
curl -fsSL "https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_arm64.tar.gz" \
    | sudo tar xz -C /usr/local/bin crane

# Disable atuin's up-arrow TUI (keep atuin for ctrl-r but restore normal up-arrow history)
sed -i 's/eval "$(atuin init zsh)"/eval "$(atuin init zsh --disable-up-arrow)"/' ~/.zshrc

# Verify installations
echo ""
echo "Verifying installations..."
echo "Go version: $(go version)"
echo "Python version: $(python3 --version)"
echo "kubectl version: $(kubectl version --client --short 2>/dev/null || echo 'kubectl not installed')"
echo "kind version: $(kind version)"
echo "kustomize version: $(kustomize version --short 2>/dev/null || echo 'kustomize not installed')"
echo "Docker version: $(docker --version)"

echo ""
echo "Post-create setup completed successfully!"
