#!/usr/bin/env bash
set -euo pipefail

echo "Starting post-create setup for Galactic development environment..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Copy host gitconfig so VS Code can write its credential helper without hitting
# EBUSY (which occurs when the target path itself has an active bind mount).
if [[ -f /home/vscode/.gitconfig.host ]]; then
    cp /home/vscode/.gitconfig.host /home/vscode/.gitconfig
fi

# Upgrade/install packages
echo "Upgrading/installing Ubuntu packages..."
curl -1sLf 'https://dl.cloudsmith.io/public/task/task/setup.deb.sh' | sudo -E bash
sudo apt-get update -q
sudo apt-get install -y -q software-properties-common
sudo add-apt-repository -y ppa:apt-fast/stable
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q apt-fast
sudo apt-fast install -y \
	bridge-utils \
	build-essential \
	conntrack \
	dnsutils \
	ethtool \
	gcc \
	iproute2 \
	iptables \
	iputils-ping \
	jq \
	make \
	net-tools \
	task \
	tcpdump

# Set up Go tools
echo "Installing Go development tools..."
go install golang.org/x/tools/gopls@latest
go install github.com/go-delve/delve/cmd/dlv@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6

# Install kind for local Kubernetes testing
echo "Installing Kind..."
go install sigs.k8s.io/kind@latest

# Install protoc (Protocol Buffer compiler)
echo "Installing protoc..."
PROTOC_VERSION="25.1"
PROTOC_ARCH=$(uname -m)
# protoc releases use aarch_64 (with underscore) for ARM64, unlike most other tools
case "$PROTOC_ARCH" in aarch64) PROTOC_ARCH="aarch_64" ;; esac
PROTOC_ZIP="protoc-${PROTOC_VERSION}-linux-${PROTOC_ARCH}.zip"
curl -fsSLO "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/${PROTOC_ZIP}"
sudo unzip -o "${PROTOC_ZIP}" -d /usr/local bin/protoc
sudo unzip -o "${PROTOC_ZIP}" -d /usr/local 'include/*'
rm -f "${PROTOC_ZIP}"

# Install protoc-gen-go for Go protobuf generation
echo "Installing protoc-gen-go..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install Claude Code CLI
echo "Installing Claude Code..."
curl -fsSL https://claude.ai/install.sh | bash

# Verify installations
echo ""
echo "Verifying installations..."
echo "Go version: $(go version)"
echo "kubectl version: $(kubectl version --client 2>/dev/null || echo 'kubectl installed')"
echo "kind version: $(kind version)"
echo "protoc version: $(protoc --version)"
echo "Docker version: $(docker --version)"
echo "golangci-lint version: $(golangci-lint version 2>/dev/null || echo 'golangci-lint installed')"
echo "delve version: $(dlv version)"
echo "gopls version: $(gopls version)"

echo ""
echo "Post-create setup completed successfully!"
echo ""
echo "You can now:"
echo "  - Build the galactic binary: task build"
echo "  - Run tests: task test"
echo "  - Run the agent: task run-agent"
echo ""
