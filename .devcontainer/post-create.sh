#!/usr/bin/env bash
set -euo pipefail

echo "Starting post-create setup for Galactic development environment..."

# Set up Go tools
echo "Installing Go development tools..."
go install golang.org/x/tools/gopls@latest
go install github.com/go-delve/delve/cmd/dlv@latest
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6

# Install controller-gen, kustomize, and other Kubernetes tools
echo "Installing Kubernetes development tools..."
cd /workspaces/galactic
make controller-gen kustomize setup-envtest

# Install kind for local Kubernetes testing
echo "Installing Kind..."
GO111MODULE=on go install sigs.k8s.io/kind@latest

# Install protoc (Protocol Buffer compiler)
echo "Installing protoc..."
PROTOC_VERSION="25.1"
curl -LO "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
sudo unzip -o protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local bin/protoc
sudo unzip -o protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local 'include/*'
rm -f protoc-${PROTOC_VERSION}-linux-x86_64.zip

# Install protoc-gen-go for Go protobuf generation
echo "Installing protoc-gen-go..."
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Install network tools
echo "Installing network tools..."
sudo apt-get update
sudo apt-get install -y \
	iproute2 \
	iptables \
	tcpdump \
	iputils-ping \
	net-tools \
	dnsutils \
	bridge-utils \
	ethtool \
	conntrack \
	jq \
	make \
	gcc \
	build-essential

# Set up Python environment for galactic-router
echo "Setting up Python environment for galactic-router..."
cd /workspaces/galactic/router
pip install --upgrade pip setuptools wheel
pip install -e .[test]

# Generate Kubernetes manifests and code
echo "Generating Kubernetes manifests and DeepCopy methods..."
cd /workspaces/galactic
make manifests generate

# Set up git safe directory
echo "Configuring git safe directory..."
git config --global --add safe.directory /workspaces/galactic

# Install Claude Code CLI
echo "Installing Claude Code..."
npm install -g @anthropic-ai/claude-code

# Verify installations
echo ""
echo "Verifying installations..."
echo "Go version: $(go version)"
echo "Python version: $(python3 --version)"
echo "kubectl version: $(kubectl version --client --short 2>/dev/null || echo 'kubectl installed')"
echo "kind version: $(kind version)"
echo "kustomize version: $(kustomize version --short 2>/dev/null || echo 'kustomize installed')"
echo "protoc version: $(protoc --version)"
echo "Docker version: $(docker --version)"
echo "golangci-lint version: $(golangci-lint version 2>/dev/null || echo 'golangci-lint installed')"
echo "delve version: $(dlv version)"
echo "gopls version: $(gopls version)"

echo ""
echo "Post-create setup completed successfully!"
echo ""
echo "You can now:"
echo "  - Build the galactic binary: make build"
echo "  - Run tests: make test"
echo "  - Run E2E tests: make test-e2e"
echo "  - Run the operator: make run-operator"
echo "  - Run the agent: make run-agent"
echo "  - Develop the router: cd router && behave"
echo ""
