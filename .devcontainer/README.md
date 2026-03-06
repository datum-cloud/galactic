# Galactic Development Container

This devcontainer provides a complete development environment for the Galactic multi-cloud networking solution.

## Features

### Languages & Runtimes
- **Go 1.24.2** - For operator, agent, and CNI development
- **Python 3.13** - For the galactic-router

### Kubernetes Tools
- **kubectl** - Kubernetes CLI
- **kind** - Kubernetes in Docker for local clusters
- **kustomize v5.6.0** - Kubernetes configuration management
- **controller-gen v0.18.0** - Code generation for Kubernetes controllers
- **setup-envtest** - Test environment for controller-runtime

### Go Development Tools
- **gopls** - Go language server
- **delve** - Go debugger
- **golangci-lint v2.1.6** - Go linter

### Network Tools
- **iproute2** - Advanced network configuration (ip, ss, etc.)
- **iptables** - Firewall management
- **tcpdump** - Network packet analyzer
- **iputils-ping** - Network connectivity testing
- **net-tools** - Classic network tools (ifconfig, netstat, etc.)
- **dnsutils** - DNS utilities (dig, nslookup)
- **bridge-utils** - Bridge configuration
- **ethtool** - Network interface settings
- **conntrack** - Connection tracking

### Build & Development Tools
- **Docker-in-Docker** - For building containers and running Kind clusters
- **protoc 25.1** - Protocol Buffer compiler
- **protoc-gen-go** - Go code generation for protobuf
- **protoc-gen-go-grpc** - gRPC code generation for Go
- **make** - Build automation
- **gcc/build-essential** - C compiler for CGO dependencies
- **jq** - JSON processor
- **git** - Version control

## VS Code Extensions

The devcontainer includes the following extensions:
- **Go** - Official Go extension
- **Python** - Official Python extension
- **Pylance** - Python language server
- **Kubernetes** - Kubernetes resource management
- **YAML** - YAML language support
- **Docker** - Docker container management
- **GitLens** - Enhanced Git integration
- **Markdown Lint** - Markdown linting
- **Even Better TOML** - TOML language support

## Configuration

### Go Settings
- Auto-format on save with `gofmt`
- Organize imports on save
- golangci-lint integration
- gopls with semantic tokens and useful code lenses
- Test environment set to `GOOS=linux`

### Python Settings
- Auto-format on save
- Organize imports on save
- flake8 linting enabled
- Python 3.13 interpreter

### Forwarded Ports
- **8080** - Metrics endpoint
- **8081** - Health check endpoint
- **9443** - Webhook server

## Capabilities

The devcontainer runs with elevated privileges to support network operations:
- `--privileged` - Full device access
- `--cap-add=NET_ADMIN` - Network administration
- `--cap-add=SYS_ADMIN` - System administration

These are required for:
- Creating network namespaces
- Configuring VRFs (Virtual Routing and Forwarding)
- Managing SRv6 routes
- Testing CNI plugins

## Post-Create Setup

The `post-create.sh` script automatically:
1. Installs Go development tools (gopls, delve, golangci-lint)
2. Installs Kubernetes tools (controller-gen, kustomize, setup-envtest, kind)
3. Installs Protocol Buffer compiler and Go plugins
4. Installs network diagnostic tools
5. Sets up the Python environment for galactic-router
6. Generates Kubernetes manifests and DeepCopy methods
7. Configures git safe directory

## Getting Started

After the container starts and post-create completes:

```bash
# Build the galactic binary
make build

# Run unit tests
make test

# Run E2E tests (creates a Kind cluster)
make test-e2e

# Run the operator locally
make run-operator

# Run the agent locally
make run-agent

# Develop the Python router
cd router
behave

# Lint Go code
make lint

# Format Go code
make fmt
```

## Testing

### Unit Tests
```bash
make test
```

### E2E Tests
```bash
# Automatically creates/tears down Kind cluster
make test-e2e

# Or manually manage the cluster
make setup-test-e2e
go test ./test/e2e/ -v -ginkgo.v
make cleanup-test-e2e
```

### Python Tests
```bash
cd router
behave           # Run BDD tests
flake8           # Lint Python code
```

## Network Development

The devcontainer includes all tools needed for network programming:

```bash
# View network interfaces
ip link show

# View routing tables
ip route show

# View SRv6 segments
ip -6 route show

# Capture traffic
tcpdump -i any

# Test connectivity
ping -c 3 8.8.8.8
```

## Docker-in-Docker

Build and test containers inside the devcontainer:

```bash
# Build the galactic image
make docker-build

# Create a Kind cluster
kind create cluster --name galactic-dev

# Load image into Kind
kind load docker-image ghcr.io/datum-cloud/galactic:latest --name galactic-dev
```

## Troubleshooting

### Post-create script fails
Check the logs in the VS Code Output panel under "Dev Containers". Common issues:
- Network connectivity for downloading tools
- Permissions for installing system packages

### Network tools don't work
Ensure the container is running with `--privileged` and the necessary capabilities. Check `runArgs` in `devcontainer.json`.

### Kind cluster creation fails
Ensure Docker-in-Docker is running:
```bash
docker ps
```

If not, restart the devcontainer.

### Go modules not resolving
```bash
go mod download
go mod tidy
```

### Python packages not installing
```bash
cd router
pip install --upgrade pip
pip install -e .[test]
```
