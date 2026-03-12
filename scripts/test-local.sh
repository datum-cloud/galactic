#!/bin/bash
# Local testing script for Galactic
# Runs tests in Docker to ensure Linux compatibility

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="golang:1.24"

echo "=== Galactic Local Test Runner ==="
echo "Repository: $REPO_ROOT"
echo ""

# Parse arguments
TEST_TYPE="${1:-unit}"

case "$TEST_TYPE" in
  unit)
    echo "Running unit tests (no K8s required)..."
    docker run --rm \
      -v "$REPO_ROOT":/workspace \
      -w /workspace \
      "$IMAGE" \
      go test -v \
        ./internal/operator/identifier/... \
        ./internal/operator/cniconfig/... \
        ./pkg/common/util/...
    ;;

  operator)
    echo "Running operator tests with envtest..."
    docker run --rm \
      -v "$REPO_ROOT":/workspace \
      -w /workspace \
      "$IMAGE" \
      sh -c '
        # Install setup-envtest
        go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

        # Setup envtest binaries
        KUBEBUILDER_ASSETS=$(setup-envtest use 1.31.0 --bin-dir /workspace/bin/k8s -p path)
        export KUBEBUILDER_ASSETS

        # Run tests
        go test -v ./internal/operator/...
      '
    ;;

  router)
    echo "Running router BDD tests..."
    docker run --rm \
      -v "$REPO_ROOT":/workspace \
      -w /workspace/router \
      python:3.13 \
      sh -c '
        pip install -e .[test] -q
        behave
      '
    ;;

  build)
    echo "Building galactic binary..."
    docker run --rm \
      -v "$REPO_ROOT":/workspace \
      -w /workspace \
      "$IMAGE" \
      go build -o bin/galactic ./cmd/galactic/...
    echo "Binary built: bin/galactic"
    file "$REPO_ROOT/bin/galactic"
    ;;

  all)
    echo "Running all tests..."
    "$0" unit
    "$0" router
    "$0" operator
    ;;

  *)
    echo "Usage: $0 {unit|operator|router|build|all}"
    echo ""
    echo "  unit     - Run unit tests (fast, no K8s)"
    echo "  operator - Run operator tests with envtest"
    echo "  router   - Run Python router BDD tests"
    echo "  build    - Build the galactic binary"
    echo "  all      - Run all tests"
    exit 1
    ;;
esac

echo ""
echo "=== Done ==="
