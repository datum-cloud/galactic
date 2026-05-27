#!/usr/bin/env bash
# Local testing script for Galactic
# Runs tests in Docker to ensure Linux compatibility

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="golang:1.24"

echo "=== Galactic Local Test Runner ==="
echo "Repository: $REPO_ROOT"
echo ""

TEST_TYPE="${1:-unit}"

case "$TEST_TYPE" in
  unit)
    echo "Running unit tests..."
    docker run --rm \
      -v "$REPO_ROOT":/workspace \
      -w /workspace \
      "$IMAGE" \
      go test -v -race ./pkg/common/util/...
    ;;

  build)
    echo "Building galactic binary..."
    docker run --rm \
      -v "$REPO_ROOT":/workspace \
      -w /workspace \
      "$IMAGE" \
      go build -o bin/galactic ./cmd/galactic/main.go
    echo "Binary built: bin/galactic"
    file "$REPO_ROOT/bin/galactic"
    ;;

  *)
    echo "Usage: $0 {unit|build}"
    echo ""
    echo "  unit   - Run unit tests with race detector"
    echo "  build  - Build the galactic binary in Docker"
    exit 1
    ;;
esac

echo ""
echo "=== Done ==="
