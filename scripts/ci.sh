#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-}"

case "$COMMAND" in
  unittest)
    echo "--- Running Go unit tests"
    go test -v -race -coverprofile=coverage.out ./cmd/... ./internal/...
    ;;

  e2etest)
    CLUSTER_NAME="${CLUSTER_NAME:-galactic-e2e}"
    IMG="${IMG:-galactic-cni:e2e}"

    trap 'kind delete cluster --name "$CLUSTER_NAME"' EXIT

    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      echo "--- Loading kernel modules required by galactic"
      sudo apt-get update -qq
      sudo apt-get install -y --no-install-recommends linux-modules-extra-azure
    fi
    sudo modprobe vrf

    echo "--- Installing kind"
    go install sigs.k8s.io/kind@latest

    echo "--- Creating Kind cluster: $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 5m
    kubectl cluster-info

    echo "--- Building image: $IMG"
    docker build -t "$IMG" -f containers/galactic-cni/Dockerfile .

    echo "--- Loading image into cluster"
    kind load docker-image "$IMG" --name "$CLUSTER_NAME"

    echo "--- Running e2e tests"
    IMG="$IMG" go test -v -timeout 10m ./tests/e2e/...
    ;;

  *)
    echo "Usage: $0 {unittest|e2etest}"
    exit 1
    ;;
esac
