#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-}"

case "$COMMAND" in
  unittest)
    go test -v -race -coverprofile=coverage.out ./pkg/common/util/...
    ;;

  e2etest)
    CLUSTER_NAME="${CLUSTER_NAME:-galactic-e2e}"
    IMG="${IMG:-galactic:e2e}"

    trap 'kind delete cluster --name "$CLUSTER_NAME"' EXIT

    go install sigs.k8s.io/kind@latest
    kind create cluster --name "$CLUSTER_NAME" --wait 5m
    kubectl cluster-info
    docker build -t "$IMG" -f containers/galactic/Dockerfile .
    kind load docker-image "$IMG" --name "$CLUSTER_NAME"
    ;;

  *)
    echo "Usage: $0 {unittest|e2etest}"
    exit 1
    ;;
esac
