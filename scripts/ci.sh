#!/usr/bin/env bash
set -euo pipefail

setup_venv() {
  if [ ! -d ".venv" ]; then
    python3 -m venv .venv
  fi
  .venv/bin/pip install --quiet yamllint
}

COMMAND="${1:-}"

case "$COMMAND" in
  setup)
    setup_venv
    ;;

  unittest)
    echo "--- Setting up Python venv"
    setup_venv

    if [ -z "${SKIP_YAMLLINT:-}" ]; then
      echo "--- Checking for .yml files (only .yaml is allowed)"
      if find . -name "*.yml" -not -path "./.git/*" | grep -q .; then
        find . -name "*.yml" -not -path "./.git/*"
        echo "ERROR: .yml files found; rename to .yaml"
        exit 1
      fi

      echo "--- Running yamllint"
      .venv/bin/yamllint .
    fi

    echo "--- Running Go unit tests"
    go test -v -race -coverprofile=coverage.out ./pkg/common/util/...
    ;;

  e2etest)
    CLUSTER_NAME="${CLUSTER_NAME:-galactic-e2e}"
    IMG="${IMG:-galactic:e2e}"

    trap 'kind delete cluster --name "$CLUSTER_NAME"' EXIT

    echo "--- Installing kind"
    go install sigs.k8s.io/kind@latest

    echo "--- Creating Kind cluster: $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 5m
    kubectl cluster-info

    echo "--- Building image: $IMG"
    docker build -t "$IMG" -f containers/galactic/Dockerfile .

    echo "--- Loading image into cluster"
    kind load docker-image "$IMG" --name "$CLUSTER_NAME"
    ;;

  *)
    echo "Usage: $0 {setup|unittest|e2etest}"
    exit 1
    ;;
esac
