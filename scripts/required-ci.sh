#!/usr/bin/env bash
set -euo pipefail

sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 update -qq
sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 install -y --no-install-recommends clang-18 llvm-18 linux-libc-dev
export BPF2GO_CC=clang-18

for pkg in prog edgeprog natprog xdpdispatch; do
  go generate "./internal/plumbing/ebpf/$pkg/..."
done

go build ./...

assets=$(go run sigs.k8s.io/controller-runtime/tools/setup-envtest@32759fab31191897ae86091d8831b2d4b890aedd use 1.37.x --bin-dir "${RUNNER_TEMP:-/tmp}/envtest" -p path)
test -x "$assets/kube-apiserver"
export KUBEBUILDER_ASSETS=$assets

go test -timeout 20m ./api/... ./cmd/... ./internal/... ./tests/edgeconformance/edgeprobe/...
