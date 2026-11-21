# Build the galactic-worker binary
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG GIT_TREE_STATE=unknown
ARG BUILD_DATE=unknown
ARG SPDX_LICENSE=AGPL-3.0-or-later
ARG GIT_URL=https://github.com/datum-cloud/galactic

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/
COPY pkg/ pkg/

# Worker's Fabric module opens the uSID maps (prog), its Local module loads
# the handoff programs (localprog) and reads the shared XDP dispatcher
# (xdpdispatch). Their bpf2go output is not committed (see each package's
# doc.go), so it is generated here.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang-19 llvm-19 linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/prog/...
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/localprog/...
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/xdpdispatch/...

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-worker ./cmd/galactic-worker

# Worker programs the host through netlink and eBPF libraries and never runs
# a host tool, so the image needs no shell. The inspect and handback
# subcommands are the same binary. Its manifests run it as root with two
# capabilities, overriding the image's unprivileged user.
FROM scratch
WORKDIR /
COPY --from=builder /workspace/galactic-worker .
USER 65532:65532

ENTRYPOINT ["/galactic-worker"]
