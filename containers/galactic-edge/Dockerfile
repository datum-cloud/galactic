# Build the galactic-edge binary
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
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

# galactic-edge registers attachment host links in the uSID datapath's
# pinned maps (internal/plumbing/ebpf/attachreg), which links against the
# prog package's bpf2go bindings. They are not committed, so they are
# generated here; galactic-edge never loads the program itself.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang-19 llvm-19 linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/prog/...

# Build galactic-edge
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-edge ./cmd/galactic-edge

# Use scratch as minimal base image to package the binary. galactic-edge
# drives netlink, the pinned eBPF maps and the CRI socket through Go
# libraries and runs no host tool, so no shell is required in the final image.
FROM scratch
WORKDIR /
COPY --from=builder /workspace/galactic-edge .
USER 65532:65532

ENTRYPOINT ["/galactic-edge"]
