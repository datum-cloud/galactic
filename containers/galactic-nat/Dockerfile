# Build the galactic-nat binary
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

# galactic-nat's build graph reaches all four of this module's eBPF
# program packages, so all four must be generated here -- none of their
# bpf2go output (*_bpfel.go/.o, *_bpfeb.go/.o) is committed to git (see each
# package's doc.go). natprog, and in dispatch mode xdpdispatch, are loaded
# by this binary; the other two arrive transitively and still have to
# compile:
#   - natprog  -- the sharded NAT66 egress XDP program, loaded directly
#                   via internal/plumbing/ebpf/natattach.
#   - prog       -- the SRv6 uSID TC-BPF program, via
#                   internal/plumbing/ebpf/attach and .../usidmap.
#   - edgeprog   -- the edge DSR load-balancer XDP program, via internal/gateway
#                   and internal/controller -> .../edgemap. galactic-nat
#                   never loads it, but shares those packages with
#                   galactic-gateway, so it links against the bindings.
#   - xdpdispatch -- the node's shared XDP dispatcher, loaded in
#                   GALACTIC_NAT_XDP_ATTACH=dispatch mode.
# Dropping any one of these turns into an "undefined: <Prog><Type>" build
# failure in the go build step below, not a missing-file error.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang-19 llvm-19 linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/prog/...
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/edgeprog/...
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/natprog/...
RUN PATH=/usr/lib/llvm-19/bin:$PATH BPF2GO_CC=clang-19 go generate ./internal/plumbing/ebpf/xdpdispatch/...

# Build galactic-nat
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-nat ./cmd/galactic-nat

# Use distroless as minimal base image to package the binary. galactic-nat
# drives its eBPF/XDP and EgressShard CRD state through the cilium/ebpf and
# controller-runtime Go libraries directly, never shells out to `ip` or any
# other host CLI tool, so no shell is required in the final image.
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/galactic-nat .
USER 65532:65532

ENTRYPOINT ["/galactic-nat"]
