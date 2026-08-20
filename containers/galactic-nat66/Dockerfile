# Build the galactic-nat66 binary
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
COPY internal/ internal/

# galactic-nat66 transitively imports both
# internal/plumbing/ebpf/nat66prog (the sharded NAT66 egress XDP program it
# loads directly) and, via internal/plumbing/ebpf/nat66attach ->
# internal/plumbing/ebpf/nat66map -> ... no further transitive eBPF
# program dependency of its own -- but galactic-router's shared
# internal/plumbing/ebpf/prog (the SRv6 uSID TC-BPF program) is still
# generated here too, matching containers/galactic-gateway/Dockerfile's
# own two-package-generate pattern, since a NAT66 shard node also needs the
# uSID decap datapath transitively available to the rest of this module's
# build graph. Neither package's bpf2go output (*_bpfel.go/.o,
# *_bpfeb.go/.o) is committed to git (see each package's doc.go), so both
# must be regenerated here.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN go generate ./internal/plumbing/ebpf/prog/...
RUN go generate ./internal/plumbing/ebpf/nat66prog/...

# Build galactic-nat66
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-nat66 ./cmd/galactic-nat66

# Use distroless as minimal base image to package the binary. galactic-nat66
# drives its eBPF/XDP and NAT66Shard CRD state through the cilium/ebpf and
# controller-runtime Go libraries directly, never shells out to `ip` or any
# other host CLI tool, so no shell is required in the final image.
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/galactic-nat66 .
USER 65532:65532

ENTRYPOINT ["/galactic-nat66"]
