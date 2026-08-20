# "network" is an empty stage by default -- overridden with a real
# go.datum.net/network checkout via `docker build --build-context
# network=<path-to-network-repo> ...` whenever go.mod carries a local
# `replace go.datum.net/network => ../network` directive (this repo's own
# convention for developing against unpublished network CRD changes before
# they're tagged -- see go.mod's own comment on that line). Copied to
# /network below, exactly matching what that relative replace path resolves
# to from /workspace/go.mod inside this build. Harmless when no such
# replace directive exists and no override is passed: go.mod then has
# nothing under /network to resolve, so an empty directory there is never
# read.
FROM scratch AS network

# Build the galactic router binary
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
# Local cross-repo development: satisfies go.mod's `replace
# go.datum.net/network => ../network`, when present -- see the "network"
# stage's own comment above for where this comes from.
COPY --from=network / /network
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/ cmd/
COPY internal/ internal/

# galactic-router transitively imports both internal/plumbing/ebpf/prog
# (via usidmap) and, via the NetworkGateway/NetworkRule reconcilers'
# internal/gateway.Engine, internal/plumbing/ebpf/edgemap's
# internal/plumbing/ebpf/edgeprog -- neither package's bpf2go output
# (*_bpfel.go/.o, *_bpfeb.go/.o) is committed to git (see each package's
# doc.go), so both must be regenerated here, same as
# containers/galactic-gateway/Dockerfile does.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN go generate ./internal/plumbing/ebpf/prog/...
RUN go generate ./internal/plumbing/ebpf/edgeprog/...

# Build the router
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-router ./cmd/galactic-router

# Use distroless as minimal base image to package the binary. galactic-router
# drives all VRF/SRv6/route/BGP state through the netlink and GoBGP Go
# libraries directly, never shells out to `ip` or any other host CLI tool, so
# no shell is required in the final image.
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/galactic-router .
USER 65532:65532

ENTRYPOINT ["/galactic-router"]
