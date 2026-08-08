# Build the galactic CNI plugin
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

# Install the eBPF build toolchain and regenerate
# internal/plumbing/ebpf/prog's bpf2go output (usid_bpfel.go/.o,
# usid_bpfeb.go/.o -- go:embed'd into the galactic-cni binary below) from
# usid.c. These aren't committed to git (see that package's doc.go), so
# every build site produces them fresh instead of embedding a copy
# checked into the repo; this builder stage is no exception. Package
# names are the generic Debian ones (this base image, unlike the CI
# runner's Ubuntu, doesn't have a clang-18 package available) -- byte-
# identical output across build sites isn't the goal here, a working BPF
# program compiled from usid.c is.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN go generate ./internal/plumbing/ebpf/prog/...

# Build CNI plugin
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-cni cmd/galactic-cni/main.go

# Build galactic-tap-cni, the tap master plugin in the galactic CNI chain
# (VM workloads: Kata, Firecracker, kraftlet/Unikraft). Ships in this same
# image/binary set since every plugin in the chain is staged onto the host
# by the same galactic-cni init container (installer.Bootstrap).
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-tap-cni cmd/galactic-tap-cni/main.go

# Build vmtap-cni. It ships in this image rather than one of its own so the
# vmtap DaemonSet (config/vmtap/) can reference the same published
# ghcr.io/datum-cloud/galactic-cni image instead of a second, separately
# published image.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o vmtap-cni cmd/vmtap-cni/main.go

# Build the host-device CNI plugin binary, used by galactic-cni to move
# the veth endpoint into the container network namespace. GOBIN can't be set
# for a cross-compiled `go install` (the toolchain rejects it outright when
# TARGETARCH differs from the builder's native arch, e.g. arm64 on an amd64
# runner), so let it install to its default (arch-suffixed when
# cross-compiling) location under GOPATH/bin and copy it out from there.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
      go install github.com/containernetworking/plugins/plugins/main/host-device@v1.9.1 \
    && find "$(go env GOPATH)/bin" -name host-device -exec cp {} /workspace/host-device \;

# Create the IPAM state directory in the builder (where /bin/sh exists)
# so it can be copied into the final distroless image.
RUN mkdir -p /var/run/galactic-cni && chmod 777 /var/run/galactic-cni

# Use distroless as minimal base image to package the binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot AS production

# Copy binaries from builder into the distroless production image
COPY --from=builder /workspace/galactic-cni /galactic-cni
COPY --from=builder /workspace/galactic-tap-cni /galactic-tap-cni
COPY --from=builder /workspace/vmtap-cni /vmtap-cni
COPY --from=builder /workspace/host-device /host-device
COPY --from=builder /var/run/galactic-cni /var/run/galactic-cni

# Final image: alpine (provides full iproute2, sh, nsenter for e2e tests)
# Alpine is used instead of busybox because BusyBox's ip utility lacks
# support for netns, "ip link add type vrf", and other subcommands the
# CNI plugin exercises at runtime.
FROM docker.io/library/alpine:latest

# Copy binaries from the production (distroless) image
COPY --from=production /galactic-cni /galactic-cni
COPY --from=production /galactic-tap-cni /galactic-tap-cni
COPY --from=production /vmtap-cni /vmtap-cni
COPY --from=production /host-device /host-device
COPY --from=production /var/run/galactic-cni /var/run/galactic-cni

# Install iproute2 (provides full-featured ip, nsenter) and create the
# netns directory with world-writable perms so the CNI plugin can create
# network namespaces regardless of the container user.
RUN apk add --no-cache iproute2 && \
    mkdir -p /usr/local/bin /var/run/netns && \
    chmod 1777 /var/run/netns && \
    ln -sf /usr/sbin/ip /usr/local/bin/ip && \
    ln -sf /usr/sbin/nsenter /usr/local/bin/nsenter

# Run as root so nsenter (setns) and netlink operations work in e2e tests.
# In production the CNI is invoked by the Kubelet as root anyway.
USER 0:0
ENTRYPOINT ["/galactic-cni"]
