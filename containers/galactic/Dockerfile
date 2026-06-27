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

# Build the host-device CNI plugin binary, used by galactic-cni to move
# the veth endpoint into the container network namespace.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} GOBIN=/workspace \
    go install github.com/containernetworking/plugins/plugins/main/host-device@v1.9.1

# Create the IPAM state directory in the builder (where /bin/sh exists)
# so it can be copied into the final distroless image.
RUN mkdir -p /var/run/galactic-cni && chmod 777 /var/run/galactic-cni

# Use distroless as minimal base image to package the binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot AS production

# Copy binaries from builder into the distroless production image
COPY --from=builder /workspace/galactic-cni /galactic-cni
COPY --from=builder /workspace/host-device /host-device
COPY --from=builder /var/run/galactic-cni /var/run/galactic-cni

# Final image: busybox (provides sh, nsenter, ip for e2e tests)
FROM docker.io/library/busybox:stable

# Copy binaries from the production (distroless) image
COPY --from=production /galactic-cni /galactic-cni
COPY --from=production /host-device /host-device
COPY --from=production /var/run/galactic-cni /var/run/galactic-cni

# busybox dispatches commands based on symlink name; create symlinks so
# standard tools (sh, nsenter, ip) are found on PATH.
# Also create /var/run/netns with world-writable perms so the CNI plugin
# (which creates network namespaces at runtime) can write there regardless
# of the user the container runs as.
RUN mkdir -p /usr/local/bin /var/run/netns && \
    chmod 1777 /var/run/netns && \
    ln -sf /bin/busybox /usr/local/bin/nsenter && \
    ln -sf /bin/busybox /usr/local/bin/sh && \
    ln -sf /bin/busybox /usr/local/bin/ip

# Run as root so nsenter (setns) and netlink operations work in e2e tests.
# In production the CNI is invoked by the Kubelet as root anyway.
USER 0:0
ENTRYPOINT ["/galactic-cni"]
