# Fabric router image: the upstream FRR image used for the eBGP fabric/transit
# roles in deploy/containerlab, layered with common network debugging tools
# so issues can be triaged from inside the container without a separate
# toolbox image, plus fabric-config-agent, which installs and live-reloads
# each node's own frr.conf from its fabric-router.<nodename> ConfigMap.
ARG FRR_VERSION=10.7.1

# "network" is an empty stage by default -- see
# containers/galactic-router/Dockerfile's own comment on this stage.
FROM scratch AS network

# Build fabric-config-agent. It imports no eBPF packages, so unlike the other
# Go images this needs no clang or go generate step.
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
COPY --from=network / /network
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o fabric-config-agent ./cmd/fabric-config-agent

FROM quay.io/frrouting/frr:${FRR_VERSION}

RUN apk add --no-cache \
      tcpdump \
      mtr \
      busybox-extras \
      bind-tools \
      curl

# Static FRR config common to every fabric/transit role. Copied to a
# non-standard path (rather than /etc/frr directly) because /etc/frr is an
# emptyDir in the fabric DaemonSet, populated at pod start by
# fabric-config-agent's init container: it seeds /etc/frr from here, then
# layers the node's own frr.conf (and any daemons/vtysh.conf override) from
# its ConfigMap on top.
COPY containers/fabric-router/daemons containers/fabric-router/vtysh.conf /etc/frr-defaults/

COPY --from=builder /workspace/fabric-config-agent /usr/bin/fabric-config-agent
