# fabric-api image: one static binary for the node sidecar (in each
# fabric-router pod), the cell gateway, the janitor and the operator query
# client. It is separate from the fabric-router image so FRR and fabric-api
# build and version independently; the sidecar checks FRR's version at
# runtime instead (see internal/fabric/frr/version.go).

# "network" is an empty stage by default -- see
# containers/galactic-router/Dockerfile's own comment on this stage.
FROM scratch AS network

# fabric-api imports no eBPF packages, so unlike the other Go images this
# needs no clang or go generate step.
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

COPY api/ api/
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
    -o fabric-api ./cmd/fabric-api

# No shell, no FRR, no vtysh: the sidecar talks to FRR's vty sockets
# directly and sends probes on raw sockets. The fabric-router Component sets
# the sidecar's user (UID 0, so an added NET_RAW is effective, with group
# frrvty 102 for the sockets) and drops every other capability; the gateway,
# janitor and query client run as this image's nonroot user.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/fabric-api /usr/bin/fabric-api
USER 65532:65532

ENTRYPOINT ["/usr/bin/fabric-api"]
