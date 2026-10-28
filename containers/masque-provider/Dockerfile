# Build the masque-provider binary
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

# masque-provider imports no eBPF package, so it needs no clang and no go generate
# step.
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
    -o masque-provider ./cmd/masque-provider

# The provider runs unprivileged: it opens the packet device galactic-edge
# created in its pod as the device's owner, 65532:65532, and talks only to
# the API server and the grant authority. No shell or host tool.
FROM scratch
WORKDIR /
COPY --from=builder /workspace/masque-provider .
USER 65532:65532
# net/http offers HTTP/2 Extended CONNECT, which the TCP fallback needs, only
# when GODEBUG holds this at process start. The provider refuses to start
# with --listen-tcp set and this missing.
ENV GODEBUG=http2xconnect=1

ENTRYPOINT ["/masque-provider"]
