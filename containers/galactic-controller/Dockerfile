# Build the galactic-controller binary
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

# galactic-controller imports no eBPF package, so unlike the node-side
# images it needs no clang and no go generate step.
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
    -o galactic-controller ./cmd/galactic-controller

# The controller only talks to the API server, so no shell or host tools.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/galactic-controller .
USER 65532:65532

ENTRYPOINT ["/galactic-controller"]
