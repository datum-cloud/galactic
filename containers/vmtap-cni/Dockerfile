# Build the vmtap CNI plugin. Exists solely for `task test:e2e`, same as
# containers/galactic-cni/Dockerfile — there is no production release image
# build in this repo.
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
    -o vmtap-cni cmd/vmtap-cni/main.go

# Use distroless as minimal base image to package the binary
FROM gcr.io/distroless/static:nonroot AS production
COPY --from=builder /workspace/vmtap-cni /vmtap-cni

# Final image: alpine (provides iproute2/tc, sh, cp) — the patch-conflist
# container needs a shell-less `cp` for its init step, and the plugin's own
# tc-redirect setup exercises iproute2/tc at runtime under e2e.
FROM docker.io/library/alpine:latest
COPY --from=production /vmtap-cni /vmtap-cni
RUN apk add --no-cache iproute2

USER 0:0
ENTRYPOINT ["/vmtap-cni"]
