# Build the reference edge provider. The build context is the repository
# root, but only the Galactic API (api/) and the root module's manifests are
# copied in beside the provider: it is built from the published contract
# alone, with none of the core's implementation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.sum ./
COPY api/ api/
COPY examples/edge-provider/go.mod examples/edge-provider/go.sum examples/edge-provider/
WORKDIR /workspace/examples/edge-provider
RUN go mod download
COPY examples/edge-provider/ ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -ldflags "-s -w" -o /edge-provider .

# The provider needs no shell or host tool. It runs unprivileged and opens
# its packet devices as the owner the attachment names, 65532:65532.
FROM scratch
COPY --from=builder /edge-provider /edge-provider
USER 65532:65532
ENTRYPOINT ["/edge-provider"]
