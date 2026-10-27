# Build the conformance suite's MASQUE fixture provider. It is a test
# fixture, not a product image: the lab loads it into its edge nodes.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY internal/ internal/
COPY tests/edgeconformance/masqueprovider/ tests/edgeconformance/masqueprovider/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -ldflags "-s -w" \
    -o /masqueprovider ./tests/edgeconformance/masqueprovider

# The fixture needs no shell or host tool. It runs unprivileged and opens
# its packet devices as the owner the attachment names, 65532:65532.
FROM scratch
COPY --from=builder /masqueprovider /masqueprovider
USER 65532:65532
ENTRYPOINT ["/masqueprovider"]
