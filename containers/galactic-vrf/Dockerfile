# Build galactic-vrf, #855's ingress sidecar. Unlike containers/galactic-cni's
# Dockerfile (one image bundling every CNI-chain binary), this image ships a
# single binary: galactic-vrf runs as its own container, the second one in
# the shared Envoy Gateway fleet's pod (docs/plans/855-ingress-sidecar-vpc-
# backend-connectivity.md §5/§6), not part of the CNI chain at all.
#
# This repo has no wired-up CI publish pipeline for this image yet -- see
# root CLAUDE.md's CI/CD section and §9 item 3 of the plan (the #856
# deployment contract is still an open, flagged dependency) -- this
# Dockerfile exists so the binary is buildable/deployable today, ahead of
# that decision.
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
    -o galactic-vrf cmd/galactic-vrf/main.go

# Minimal static-Go-binary image, matching containers/galactic-cni/
# Dockerfile's production-stage pattern -- §6 of the plan. Unlike
# galactic-cni's own final image (alpine, for iproute2/nsenter needed by
# e2e tests), this container never shells out to `ip`: every kernel
# operation goes through internal/plumbing/vrf and internal/plumbing/srv6's
# own netlink calls, so distroless is sufficient.
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /workspace/galactic-vrf /galactic-vrf

# CAP_NET_ADMIN only, never privileged -- per PR #851's explicit privilege
# split (this sidecar creates VRF devices/routes; Envoy only binds to them).
# The capability itself is granted by the pod's securityContext, not here;
# USER is left at distroless:nonroot's default (65532:65532) since
# CAP_NET_ADMIN does not require running as root.
ENTRYPOINT ["/galactic-vrf"]
