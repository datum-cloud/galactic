# Build galactic-vrf, #855's ingress sidecar. Unlike containers/galactic-cni's
# Dockerfile (one image bundling every CNI-chain binary), this image ships a
# single binary: galactic-vrf runs as its own container, the second one in
# the shared Envoy Gateway fleet's pod (docs/plans/855-ingress-sidecar-vpc-
# backend-connectivity.md §5/§6), not part of the CNI chain at all.
#
# Published by .github/workflows/publish.yaml, same reusable
# datum-cloud/actions publish-docker workflow, tag scheme and
# linux/amd64,linux/arm64 matrix as every other image here. The
# config/galactic-vrf kustomize Component adds it to an Envoy Deployment
# (see its README.md). The galactic-kustomize bundle carries that directory,
# but publish.yaml does not stamp this image's tag into it, so the Component
# keeps its `latest` tag until the consumer sets one with `images:`.
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
COPY api/ api/
COPY internal/ internal/
COPY pkg/ pkg/

# galactic-vrf reaches internal/plumbing/ebpf/prog transitively (via
# internal/config -> usidmap/egressroutemap), and that package's bpf2go
# output (usid_bpfel/eb.go plus their go:embed'd .o's) is not committed to
# git -- see its doc.go. Regenerate it here, exactly as
# containers/galactic-cni/Dockerfile does. Only the usid datapath is on
# this binary's import graph; edgeprog/natprog are not.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*
RUN go generate ./internal/plumbing/ebpf/prog/...

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-vrf ./cmd/galactic-vrf

# Minimal static-Go-binary image. Unlike galactic-cni's own final image
# (alpine, for iproute2/nsenter needed by e2e tests), this container never
# shells out to `ip`: every kernel operation goes through
# internal/plumbing/vrf and internal/plumbing/srv6's own netlink calls, so
# scratch is sufficient.
FROM scratch

COPY --from=builder /workspace/galactic-vrf /galactic-vrf

# Never privileged -- per PR #851's explicit privilege split (this sidecar
# creates VRF devices/routes; Envoy only binds to them). The
# config/galactic-vrf Component grants NET_ADMIN, BPF and SYS_ADMIN, mounts
# /sys/fs/bpf and /run/galactic-worker, and runs the container as root: root
# is needed to write the hostPath bpffs and to connect to Worker's root-owned
# socket. The
# USER below is the image's default for runs outside that Component.
USER 65532:65532

ENTRYPOINT ["/galactic-vrf"]
