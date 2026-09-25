# galactic-debug: an incident-response toolbox for `kubectl debug`, built on
# top of nicolaka/netshoot (already the org's convention -- see
# deploy/containerlab/resources/tenants/base/pod.yaml) rather than
# reimplementing its curated tool set from a stock base. See
# containers/galactic-debug/README.md for how the two `kubectl debug` modes
# below are meant to be used, and the KB note both modes were designed
# against: ~/.vaults/notebook/projects/galactic/kb/xregion-503-envoy-egress-route-incidents.md.

# Build galactic-usid (base62<->hex uSID codec CLI) and the gobgp CLI,
# pinned to the same major version galactic-router embeds (see go.mod's
# github.com/osrg/gobgp/v4 line) so RIB queries against a live GoBGP
# instance speak a protocol version it actually understands.
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG GIT_TREE_STATE=unknown
ARG BUILD_DATE=unknown
ARG SPDX_LICENSE=AGPL-3.0-or-later
ARG GIT_URL=https://github.com/datum-cloud/galactic
# Keep in sync with go.mod's github.com/osrg/gobgp/v4 version -- this CLI
# is not vendored from this module's own go.sum, so it does not drift
# automatically the way galactic-router's embedded server does.
ARG GOBGP_VERSION=v4.9.0

WORKDIR /workspace

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/galactic-usid/ cmd/galactic-usid/
COPY internal/metadata/ internal/metadata/
COPY internal/plumbing/intf/ internal/plumbing/intf/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X go.datum.net/galactic/internal/metadata.Version=${VERSION} \
      -X go.datum.net/galactic/internal/metadata.GitCommit=${GIT_COMMIT} \
      -X go.datum.net/galactic/internal/metadata.GitTreeState=${GIT_TREE_STATE} \
      -X go.datum.net/galactic/internal/metadata.BuildDate=${BUILD_DATE} \
      -X go.datum.net/galactic/internal/metadata.SPDXLicense=${SPDX_LICENSE} \
      -X go.datum.net/galactic/internal/metadata.GitURL=${GIT_URL}" \
    -o galactic-usid cmd/galactic-usid/main.go

# gobgp's CLI lives in its own module outside this project's go.sum, so it
# is cross-compiled independently rather than via `go build ./cmd/...`.
# GOBIN can't be set for a cross-compiled `go install` when TARGETARCH
# differs from the builder's native arch -- same constraint documented in
# containers/galactic-cni/Dockerfile for host-device -- so let it install
# to its default (arch-suffixed when cross-compiling) location and copy it
# out from there.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
      go install "github.com/osrg/gobgp/v4/cmd/gobgp@${GOBGP_VERSION}" \
    && find "$(go env GOPATH)/bin" -name gobgp -exec cp {} /workspace/gobgp \;

FROM nicolaka/netshoot:latest
ARG TARGETARCH
ARG KUBECTL_VERSION=v1.34.0
ARG CRICTL_VERSION=v1.34.0
ARG YQ_VERSION=v4.44.3

# bpftool/bpftrace: eBPF map/prog introspection -- the tool that was
# missing on the night-two incident ("no low-level eBPF map introspection
# tool available on these nodes"), for dumping galactic-cni's usid_egress
# and egress_route_table maps directly.
# frr: ships vtysh, for querying fabric-router's FRR instance directly
# rather than only through the infra repo's looking glass -- night one's
# root cause was an FRR underlay advertisement flag.
RUN apk add --no-cache \
      bpftool \
      bpftrace \
      frr

# kubectl: correlating with the EndpointSlice state that drives
# vpc-vrf-sidecar's route installs (night two's root cause path).
RUN curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
      -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# crictl: CRI-level container/pod inspection alongside kubectl.
RUN curl -fsSL "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${TARGETARCH}.tar.gz" \
    | tar xz -C /usr/local/bin

# yq: YAML counterpart to netshoot's existing jq, for CRDs and kustomize
# output.
RUN curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_${TARGETARCH}" \
      -o /usr/local/bin/yq \
    && chmod +x /usr/local/bin/yq

COPY --from=builder /workspace/galactic-usid /usr/local/bin/galactic-usid
COPY --from=builder /workspace/gobgp /usr/local/bin/gobgp

COPY containers/galactic-debug/README.md /README.md

ENTRYPOINT ["/bin/bash"]
