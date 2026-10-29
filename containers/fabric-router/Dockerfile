# Fabric router image: the upstream FRR image used for the eBGP fabric/transit
# roles in deploy/containerlab, with zebra rebuilt from the same release plus
# patches/, layered with common network debugging tools so issues can be
# triaged from inside the container without a separate toolbox image, plus
# fabric-config-agent, which installs and live-reloads each node's own
# frr.conf from its fabric-router.<nodename> ConfigMap.
ARG FRR_VERSION=10.7.1
# The commit FRR_VERSION's release tag points at. zebra is rebuilt from it, so
# the two change together, and the build refuses a commit of another release.
ARG FRR_COMMIT=f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1

# Rebuild zebra from the release's own source with patches/ applied, on the
# release image itself so it links against the libfrr shipped beside it,
# configured with the flags that image was built with (`zebra --version`).
# Only the zebra binary is taken from this stage.
#
# zebra-nhg-removed-nexthop.patch: unpatched, zebra keeps an ECMP next hop
# BGP has withdrawn while its link was down and installs it again when the
# link returns, before the session to that peer is even up
# (FRRouting/frr#22752), so a node forwards to a neighbor that has no routes
# yet. Drop the stage once a release carries a fix.
FROM quay.io/frrouting/frr:${FRR_VERSION} AS zebra
ARG FRR_VERSION
ARG FRR_COMMIT
RUN apk add --no-cache build-base autoconf automake libtool bison flex git perl linux-headers \
      python3-dev readline-dev json-c-dev c-ares-dev pcre2-dev rtrlib-dev lua5.3-dev libcap-dev elfutils-dev
WORKDIR /src
RUN git init -q && git fetch -q --depth 1 https://github.com/FRRouting/frr.git "${FRR_COMMIT}" && \
    git checkout -q FETCH_HEAD
RUN grep -q "^AC_INIT(\[frr\], \[${FRR_VERSION}\]" configure.ac || \
    { echo "FRR_COMMIT ${FRR_COMMIT} is not FRR ${FRR_VERSION}; set it to the frr-${FRR_VERSION} tag's commit" >&2; exit 1; }
COPY containers/fabric-router/patches/ /patches/
RUN for p in /patches/*.patch; do patch -p1 --forward < "$p" || exit 1; done
RUN ./bootstrap.sh && ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
      --sbindir=/usr/lib/frr --libdir=/usr/lib --enable-rpki --enable-vtysh --enable-multipath=64 \
      --enable-vty-group=frrvty --enable-user=frr --enable-group=frr --enable-pcre2posix \
      --enable-scripting CC=cc CXX=c++ && \
    make -j"$(nproc)" zebra/zebra


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
RUN go mod download

COPY cmd/ cmd/
COPY api/ api/
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

RUN apk add --no-cache --upgrade 'ca-certificates>=20261020-r0'
RUN ! grep -q MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG /etc/ssl/certs/ca-certificates.crt

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

COPY --from=zebra /src/zebra/.libs/zebra /usr/lib/frr/zebra

COPY --from=builder /workspace/fabric-config-agent /usr/bin/fabric-config-agent
