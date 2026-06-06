ARG FRR_VERSION=10.6.1
FROM alpine:edge
ARG FRR_VERSION

# alpine:edge is a rolling release — base OS packages update on every rebuild.
# FRR is pinned via "frr=${FRR_VERSION}-r0". If Alpine bumps the package to -r1
# for the same FRR version, the build will fail; drop or adjust the -r0 suffix.
RUN apk add --no-cache \
    "frr=${FRR_VERSION}-r0" \
    frr-pythontools \
    iproute2 \
    tcpdump
