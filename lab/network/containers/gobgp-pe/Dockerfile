FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    procps \
    ca-certificates \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN curl -s https://deb.frrouting.org/frr/keys.gpg \
    | gpg --dearmor > /usr/share/keyrings/frr.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/frr.gpg] https://deb.frrouting.org/frr bookworm frr-stable" \
    > /etc/apt/sources.list.d/frr.list \
    && apt-get update && apt-get install -y --no-install-recommends frr \
    && rm -rf /var/lib/apt/lists/*

ARG GOBGP_VERSION=4.5.0
RUN curl -fsSL \
    "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin gobgp gobgpd
