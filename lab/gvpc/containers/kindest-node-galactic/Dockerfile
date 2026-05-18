FROM kindest/node:v1.35.1

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /galactic

COPY --chmod=0755 scripts/ ./scripts/
