FROM kindest/node:v1.34.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 install.sh /galactic/
COPY mqtt.k8s.yml router.k8s.yml agent.k8s.yml operator.k8s.yaml /galactic/
