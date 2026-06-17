ARG KINDEST_VER=v1.36.1

FROM golang:1.26 AS builder
WORKDIR /src
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o bin/galactic-cni cmd/galactic-cni/main.go

FROM kindest/node:${KINDEST_VER}

SHELL ["/bin/bash", "-eo", "pipefail", "-c"]

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /galactic

COPY --from=builder /src/bin/galactic-cni ./bin/galactic-cni
COPY deploy/containerlab/resources/ ./resources/
COPY --chmod=0755 deploy/containerlab/containers/kindest-node-galactic/scripts/ ./scripts/

# Wrap kubectl to work around OrbStack DooD: kind runs `kubectl apply` for the
# StorageClass step immediately after kubeadm init, but the apiserver briefly
# goes offline while OrbStack's bridge finishes coming up, causing worker nodes
# to never reach kubeadm join. The wrapper polls /healthz before passing through.
COPY --chmod=0755 deploy/containerlab/containers/kindest-node-galactic/kubectl-wrapper /usr/local/bin/kubectl
