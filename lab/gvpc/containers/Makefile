.PHONY: help build pull-base create host-setup status

.DEFAULT_GOAL := help

KINDEST_VER := v1.35.1
ARCH := $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}' \
		| sort

pull-base: ## Pull the base Kind node image (uses crane; Docker Hub TLS 1.3 panics in OrbStack's msft-golang Docker builds)
	@if ! docker image inspect kindest/node:$(KINDEST_VER) >/dev/null 2>&1; then \
		crane pull --platform linux/$(ARCH) \
			kindest/node:$(KINDEST_VER) /tmp/kindest-node-$(KINDEST_VER).tar; \
		docker load -i /tmp/kindest-node-$(KINDEST_VER).tar; \
		rm /tmp/kindest-node-$(KINDEST_VER).tar; \
	fi

build: pull-base ## Build the Galactic image
	docker build --pull=false -t kindest/node:galactic ./kindest-node-galactic/

create: ## Create the kind cluster
	@if kind get clusters 2>/dev/null | grep -q '^kind$$'; then \
		echo "kind cluster already exists, skipping create"; \
	else \
		kind create cluster --config kind-config.yaml; \
	fi
	kind export kubeconfig

host-setup: ## Setup each node in the cluster
	for node in $$(kind get nodes); do \
		docker exec "$$node" /galactic/scripts/install.sh; \
	done

status: ## Show cluster nodes, pods, deployments, and services
	@echo "\n=== Nodes ==="; \
	kubectl get nodes -o wide; \
	echo "\n=== Pods ==="; \
	kubectl get pods -A -o wide | egrep '^galactic|^NAMESPACE'; \
	echo "\n=== Deployments ==="; \
	kubectl get deployments -A | egrep '^galactic|^NAMESPACE'; \
	echo "\n=== Services ==="; \
	kubectl get services -A  | egrep '^galactic|^NAMESPACE';

clean: ## Delete kind cluster
	kind delete cluster
