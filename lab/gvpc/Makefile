LAB_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LAB := $(shell awk '/^name:/ {print $$2; exit}' *.clab.yaml)
TOPO := $(wildcard *.clab.yaml)

.PHONY: help build up down reload inspect graph host-setup underlay overlay clean

.DEFAULT_GOAL := help

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}' \
		| sort

build: ## Build container images (Kind node)
	docker build --network=host -t kindest/node:galactic $(LAB_DIR)containers/kindest-node-galactic

up: build host-setup ## Build the Kind node image and deploy the lab
	sudo containerlab deploy -t $(TOPO)

down: ## Destroy the lab and clean generated state
	sudo containerlab destroy -t $(TOPO) --cleanup

reload: down up ## Full rebuild and redeploy

inspect: ## Inspect deployed nodes and management addresses
	sudo containerlab inspect -t $(TOPO)

graph: ## Generate a draw.io diagram for the current topology
	sudo containerlab graph -t $(TOPO) --drawio --drawio-dir .

host-setup: ## Apply host sysctls for this dual-stack lab
	sudo ./scripts/host-setup.sh --no-persist

underlay: ## Apply FRR DaemonSets to all clusters
	./scripts/install-underlay.sh

overlay: ## Pull GoBGP image, load into clusters, and apply DaemonSets to iad and sjc
	docker pull osrg/gobgp:latest
	kind load docker-image osrg/gobgp:latest --name iad
	kind load docker-image osrg/gobgp:latest --name sjc
	./scripts/install-overlay.sh

clean: down ## Destroy the lab, remove ContainerLab state, and delete container images
	docker rmi kindest/node:galactic || true
	docker rmi osrg/gobgp:latest || true
	rm -rf clab-$(LAB)
