LAB := $(shell awk '/^name:/ {print $$2; exit}' *.clab.yaml)
TOPO := $(wildcard *.clab.yaml)

.PHONY: help build up down reload inspect graph host-setup clean

.DEFAULT_GOAL := help

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}' \
		| sort

build: ## Build the custom GoBGP + FRR image
	docker build -t gobgp-pe:latest containers/gobgp-pe

up: build host-setup ## Build the image and deploy the lab
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

clean: down ## Destroy the lab, remove ContainerLab state, and delete the gobgp-pe image
	docker rmi gobgp-pe:latest || true
	rm -rf clab-$(LAB)
