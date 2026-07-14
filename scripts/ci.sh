#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-}"

case "$COMMAND" in
  unittest)
    echo "--- Running Go unit tests"
    go test -v -race -coverprofile=coverage.out ./cmd/... ./internal/...
    ;;

  e2etest)
    CLUSTER_NAME="${CLUSTER_NAME:-galactic-e2e}"
    IMG="${IMG:-galactic-cni:e2e}"

    trap 'kind delete cluster --name "$CLUSTER_NAME"' EXIT

    if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
      echo "--- Loading kernel modules required by galactic"
      sudo apt-get update -qq
      # Pin to the running kernel so modprobe finds the modules. The unversioned
      # meta-package may pull a newer kernel's modules than the one the runner is
      # actually executing, which causes modprobe to fail.
      sudo apt-get install -y --no-install-recommends "linux-modules-extra-$(uname -r)"
    fi
    sudo modprobe vrf

    echo "--- Installing kind"
    go install sigs.k8s.io/kind@latest

    echo "--- Creating Kind cluster: $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 5m
    kubectl cluster-info

    echo "--- Enabling VRF strict mode on Kind node(s)"
    # net.vrf.strict_mode is per-netns (the Kind node's own netns, not the
    # CI runner host's), so it must be set inside the node container -- same
    # sysctl deploy/containerlab/containers/kindest-node-galactic/scripts/install.sh
    # sets for the containerlab nodes. Without it, adding the SEG6Local
    # END.DT46 ingress route with the VRFTABLE flag fails with EPERM.
    for node in $(kind get nodes --name "$CLUSTER_NAME"); do
      docker exec "$node" sysctl -w net.vrf.strict_mode=1
    done

    echo "--- Installing BGP CRDs (datum-cloud/network)"
    # Extract the datum-cloud/network commit SHA from go.mod (pseudo-version
    # suffix after the last hyphen), same approach as
    # deploy/containerlab/scripts/deploy-system.sh.
    NETWORK_SHA=$(awk '/go\.datum\.net\/network / {print $2}' go.mod | sed 's/.*-//')
    NETWORK_CRD_URL="https://raw.githubusercontent.com/datum-cloud/network/${NETWORK_SHA}/config/crd"
    for crd in \
      network.datumapis.com_bgpadvertisements.yaml \
      network.datumapis.com_bgppeers.yaml \
      network.datumapis.com_bgppolicies.yaml \
      network.datumapis.com_bgprouters.yaml \
      network.datumapis.com_bgpvrfinstances.yaml; do
      curl -sL "${NETWORK_CRD_URL}/${crd}" | kubectl apply -f -
    done

    echo "--- Applying galactic-system namespace and CNI RBAC"
    kubectl apply -k config/system
    kubectl apply -f config/cni/serviceaccount.yaml -f config/cni/rbac.yaml
    kubectl config set-context --current --namespace=galactic-system

    echo "--- Creating BGPRouter fixture for the e2e node"
    # cmdAdd requires a BGPRouter targeting the node it runs on (see
    # internal/cni/bgp.go lookupBGPRouter) to resolve the SRv6 locator/nodeID
    # and publish BGP state -- true for veth mode already, and as of the tap
    # mode ADD path calling allocateIPAM/publishBGPState unconditionally, for
    # tap mode too.
    E2E_NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
    cat <<EOF | kubectl apply -f -
apiVersion: network.datumapis.com/v1alpha1
kind: BGPRouter
metadata:
  name: e2e-node-router
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: ${E2E_NODE}
  roles:
    - tenant
  localASN: 65000
  routerID: "10.0.0.1"
  srv6Locator: "2001:db8:ff01::/48"
  nodeID: 1
  addressFamilies:
    - afi: l2vpn
      safi: evpn
EOF

    echo "--- Building image: $IMG"
    docker build -t "$IMG" -f containers/galactic-cni/Dockerfile .

    echo "--- Loading image into cluster"
    kind load docker-image "$IMG" --name "$CLUSTER_NAME"

    echo "--- Running e2e tests"
    IMG="$IMG" NODE_NAME="$E2E_NODE" go test -v -timeout 10m ./tests/e2e/...
    ;;

  *)
    echo "Usage: $0 {unittest|e2etest}"
    exit 1
    ;;
esac
