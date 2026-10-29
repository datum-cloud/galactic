#!/usr/bin/env bash
set -euo pipefail

COMMAND="${1:-}"

case "$COMMAND" in
  unittest)
    echo "--- Running Go unit tests"
    go test -v -race -coverprofile=coverage.out ./api/... ./cmd/... ./internal/... ./tests/edgeconformance/edgeprobe/...
    ;;

  unittest-root)
    # Scoped to just the packages with requireRoot(t)-gated tests, found by
    # grep rather than a hardcoded list -- unlike `unittest` above (run
    # unprivileged, where those cases just skip), this re-runs them as root
    # so they actually load/attach real kernel state (BPF programs, netns,
    # VRFs) instead of skipping. Discovering the list dynamically means new
    # root-gated packages (e.g. the planned internal/plumbing/ebpf/attach,
    # internal/plumbing/ebpf/usidmap milestones) get picked up automatically
    # instead of silently running unprivileged until someone remembers to
    # add them here. Scoping (instead of re-running the whole suite, as
    # test-unit-root used to) avoids the duplicated runtime and any risk of
    # a permission-denied assertion elsewhere in the suite behaving
    # differently once actually run as root.
    echo "--- Discovering root-gated packages"
    mapfile -t pkgs < <(
      grep -rl 'requireRoot(t)' --include='*_test.go' ./cmd ./internal 2>/dev/null \
        | xargs -n1 dirname | sort -u | sed 's#^\./#./#'
    )
    if [ "${#pkgs[@]}" -eq 0 ]; then
      echo "no requireRoot(t)-gated packages found; nothing to do"
      exit 0
    fi
    printf '%s\n' "${pkgs[@]}"
    echo "--- Running Go unit tests as root"
    go test -v -race "${pkgs[@]}"
    ;;

  e2etest)
    CLUSTER_NAME="${CLUSTER_NAME:-galactic-e2e}"
    IMG="${IMG:-galactic-cni:e2e}"

    trap 'kind delete cluster --name "$CLUSTER_NAME"' EXIT

    if [[ "${GITHUB_ACTIONS:-}" == "true" ]] && ! sudo modprobe vrf; then
      echo "--- Loading kernel modules required by galactic"
      # -o Acquire::Retries/::*::Timeout: bare `apt-get update` has no
      # per-request timeout, so a stalled mirror connection hangs until the
      # job's own timeout-minutes kills it -- see ci.yaml's identical flags
      # on this same install for the incident that motivated them (#425).
      sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 update -qq
      # Pin to the running kernel so modprobe finds the modules. The unversioned
      # meta-package may pull a newer kernel's modules than the one the runner is
      # actually executing, which causes modprobe to fail. This runs only when
      # modprobe cannot find vrf, since some kernels ship it in their base
      # modules and publish no extra-modules package at all.
      sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=10 -o Acquire::https::Timeout=10 install -y --no-install-recommends "linux-modules-extra-$(uname -r)"
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

    echo "--- Mounting bpffs on Kind node(s)"
    # The eBPF uSID datapath pins its maps under /sys/fs/bpf/galactic (see
    # internal/plumbing/ebpf/attach.PinDir). config/galactic-cni/daemonset.yaml's
    # bpf-fs hostPath volume comment spells out why this can't be created
    # from inside a pod's own mount namespace: bpffs must already be
    # mounted at this path by the node itself. A real node's OS/kubelet
    # setup does this at boot; a Kind node container doesn't, so mount it
    # here once per node.
    for node in $(kind get nodes --name "$CLUSTER_NAME"); do
      docker exec "$node" sh -c 'mkdir -p /sys/fs/bpf && (mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf)'
    done

    echo "--- Installing Galactic CRDs"
    kubectl apply -k config/crd

    echo "--- Applying galactic-system namespace and CNI RBAC"
    kubectl apply -k config/galactic-system
    kubectl apply -f config/galactic-cni/serviceaccount.yaml -f config/galactic-cni/rbac.yaml
    kubectl config set-context --current --namespace=galactic-system

    echo "--- Creating BGPRouter fixture for the e2e node"
    # cmdAdd requires a BGPRouter targeting the node it runs on (see
    # internal/cni/bgp.go lookupBGPRouter) to resolve the SRv6 locator/nodeID
    # and publish BGP state -- true for veth mode already, and as of the tap
    # mode ADD path calling allocateIPAM/publishBGPState unconditionally, for
    # tap mode too.
    E2E_NODE=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
    cat <<EOF | kubectl apply -f -
apiVersion: galactic.datumapis.com/v1alpha1
kind: BGPRouter
metadata:
  name: e2e-node-router
  namespace: galactic-system
spec:
  targetRef:
    kind: Node
    name: ${E2E_NODE}
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

    echo "--- Copying the hostattach test binary onto Kind node(s)"
    # TestEdgeAgentCreatesTUN runs it inside the shipped galactic-edge
    # container spec, mounted from the node; the agent's own image has no
    # test entry point.
    CGO_ENABLED=0 go test -c -o bin/e2e/hostattach.test ./internal/edge/hostattach
    for node in $(kind get nodes --name "$CLUSTER_NAME"); do
      docker exec "$node" mkdir -p /opt/galactic-e2e
      docker cp bin/e2e/hostattach.test "$node":/opt/galactic-e2e/hostattach.test
    done

    echo "--- Running e2e tests"
    IMG="$IMG" NODE_NAME="$E2E_NODE" go test -v -timeout 10m ./tests/e2e/...
    ;;

  *)
    echo "Usage: $0 {unittest|unittest-root|e2etest}"
    exit 1
    ;;
esac
