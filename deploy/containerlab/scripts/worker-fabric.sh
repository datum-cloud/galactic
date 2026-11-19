#!/bin/bash
# worker-fabric.sh: run this checkout's galactic-worker on the compute nodes
# of the dedicated-placement fixture (docs/baseline.md) and inspect what its
# Fabric module programs. Lab-only: Worker has no manifests yet, so the
# binary runs as a process inside each Kind node with the cluster's admin
# kubeconfig. galactic-router finds it through GALACTIC_ROUTER_WORKER_SOCKET
# and hands it every tenant route.
#
# Worker takes over every VPC scope on the node and never hands one back, so
# after stop the router leaves those VPCs' tenant routes to a Worker that is
# gone. Redeploy the lab (task destroy, task deploy) before reusing it.
#
# Usage:
#   worker-fabric.sh start          build, copy and start Worker on NODES
#   worker-fabric.sh stop           stop Worker on NODES
#   worker-fabric.sh scopes NODE    print the node's VPC fence records
#   worker-fabric.sh table NODE VPC print VPC's VRF table ID on NODE
#   worker-fabric.sh dump NODE VPC  print VPC's egress_route_table entries
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "${SCRIPT_DIR}/../../.." && pwd)
NODES=${NODES:-"dfw-worker sjc-worker"}
DIR=/opt/galactic-worker
LOG=/var/log/galactic-worker.log
PIN_DIR=/sys/fs/bpf/galactic
FENCE_DIR=/var/lib/galactic-edge/ownership

site_of() { echo "${1%%-*}"; }

start() {
  local bin
  bin=$(mktemp -d)
  trap 'rm -rf "${bin}"' RETURN
  (cd "${REPO_DIR}" && CGO_ENABLED=0 go build -o "${bin}/galactic-worker" ./cmd/galactic-worker)
  cat >"${bin}/allowlist.yaml" <<'EOF'
serviceAccounts:
  - serviceAccount: galactic-system/galactic-router
    capabilities: [fabric.routes]
EOF
  for node in ${NODES}; do
    kind get kubeconfig --name "$(site_of "${node}")" --internal >"${bin}/kubeconfig"
    docker exec "${node}" mkdir -p "${DIR}"
    docker cp "${bin}/galactic-worker" "${node}:${DIR}/galactic-worker"
    docker cp "${bin}/allowlist.yaml" "${node}:${DIR}/allowlist.yaml"
    docker cp "${bin}/kubeconfig" "${node}:${DIR}/kubeconfig"
    docker exec -d -e KUBECONFIG="${DIR}/kubeconfig" "${node}" sh -c \
      "exec ${DIR}/galactic-worker --node-name ${node} --allowlist ${DIR}/allowlist.yaml \
        --metrics-port 19104 --grpc-health-port 19105 --log-level debug >>${LOG} 2>&1"
  done
  for node in ${NODES}; do
    for _ in $(seq 60); do
      if docker exec "${node}" test -S /run/galactic-worker/worker.sock; then
        echo "${node}: Worker serving"
        continue 2
      fi
      sleep 2
    done
    echo "${node}: Worker did not start; log follows" >&2
    docker exec "${node}" tail -50 "${LOG}" >&2 || true
    return 1
  done
}

stop() {
  for node in ${NODES}; do
    docker exec "${node}" sh -c "pkill -TERM -f '^${DIR}/galactic-worker' || true"
    for _ in $(seq 30); do
      docker exec "${node}" pgrep -f "^${DIR}/galactic-worker" >/dev/null || break
      sleep 1
    done
    docker exec "${node}" sh -c "pkill -KILL -f '^${DIR}/galactic-worker' || true; rm -f /run/galactic-worker/worker.sock"
    echo "${node}: Worker stopped"
  done
}

scopes() {
  docker exec "$1" sh -c "for f in ${FENCE_DIR}/vpc-*.json; do [ -e \"\$f\" ] || continue; echo \"\$(basename \"\$f\" .json) \$(cat \"\$f\")\"; done"
}

table() {
  local vrf
  vrf=$(printf 'G%09sV' "$2")
  docker exec "$1" ip -j -d link show dev "${vrf}" | jq -r '.[0].linkinfo.info_data.table'
}

# dump prints NODE's egress_route_table entries in VPC's table, one per line:
# prefix, SID, link index and destination MAC. It needs bpftool on the host.
dump() {
  local node=$1 vpc=$2 tbl pid
  tbl=$(table "${node}" "${vpc}")
  pid=$(docker inspect -f '{{.State.Pid}}' "${node}")
  # The node's bpffs is reachable through its /proc root; bpftool runs on the
  # host, since the node image has none.
  sudo bpftool -j map dump pinned "/proc/${pid}/root${PIN_DIR}/egress_route_table" |
    jq -r --argjson t "${tbl}" '
      .[] | .formatted | select(.key.table_id == $t)
      | [.key.family, .key.prefixlen - 40, (.key.addr | @json), (.value.sid | @json),
         .value.link_ifindex, (.value.dmac | @json)] | @tsv' |
    python3 -c '
import ipaddress, json, sys
for line in sys.stdin:
    fam, plen, addr, sid, link, dmac = line.rstrip("\n").split("\t")
    a = bytes(json.loads(addr))
    ip = ipaddress.IPv6Address(a) if fam == "0" else ipaddress.IPv4Address(a[:4])
    s = ipaddress.IPv6Address(bytes(json.loads(sid)))
    mac = ":".join("%02x" % b for b in json.loads(dmac))
    link = int(link)
    kind = "pass-through" if link == 0 else "group" if link == 0xFFFFFFFF else "encap"
    print(f"{ip}/{plen} {kind} sid={s} link={link} dmac={mac}")
' | sort
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  scopes) scopes "${2:?node}" ;;
  table) table "${2:?node}" "${3:?vpc}" ;;
  dump) dump "${2:?node}" "${3:?vpc}" ;;
  *)
    sed -n '2,19p' "$0" >&2
    exit 2
    ;;
esac
