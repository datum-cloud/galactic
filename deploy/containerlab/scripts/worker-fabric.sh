#!/bin/bash
# worker-fabric.sh: run this checkout's galactic-worker on the compute nodes
# of the dedicated-placement fixture (docs/baseline.md) and inspect what its
# Fabric module programs. Lab-only: it runs the binary as a process inside
# each Kind node with the cluster's admin kubeconfig, for quick iteration.
# scripts/deploy-galactic-worker.sh installs Worker from its manifests
# instead, as a deployment does. galactic-router finds it through
# GALACTIC_ROUTER_WORKER_SOCKET and hands it every tenant route.
#
# Worker takes over every VPC scope on the node. After stop, run
# `galactic-worker handback` on each node and restart galactic-router there
# (docs/worker/operations.md), or redeploy the lab, before reusing it.
#
# Usage:
#   worker-fabric.sh start          build, copy and start Worker on NODES, with the
#                                   allowlist file WORKER_ALLOWLIST names, or one
#                                   letting only galactic-router hand it routes
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
  if [ -n "${WORKER_ALLOWLIST:-}" ]; then
    cp "${WORKER_ALLOWLIST}" "${bin}/allowlist.yaml"
  else
    cat >"${bin}/allowlist.yaml" <<'EOF'
serviceAccounts:
  - serviceAccount: galactic-system/galactic-router
    capabilities: [fabric.routes]
EOF
  fi
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
  # The VPC identifier is zero-padded to 9 characters; printf pads strings
  # with spaces only.
  vrf="G$(printf '%9s' "$2" | tr ' ' 0)V"
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
    python3 -c '
import ipaddress, json, struct, sys

table = int(sys.argv[1])

def raw(field):
    return bytes(int(b, 16) for b in field)

out = []
for e in json.load(sys.stdin):
    f = e.get("formatted")
    if f:
        k, v = f["key"], f["value"]
        tid, fam, plen = k["table_id"], k["family"], k["prefixlen"] - 40
        addr, sid = bytes(k["addr"]), bytes(v["sid"])
        link, dmac = v["link_ifindex"], bytes(v["dmac"])
    else:
        # struct egress_route_key and egress_route_value, packed, little endian.
        kb, vb = raw(e["key"]), raw(e["value"])
        plen, tid = struct.unpack_from("<II", kb)
        plen -= 40
        fam, addr = kb[8], kb[9:25]
        sid, link, dmac = vb[:16], struct.unpack_from("<I", vb, 16)[0], vb[20:26]
    if tid != table:
        continue
    ip = ipaddress.IPv6Address(addr) if fam == 0 else ipaddress.IPv4Address(addr[:4])
    kind = "pass-through" if link == 0 else "group" if link == 0xFFFFFFFF else "encap"
    mac = ":".join("%02x" % b for b in dmac)
    out.append(f"{ip}/{plen} {kind} sid={ipaddress.IPv6Address(sid)} link={link} dmac={mac}")
print("\n".join(sorted(out)))
' "${tbl}"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  scopes) scopes "${2:?node}" ;;
  table) table "${2:?node}" "${3:?vpc}" ;;
  dump) dump "${2:?node}" "${3:?vpc}" ;;
  *)
    sed -n '2,20p' "$0" >&2
    exit 2
    ;;
esac
