#!/bin/bash
# verify-gateway-restart.sh — prove the gateway and the egress shard on one
# edge node restart without cutting each other's traffic (#710).
#
# Both run from the node's XDP dispatcher, each in its own slot, so restarting
# one detaches nothing the other uses. On dfw-worker2:
#
#   1. Restart the gateway while dfw's tenant (ns10) sends to the off-fabric
#      host through dfw-worker2's shard, its first. Every request must succeed.
#   2. Restart the shard while the off-fabric host sends to dfw's VIP, pinned
#      through dfw-worker2's gateway. Every request must succeed.
#
# dfw-worker2's uplink members must also keep their carrier. A restart that
# reattached XDP would reset a real NIC; veths do not show that, so this half
# is weak here and was confirmed on staging hardware instead.
set -euo pipefail

if [ "$#" -ne 0 ]; then
  echo "usage: $(basename "$0")  (takes no arguments)" >&2
  exit 2
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
CP=$(control_plane dfw)
NODE=dfw-worker2
MEMBERS="eth1 eth2 eth3 eth4"
HOST="2001:db8:1:40::2"
VIP="2001:db8:6060:1::1"
# tr1's link to dfw-worker2: see verify-gateway-ingress.sh's UPLINK.
PIN="via 2001:db8:1:11::2 dev bond1"
# Marks the request loops' command lines, so they can be stopped by name. The
# loops run inside the tenant pod and on remote-host, where killing the local
# docker exec leaves them running, and their traffic would land in the next
# check's capture.
MARKER=gw-restart-probe

work=$(mktemp -d)
# stop_loops ends both request loops wherever they run.
stop_loops() {
  if [ -n "${pod:-}" ]; then
    docker exec "${CP}" kubectl -n ns10 exec "${pod}" -- pkill -f "${MARKER}" 2>/dev/null || true
  fi
  docker exec "clab-${LAB}-remote-host" pkill -f "${MARKER}" 2>/dev/null || true
  jobs -p | xargs -r kill 2>/dev/null || true
}

cleanup() {
  stop_loops
  docker exec "clab-${LAB}-tr1" ip -6 route del "${VIP}/128" 2>/dev/null || true
  rm -rf "${work}"
}
trap cleanup EXIT

rc=0

carrier() {
  local m
  for m in ${MEMBERS}; do
    docker exec "${NODE}" cat "/sys/class/net/${m}/carrier_changes"
  done | paste -sd' '
}

# watch NAME CMD... runs CMD in the background, recording one "ok" or "fail"
# line per request in ${work}/NAME.
watch() {
  local name="$1"
  shift
  "$@" >"${work}/${name}" 2>/dev/null &
}

# tally NAME prints "<ok> <fail>" for the requests recorded so far.
tally() {
  awk '/^ok$/ {o++} /^fail$/ {f++} END {print o + 0, f + 0}' "${work}/$1"
}

# settle NAME stops the background requests and fails the check on any
# failed request, or if too few ran to cover the restart.
settle() {
  local name="$1" what="$2" ok failed
  sleep 3
  stop_loops
  wait 2>/dev/null || true
  read -r ok failed <<<"$(tally "${name}")"
  if [ "${ok}" -lt 10 ]; then
    echo "  FAIL ${what}: only ${ok} requests completed, too few to cover the restart" >&2
    rc=1
  elif [ "${failed}" -ne 0 ]; then
    echo "  FAIL ${what}: ${failed} of $((ok + failed)) requests failed during the restart" >&2
    rc=1
  else
    echo "  ok   ${what}: ${ok} requests, none failed"
  fi
}

before=$(carrier)

echo "--- restart ${NODE}'s gateway while ns10 egresses through its shard ---"
pod=$(pod_name "${CP}" ns10)
watch egress docker exec "${CP}" kubectl -n ns10 exec "${pod}" -- timeout 120 sh -c \
  ": ${MARKER}; while :; do curl -s -o /dev/null -m2 http://[${HOST}]/ && echo ok || echo fail; sleep 0.2; done"
sleep 3
docker exec "${CP}" kubectl -n galactic-system rollout restart daemonset "galactic-gateway-${NODE}"
docker exec "${CP}" kubectl -n galactic-system rollout status daemonset "galactic-gateway-${NODE}" --timeout=120s
docker exec "${CP}" kubectl -n galactic-system wait networkgateway "${NODE}" \
  --for=condition=Ready --timeout=60s
settle egress "egress through ${NODE}'s shard"

echo "--- restart ${NODE}'s shard while the VIP is served through its gateway ---"
docker exec "clab-${LAB}-tr1" ip -6 route replace "${VIP}/128" ${PIN}
watch vip docker exec "clab-${LAB}-remote-host" timeout 120 sh -c \
  ": ${MARKER}; while :; do echo p | socat -t1 -T2 - TCP6:[${VIP}]:80 2>/dev/null | grep -q . && echo ok || echo fail; sleep 0.2; done"
sleep 3
shard=$(docker exec "${CP}" kubectl -n galactic-system get pods -l app.kubernetes.io/name=galactic-nat \
  --field-selector "spec.nodeName=${NODE}" -o jsonpath='{.items[0].metadata.name}')
docker exec "${CP}" kubectl -n galactic-system delete pod "${shard}" --wait
docker exec "${CP}" kubectl -n galactic-system rollout status daemonset galactic-nat --timeout=120s
docker exec "${CP}" kubectl -n galactic-system wait egressshard "${NODE}-egress" \
  --for=condition=Programmed --timeout=60s
settle vip "VIP through ${NODE}'s gateway"

after=$(carrier)
if [ "${before}" != "${after}" ]; then
  echo "  FAIL ${NODE}'s uplink members lost carrier (carrier_changes ${before} -> ${after})" >&2
  rc=1
else
  echo "  ok   ${NODE}'s uplink members kept carrier (${MEMBERS}: ${after})"
fi

if [ "${rc}" -ne 0 ]; then
  echo "FAIL: restarting one datapath on ${NODE} interrupted the other" >&2
  exit 1
fi
echo "PASS: the gateway and the shard on ${NODE} each restarted without interrupting the other"
