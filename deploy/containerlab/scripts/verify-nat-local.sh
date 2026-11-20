#!/bin/bash
# verify-nat-local.sh: NAT66 and NAT64 through a node's own egress shard and
# through a remote one, for the same VPC (#1437, resources/nat-local/).
#
# It adds a guest to each ns80 VPC on dfw-worker2, an edge node that runs an
# egress shard, with the same address in both. It then runs galactic-worker
# there, and points dfw's galactic-nat at it. Steps:
#
#   1. Setup and readiness: both VPCs' Local handoffs report ready, and
#      dfw-worker2 holds an egress_local_shard row for each.
#   2. Ordered mode, where dfw-worker2 is first: TCP, UDP and ICMP over NAT66
#      and NAT64 leave from dfw-worker2's own shard, with replies delivered.
#      The two guests' identical address and port get two sessions. No
#      packet toward dfw-worker2's own shard SID crosses its uplinks, and
#      galactic-nat counts the Local forwards and returns.
#   3. Hashed mode, flow hash: the same guest's flows leave from both
#      dfw-worker2 (Local) and dfw-worker3 (Fabric).
#   4. Recovery, ordered mode: after galactic-nat restarts and after the
#      pair is recreated, the same UDP flow keeps its masquerade port: the
#      session is reused.
#   5. Drain, hashed source mode with pins: a pinned flow keeps its shard
#      and masquerade port while that shard drains.
#
# Worker takes over every VPC scope on dfw-worker2 and never hands one back,
# so this check leaves the lab needing task destroy and task deploy. It
# restores the egress mode, the drain and galactic-nat's manifest, and stops
# Worker, on exit.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LAB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
FIXTURE="${LAB_DIR}/resources/nat-local"
source "${SCRIPT_DIR}/lib.sh"

CP=dfw-control-plane
EDGE=dfw-worker2
REMOTE=clab-gvpc-remote-host
HOST6=2001:db8:1:40::2
HOST4=11.1.40.2
HOST4_SYNTH=2001:db8:64::b01:2802
LOCAL_SHARD=dfw-worker2-egress
REMOTE_SHARD=dfw-worker3-egress
GUESTS=(guest-a-edge guest-b-edge)
CNI_METRICS=http://localhost:9180/metrics
NAT_METRICS=http://localhost:9182/metrics
ECHO_PORT=7

kc() { docker exec "${CP}" kubectl "$@"; }
kci() { docker exec -i "${CP}" kubectl "$@"; }
log() { echo "== $*"; }
die() {
  echo "FAIL: $*" >&2
  exit 1
}
STATE=$(mktemp -d)

# --- shard identities -----------------------------------------------------------

shard_field() { kc -n galactic-system get egressshard "$1" -o jsonpath="{$2}"; }
L6=$(shard_field "${LOCAL_SHARD}" .status.shardAddressIPv6)
L4=$(shard_field "${LOCAL_SHARD}" .status.shardAddressIPv4)
LSID=$(shard_field "${LOCAL_SHARD}" .status.shardSID)
R6=$(shard_field "${REMOTE_SHARD}" .status.shardAddressIPv6)
R4=$(shard_field "${REMOTE_SHARD}" .status.shardAddressIPv4)
if [ -z "${L6}" ] || [ -z "${L4}" ] || [ -z "${LSID}" ] || [ -z "${R6}" ] || [ -z "${R4}" ]; then
  die "the dfw EgressShards report no identity; deploy galactic-nat first"
fi
LSID64=$(python3 -c 'import ipaddress,sys; print(ipaddress.IPv6Network(sys.argv[1] + "/64", strict=False))' "${LSID}")

# --- saved state and cleanup ------------------------------------------------------

ENV_VARS=(GALACTIC_CNI_EGRESS_MODE GALACTIC_CNI_EGRESS_HASH GALACTIC_CNI_EGRESS_PIN_IDLE)
declare -A SAVED_ENV
env_of() {
  kc -n galactic-system get ds galactic-cni -o json | python3 -c 'import json,sys
d = json.load(sys.stdin)
for c in d["spec"]["template"]["spec"]["containers"]:
    if c["name"] == "credential-refresh":
        for e in c.get("env", []):
            if e["name"] == sys.argv[1]: print(e.get("value", "")); sys.exit(0)
print("<unset>")' "$1"
}
for v in "${ENV_VARS[@]}"; do SAVED_ENV[${v}]=$(env_of "${v}"); done
SAVED_DRAIN=$(shard_field "${LOCAL_SHARD}" .spec.drain)
SAVED_DRAIN_R=$(shard_field "${REMOTE_SHARD}" .spec.drain)
kc -n galactic-system get ds galactic-nat -o json >"${STATE}/nat-ds.json"

set_drain() { # SHARD true|false|""
  local value=null
  [ -n "$2" ] && value=$2
  kc -n galactic-system patch egressshard "$1" --type=merge -p "{\"spec\":{\"drain\":${value}}}" >/dev/null
}

cleanup() {
  local rc=$?
  set +e
  [ "${rc}" -ne 0 ] && diagnostics
  log "restoring"
  docker exec "${REMOTE}" sh -c 'pkill -f "socat UDP" || true'
  set_drain "${LOCAL_SHARD}" "${SAVED_DRAIN}"
  set_drain "${REMOTE_SHARD}" "${SAVED_DRAIN_R}"
  local args=() v
  for v in "${ENV_VARS[@]}"; do
    if [ "${SAVED_ENV[${v}]}" = "<unset>" ]; then args+=("${v}-"); else args+=("${v}=${SAVED_ENV[${v}]}"); fi
  done
  kc -n galactic-system set env daemonset/galactic-cni -c credential-refresh "${args[@]}" >/dev/null
  python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields", "generation"): d["metadata"].pop(k, None)
d.pop("status", None)
json.dump(d, sys.stdout)' "${STATE}/nat-ds.json" | kci replace -f - >/dev/null
  local f
  for f in guests nad bindings vpcattachments; do
    kci delete --ignore-not-found -f - <"${FIXTURE}/${f}.yaml" >/dev/null
  done
  NODES="${EDGE}" "${SCRIPT_DIR}/worker-fabric.sh" stop || true
  kc -n galactic-system rollout status daemonset/galactic-cni --timeout=900s >/dev/null
  kc -n galactic-system rollout status daemonset/galactic-nat --timeout=600s >/dev/null
  rm -rf "${STATE}"
  exit "${rc}"
}
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------------

pod_of() { kc -n ns80 get pods -l "app=vpc-${1#guest-}" -o jsonpath='{.items[0].metadata.name}'; }
pod_exec() {
  local p
  p=$(pod_of "$1")
  shift
  kc -n ns80 exec "${p}" -- "$@"
}

nat_metric_sum() { # PREFIX
  docker exec "${EDGE}" curl -s --max-time 4 "${NAT_METRICS}" |
    awk -v p="$1" 'index($1, p) == 1 {s += $2} END {print s + 0}'
}

# wait_true DESCRIPTION TIMEOUT CMD... retries CMD until it succeeds.
wait_true() {
  local what="$1" deadline=$((SECONDS + $2))
  shift 2
  until "$@"; do
    [ ${SECONDS} -lt ${deadline} ] || die "${what}"
    sleep 3
  done
}

# wait_mode MODE waits until dfw-worker2's galactic-cni reports MODE, after a
# rollout.
mode_is() {
  [ "$(docker exec "${EDGE}" curl -s --max-time 4 "${CNI_METRICS}" |
    awk -v m="galactic_cni_egress_mode{mode=\"$1\"}" '$1 == m {print $2}')" = 1 ]
}
wait_mode() {
  kc -n galactic-system rollout status daemonset/galactic-cni --timeout=900s >/dev/null
  wait_true "galactic-cni on ${EDGE} does not report egress mode $1 after 120s" 120 mode_is "$1"
  sleep 5
}

# handoffs_ready reports whether galactic-nat says Worker reports VPC 80's and
# VPC 81's Local handoffs Ready. It names them: galactic-nat also claims a
# pair for every other VPC with an attachment on the node, such as the edge
# conformance clients'.
VPCS=(80 81)
handoffs_ready() {
  local metrics v
  metrics=$(docker exec "${EDGE}" curl -s --max-time 4 "${NAT_METRICS}") || return 1
  for v in "${VPCS[@]}"; do
    awk -v v="vpc=\"${v}\"" '$1 ~ /^galactic_nat_local_handoff_ready\{/ && index($1, v) && $2 == 1 {f = 1}
      END {exit !f}' <<<"${metrics}" || return 1
  done
}

# local_rows_dump prints dfw-worker2's egress_local_shard rows. The node
# image has no bpftool, so it runs on the host through the node's /proc root,
# as worker-fabric.sh does.
local_rows_dump() {
  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' "${EDGE}")
  sudo -n bpftool -j map dump pinned "/proc/${pid}/root/sys/fs/bpf/galactic/egress_local_shard"
}

# local_rows reports whether egress_local_shard holds a row toward a pair for
# VPC 80's and VPC 81's VRF tables. A failed read or an unparseable dump ends
# the run at once, rather than reading as "no rows".
local_rows() {
  local dump tables=() v t
  for v in "${VPCS[@]}"; do
    t=$("${SCRIPT_DIR}/worker-fabric.sh" table "${EDGE}" "${v}") || die "cannot read VPC ${v}'s VRF table on ${EDGE}"
    [[ "${t}" =~ ^[0-9]+$ ]] || die "VPC ${v}'s VRF table on ${EDGE} reads '${t}'"
    tables+=("${t}")
  done
  dump=$(local_rows_dump 2>&1) || die "bpftool could not read egress_local_shard on ${EDGE}: ${dump}"
  python3 -c '
import json, struct, sys
try:
    rows = json.loads(sys.argv[1])
except ValueError as e:
    print("unparseable egress_local_shard dump: %s" % e, file=sys.stderr)
    sys.exit(2)
def u32(v):
    if isinstance(v, int):
        return v
    return struct.unpack("<I", bytes(int(b, 16) for b in v[:4]))[0]
have = {}
for r in rows:
    key, val = r.get("key"), r.get("value")
    if isinstance(r.get("formatted"), dict):
        key, val = r["formatted"]["key"], r["formatted"]["value"]
    pair = val.get("pair_ifindex", 0) if isinstance(val, dict) else u32(val[16:20])
    have[u32(key)] = pair
want = [int(t) for t in sys.argv[2:]]
sys.exit(0 if all(have.get(t, 0) > 0 for t in want) else 1)
' "${dump}" "${tables[@]}"
  case $? in
    0) return 0 ;;
    1) return 1 ;;
    *) die "egress_local_shard on ${EDGE} could not be parsed" ;;
  esac
}

# diagnostics prints what a failed run needs to be understood, before the
# cleanup removes it: Worker's log, galactic-nat's log and Local metrics on
# dfw-worker2, and the egress_local_shard rows.
diagnostics() {
  echo "== diagnostics"
  echo "-- galactic-worker log (dfw-worker2)"
  docker exec "${EDGE}" tail -n 120 /var/log/galactic-worker.log 2>&1 || true
  echo "-- galactic-nat log (dfw-worker2)"
  local p
  p=$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-nat \
    --field-selector "spec.nodeName=${EDGE}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "${p}" ] && kc -n galactic-system logs "${p}" -c galactic-nat --tail=120 2>&1 || true
  echo "-- galactic-nat Local metrics"
  docker exec "${EDGE}" curl -s --max-time 4 "${NAT_METRICS}" 2>/dev/null |
    grep -E '^galactic_nat_(worker|local)_' || true
  echo "-- egress_local_shard on dfw-worker2"
  local_rows_dump 2>&1 || true
}

# hairpin_start / hairpin_check capture packets toward dfw-worker2's own
# shard SID on its uplinks: a Local flow must never cross the underlay.
# Only packets leaving the node count: other nodes' tenants reach this shard
# over the same uplinks, inbound.
BONDS=()
hairpin_start() {
  mapfile -t BONDS < <(docker exec "${EDGE}" ip -o link show type bond | awk -F': ' '{print $2}')
  [ "${#BONDS[@]}" -gt 0 ] || die "${EDGE} has no bond uplinks"
  local b
  for b in "${BONDS[@]}"; do
    docker exec -d "${EDGE}" sh -c "timeout 600 tcpdump -i ${b} -Q out -nn -U -w /tmp/nat-local-hairpin-${b}.pcap 'ip6 and dst net ${LSID64}' >/dev/null 2>&1"
  done
  sleep 2
  for b in "${BONDS[@]}"; do
    docker exec "${EDGE}" pgrep -f "nat-local-hairpin-${b}.pcap" >/dev/null || die "the hairpin capture on ${b} did not start"
  done
}
hairpin_check() {
  docker exec "${EDGE}" sh -c 'pkill -INT -f nat-local-hairpin- || true'
  sleep 2
  local b n total=0
  for b in "${BONDS[@]}"; do
    n=$(docker exec "${EDGE}" sh -c "tcpdump -nn -r /tmp/nat-local-hairpin-${b}.pcap 2>/dev/null | wc -l") ||
      die "cannot read the hairpin capture on ${b}"
    total=$((total + n))
  done
  docker exec "${EDGE}" sh -c 'rm -f /tmp/nat-local-hairpin-*.pcap'
  [ "${total}" -eq 0 ] || die "${total} packets toward ${EDGE}'s own shard SID left through its uplinks (hairpin)"
  echo "    no packet toward ${LSID64} left through ${BONDS[*]}"
}

# probe KIND GUEST COUNT ALLOWED... sends COUNT requests of KIND (tcp6, tcp4,
# udp6, udp4, icmp6, icmp4) from GUEST to remote-host and checks every
# answer arrived and every source remote-host saw is in ALLOWED. The sources
# seen are left in ${STATE}/seen.
probe() {
  local kind="$1" guest="$2" count="$3"
  shift 3
  local allowed=("$@") dst filter cmd ok out cap="${STATE}/cap"
  case "${kind}" in
    *6) dst=${HOST6} ;;
    *) dst=${HOST4_SYNTH} ;;
  esac
  case "${kind}" in
    tcp6) filter="ip6 and dst ${HOST6} and tcp dst port 80 and ip6[53] & 0x12 == 0x02" ;;
    tcp4) filter="ip and dst ${HOST4} and tcp dst port 80 and tcp[13] & 0x12 == 0x02" ;;
    udp6) filter="ip6 and dst ${HOST6} and udp dst port ${ECHO_PORT}" ;;
    udp4) filter="ip and dst ${HOST4} and udp dst port ${ECHO_PORT}" ;;
    icmp6) filter="icmp6 and dst ${HOST6} and ip6[40] == 128" ;;
    icmp4) filter="icmp and dst ${HOST4} and icmp[0] == 8" ;;
  esac
  case "${kind}" in
    tcp*) cmd="for i in \$(seq ${count}); do curl -s -o /dev/null -w '%{http_code}\n' --max-time 4 'http://[${dst}]/'; done" ;;
    udp*) cmd="for i in \$(seq ${count}); do echo echo-\$i | nc -u -w2 ${dst} ${ECHO_PORT}; done" ;;
    icmp*) cmd="ping -6 -c ${count} -i 0.3 -W 2 ${dst}" ;;
  esac
  docker exec "${REMOTE}" timeout $((count * 4 + 15)) tcpdump -i eth1 -nn -l -c "${count}" "${filter}" >"${cap}" 2>&1 &
  local tpid=$!
  sleep 2
  out=$(pod_exec "${guest}" sh -c "${cmd}" 2>&1) || true
  local cap_rc=0
  wait "${tpid}" || cap_rc=$?
  case "${kind}" in
    tcp*) ok=$(grep -c '^200$' <<<"${out}" || true) ;;
    udp*) ok=$(grep -c '^echo-' <<<"${out}" || true) ;;
    icmp*) ok=$(sed -n 's/.* \([0-9]*\) received.*/\1/p' <<<"${out}" | head -1) ;;
  esac
  local strip='s/\.[0-9]+$//'
  case "${kind}" in icmp*) strip='s/^//' ;; esac
  grep -oE '^[0-9:.]+ IP6? [0-9a-f:.]+ >' "${cap}" | awk '{print $3}' | sed -E "${strip}" | sort -u |
    sed '/^$/d' >"${STATE}/seen" || true
  if [ "${ok:-0}" != "${count}" ]; then
    echo "    ${kind} from ${guest}: ${ok:-0}/${count} answered; output: $(tr '\n' ' ' <<<"${out}")" >&2
    return 1
  fi
  if [ "${cap_rc}" -ne 0 ]; then
    echo "    ${kind} from ${guest}: remote-host did not see ${count} requests" >&2
    return 1
  fi
  local addr a found
  while read -r addr; do
    found=0
    for a in "${allowed[@]}"; do [ "${addr}" = "${a}" ] && found=1; done
    if [ "${found}" -eq 0 ]; then
      echo "    ${kind} from ${guest}: arrived from ${addr}, want one of ${allowed[*]}" >&2
      return 1
    fi
  done <"${STATE}/seen"
  echo "    ${kind} from ${guest}: ${count}/${count} answered, sources $(tr '\n' ' ' <<<"$(cat "${STATE}/seen")")"
}
expect() { probe "$@" || die "$1 from $2"; }

# udp_tuple GUEST FAMILY sends one UDP datagram from source port 40000 and
# prints the address.port remote-host saw it from, after checking the echo
# came back.
udp_tuple() {
  local guest="$1" dst filter host out cap="${STATE}/tuple"
  if [ "$2" = 6 ]; then dst=${HOST6} host=${HOST6}; else dst=${HOST4_SYNTH} host=${HOST4}; fi
  filter="dst host ${host} and udp dst port ${ECHO_PORT}"
  docker exec "${REMOTE}" timeout 15 tcpdump -i eth1 -nn -l -c 1 "${filter}" >"${cap}" 2>&1 &
  local tpid=$!
  sleep 2
  out=$(pod_exec "${guest}" sh -c "echo tuple | nc -u -w2 -p 40000 ${dst} ${ECHO_PORT}" 2>&1) || true
  wait "${tpid}" || true
  [ "${out}" = tuple ] || die "UDP echo to ${dst} from ${guest} got '${out}'"
  grep -oE ' IP6? [0-9a-f:.]+ >' "${cap}" | awk '{print $2}' | head -1
}

# --- 1. setup ------------------------------------------------------------------------

log "1. setup: edge guests, galactic-worker and galactic-nat's claims on ${EDGE}"
kci apply -f - >/dev/null <"${LAB_DIR}/../../config/galactic-nat/rbac.yaml"
kci apply -f - >/dev/null <"${FIXTURE}/vpcattachments.yaml"
kci apply -f - >/dev/null <"${FIXTURE}/bindings.yaml"
kci apply -f - >/dev/null <"${FIXTURE}/nad.yaml"
kci apply -f - >/dev/null <"${FIXTURE}/guests.yaml"
for g in "${GUESTS[@]}"; do kc -n ns80 rollout status deployment "${g}" --timeout=300s >/dev/null; done
"${SCRIPT_DIR}/publish-attachments.sh" ns80 dfw

NODES="${EDGE}" WORKER_ALLOWLIST="${FIXTURE}/allowlist.yaml" "${SCRIPT_DIR}/worker-fabric.sh" start
kc -n galactic-system patch ds galactic-nat --type=strategic \
  --patch "$(cat "${FIXTURE}/nat-worker-patch.yaml")" >/dev/null
kc -n galactic-system rollout status daemonset/galactic-nat --timeout=600s >/dev/null

wait_true "galactic-nat's Local handoffs on ${EDGE} are not ready after 300s" 300 handoffs_ready
wait_true "${EDGE} holds no egress_local_shard row for both VPCs after 120s" 120 local_rows
echo "    both VPCs' Local handoffs ready; egress_local_shard rows present"

docker exec -d "${REMOTE}" sh -c "socat UDP6-RECVFROM:${ECHO_PORT},ipv6only=1,fork EXEC:cat"
docker exec -d "${REMOTE}" sh -c "socat UDP4-RECVFROM:${ECHO_PORT},fork EXEC:cat"
sleep 1
n=$(docker exec "${REMOTE}" sh -c 'pgrep -f "socat UDP" | wc -l')
[ "${n}" -eq 2 ] || die "remote-host runs ${n} UDP echo servers, want 2"

# --- 2. ordered: the local shard --------------------------------------------------------

log "2. ordered mode: every family and protocol leaves from ${EDGE}'s own shard"
fwd0=$(nat_metric_sum 'galactic_nat_local_packets_total{stat="forward"}')
ret0=$(nat_metric_sum 'galactic_nat_local_packets_total{stat="return"}')
hairpin_start
for g in "${GUESTS[@]}"; do
  for k in tcp6 udp6 icmp6; do expect "${k}" "${g}" 3 "${L6}"; done
  for k in tcp4 udp4 icmp4; do expect "${k}" "${g}" 3 "${L4}"; done
done
a=$(udp_tuple guest-a-edge 6)
b=$(udp_tuple guest-b-edge 6)
echo "    overlapping guests, same address and port: VPC 80 as ${a}, VPC 81 as ${b}"
[ "${a}" != "${b}" ] || die "the two VPCs' identical flows share masquerade tuple ${a}"
hairpin_check
fwd1=$(nat_metric_sum 'galactic_nat_local_packets_total{stat="forward"}')
ret1=$(nat_metric_sum 'galactic_nat_local_packets_total{stat="return"}')
[ "${fwd1%.*}" -gt "${fwd0%.*}" ] && [ "${ret1%.*}" -gt "${ret0%.*}" ] ||
  die "galactic-nat counted no Local forwards (${fwd0}->${fwd1}) or returns (${ret0}->${ret1})"
echo "    Local forwards ${fwd0}->${fwd1}, returns ${ret0}->${ret1}"

# --- 3. hashed: local and remote shards -------------------------------------------------

log "3. hashed mode, flow hash: flows leave from ${EDGE} (Local) and dfw-worker3 (Fabric)"
kc -n galactic-system set env daemonset/galactic-cni -c credential-refresh \
  GALACTIC_CNI_EGRESS_MODE=hashed GALACTIC_CNI_EGRESS_HASH=flow GALACTIC_CNI_EGRESS_PIN_IDLE=0s >/dev/null
wait_mode hashed
for g in "${GUESTS[@]}"; do
  expect tcp6 "${g}" 24 "${L6}" "${R6}"
  [ "$(wc -l <"${STATE}/seen")" -eq 2 ] || die "${g}'s NAT66 flows used one shard: $(cat "${STATE}/seen")"
  expect tcp4 "${g}" 24 "${L4}" "${R4}"
  [ "$(wc -l <"${STATE}/seen")" -eq 2 ] || die "${g}'s NAT64 flows used one shard: $(cat "${STATE}/seen")"
done

# --- 4. recovery, ordered -------------------------------------------------------------

log "4. recovery: the same UDP flow keeps its masquerade port"
kc -n galactic-system set env daemonset/galactic-cni -c credential-refresh GALACTIC_CNI_EGRESS_MODE- \
  GALACTIC_CNI_EGRESS_HASH- GALACTIC_CNI_EGRESS_PIN_IDLE- >/dev/null
wait_mode ordered
before=$(udp_tuple guest-a-edge 6)
[ "${before%.*}" = "${L6}" ] || die "ordered mode sent guest-a-edge to ${before}, not ${EDGE}"

nat_pod=$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-nat \
  --field-selector "spec.nodeName=${EDGE}" -o jsonpath='{.items[0].metadata.name}')
kc -n galactic-system delete pod "${nat_pod}" --wait >/dev/null
kc -n galactic-system rollout status daemonset/galactic-nat --timeout=600s >/dev/null
wait_true "Local handoffs not ready after galactic-nat restarted" 300 handoffs_ready
after=$(udp_tuple guest-a-edge 6)
echo "    galactic-nat restart: ${before} -> ${after}"
[ "${after}" = "${before}" ] || die "the session was not reused across a galactic-nat restart"

# The NAT end is the pair end outside any VRF; the tenant end has one as
# its master.
nat_end=$(docker exec "${EDGE}" ip -o link show type veth |
  awk '/alias galactic-local:80\// && !/ master / {sub(/@.*/, "", $2); print $2; exit}')
[ -n "${nat_end}" ] || die "found no NAT end of VPC 80's pair on ${EDGE}"
old_idx=$(docker exec "${EDGE}" cat "/sys/class/net/${nat_end}/ifindex")
docker exec "${EDGE}" ip link del "${nat_end}"
# pair_back reports whether Worker recreated the pair under a new ifindex and
# galactic-nat attached its program to the new NAT end.
pair_back() {
  local idx
  idx=$(docker exec "${EDGE}" cat "/sys/class/net/${nat_end}/ifindex" 2>/dev/null) || return 1
  [ "${idx}" != "${old_idx}" ] || return 1
  docker exec "${EDGE}" ip -d link show "${nat_end}" | grep -E 'xdp(drv|generic)?/id:|prog/xdp' >/dev/null
}
wait_true "VPC 80's pair is not back with galactic-nat's program after 300s" 300 pair_back
wait_true "Local handoffs not ready after the pair was recreated" 300 handoffs_ready
wait_true "egress_local_shard rows not back after the pair was recreated" 120 local_rows
after=$(udp_tuple guest-a-edge 6)
echo "    pair recreated (${nat_end}): ${before} -> ${after}"
[ "${after}" = "${before}" ] || die "the session was not reused after the pair was recreated"

# --- 5. drain, hashed source mode with pins ----------------------------------------------

log "5. drain: a pinned flow keeps its shard and masquerade port"
kc -n galactic-system set env daemonset/galactic-cni -c credential-refresh \
  GALACTIC_CNI_EGRESS_MODE=hashed GALACTIC_CNI_EGRESS_HASH=source GALACTIC_CNI_EGRESS_PIN_IDLE=1h >/dev/null
wait_mode hashed
for g in "${GUESTS[@]}"; do
  pinned=$(udp_tuple "${g}" 6)
  case "${pinned%.*}" in
    "${L6}") s=${LOCAL_SHARD} where=Local ;;
    "${R6}") s=${REMOTE_SHARD} where=Fabric ;;
    *) die "${g} left from ${pinned}" ;;
  esac
  set_drain "${s}" true
  sleep 10
  again=$(udp_tuple "${g}" 6)
  set_drain "${s}" ""
  echo "    ${g} pinned to ${s} (${where}): ${pinned} -> ${again} while it drained"
  [ "${again}" = "${pinned}" ] || die "${g}'s pin to ${s} did not hold while it drained"
done

log "PASS"
