#!/bin/bash
# verify-gateway-backend-health.sh — prove that a VIP stops sending new flows
# to a backend that stops serving, on every gateway node and with no operator
# action, and sends them again once it recovers.
#
# dfw's VIP has two ns60 backends on dfw-worker and two gateway nodes,
# dfw-worker2 and dfw-worker3. ns60-tcp and ns60-udp both carry a
# healthCheck that probes TCP port 80. The check stops backend-a's TCP
# listener while its pod, container and VPCAttachment stay as they are, so
# the backend still resolves and advertises and only its health says it is
# gone. Then:
#
#   1. Both backends are Healthy, and both gateways report applying health.
#   2. backend-a's bindings turn Unhealthy within DETECT_S, and within
#      CONVERGE_S of that both gateways hold one backend for the VIP
#      (galactic_edge_rule_backends, read from each node's datapath).
#   3. Through each gateway pinned in turn, every new TCP and UDP flow is
#      answered, and by backend-b only. The UDP service drops backend-a too:
#      its health check probes TCP port 80.
#   4. Restarting galactic-router on dfw-worker leaves backend-a's published
#      decision as it was, and restarting galactic-gateway on dfw-worker2
#      brings that gateway back without backend-a.
#   5. backend-a's listener restarts, its bindings turn Healthy within
#      DETECT_S, both gateways hold two backends within CONVERGE_S, and both
#      backends answer flows again.
#
# Throughout, FIXED_PORTS fixed UDP source ports must map to the same backend
# through both gateways, which is what identical Maglev tables look like from
# a client, and after recovery each must map where it did before. The run
# reports how many of them changed backend on removal and on recovery.
#
# Usage: verify-gateway-backend-health.sh
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
CP=$(control_plane dfw)
CLIENT_HOST="clab-${LAB}-remote-host"
VIP=2001:db8:6060:1::1
PORT=80
FLOWS=16
FIXED_PORTS=32
DETECT_S=30
CONVERGE_S=5
GATEWAY_METRICS_PORT=8081
BACKEND_NODE=dfw-worker
GATEWAYS=(dfw-worker2 dfw-worker3)
# "<transit router> <edge node's address on that link> <transit-side bond>",
# as in verify-gateway-ingress.sh.
declare -A UPLINK=(
  [dfw-worker2]="tr1 2001:db8:1:11::2 bond1"
  [dfw-worker3]="tr1 2001:db8:1:12::2 bond2"
)

kc() { docker exec -i "${CP}" kubectl "$@"; }
transit() { docker exec "clab-${LAB}-$1" "${@:2}"; }

rc=0
fail() {
  echo "  FAIL $*" >&2
  rc=1
}
die() {
  echo "FAIL: $*" >&2
  exit 1
}

listening() {
  kc -n ns60 exec deploy/backend-a -- sh -c 'pgrep -f "TCP6-LISTE[N]" >/dev/null' 2>/dev/null
}
stop_listener() {
  kc -n ns60 exec deploy/backend-a -- sh -c 'pkill -f "TCP6-LISTE[N]"'
}
start_listener() {
  kc -n ns60 exec -i deploy/backend-a -- sh -s <<'EOF'
reply='echo "$POD_NAME $SOCAT_PEERADDR"'
setsid socat TCP6-LISTEN:80,reuseaddr,fork SYSTEM:"$reply" </dev/null >/dev/null 2>&1 &
EOF
}

work=$(mktemp -d)
cleanup() {
  transit tr1 ip -6 route del "${VIP}/128" 2>/dev/null || true
  listening || start_listener || true
  rm -rf "${work}"
}
trap cleanup EXIT

# rule_backends NODE PROTO prints NODE's backend count for the VIP's PROTO rule.
rule_backends() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${GATEWAY_METRICS_PORT}/metrics" |
    awk -v p="proto=\"$2\"" -v v="vip=\"${VIP}\"" \
      'index($0, "galactic_edge_rule_backends{") == 1 && index($0, p) && index($0, v) && index($0, "port=\"80\"") {print $NF; exit}'
}

# backend_health SERVICE ADDR prints "state lastTransitionTime" of the
# binding dfw-worker writes for SERVICE's IPv6 VIP and the backend at ADDR.
backend_health() {
  kc -n galactic-system get servicevipbindings \
    -l "galactic.datum.net/network-rule=$1,galactic.datum.net/binding-node=${BACKEND_NODE}" \
    -o jsonpath="{range .items[?(@.spec.vipAddress==\"${VIP}\")]}{.spec.backendAddress} {.status.health.state} {.status.health.lastTransitionTime}{\"\\n\"}{end}" |
    awk -v a="$2" '$1 == a {print $2, $3}'
}

# request PROTO SPORT prints the answering backend pod, or nothing.
request() {
  local addr
  case "$1" in
    tcp) addr="TCP6:[${VIP}]:${PORT},sourceport=$2,reuseaddr" ;;
    udp) addr="UDP6:[${VIP}]:${PORT},sourceport=$2,reuseaddr" ;;
  esac
  echo probe | docker exec -i "${CLIENT_HOST}" timeout 5 socat -t2 -T3 - "${addr}" 2>/dev/null |
    head -1 | awk '{print $1}' || true
}

pin() {
  local tr nexthop dev
  read -r tr nexthop dev <<<"${UPLINK[$1]}"
  transit "${tr}" ip -6 route replace "${VIP}/128" via "${nexthop}" dev "${dev}"
}
unpin() { transit tr1 ip -6 route del "${VIP}/128" 2>/dev/null || true; }

# wait_for SECONDS DESCRIPTION COMMAND... polls COMMAND every half second and
# sets WAITED to the seconds it took, failing past SECONDS.
wait_for() {
  local limit="$1" what="$2" start now
  shift 2
  start=$(date +%s.%N)
  while :; do
    if "$@"; then
      now=$(date +%s.%N)
      WAITED=$(awk -v a="${start}" -v b="${now}" 'BEGIN {printf "%.1f", b - a}')
      return 0
    fi
    now=$(date +%s.%N)
    if awk -v a="${start}" -v b="${now}" -v l="${limit}" 'BEGIN {exit !(b - a > l)}'; then
      fail "${what}: not within ${limit}s"
      WAITED=""
      return 1
    fi
    sleep 0.5
  done
}

health_is() { # SERVICE ADDR STATE
  local got
  got=$(backend_health "$1" "$2")
  [ "${got%% *}" = "$3" ]
}
both_health_is() { health_is ns60-tcp "$1" "$2" && health_is ns60-udp "$1" "$2"; }
holds() { # GATEWAY COUNT
  [ "$(rule_backends "$1" tcp)" = "$2" ] && [ "$(rule_backends "$1" udp)" = "$2" ]
}
gateways_hold() { # COUNT
  local gw
  for gw in "${GATEWAYS[@]}"; do
    holds "${gw}" "$1" || return 1
  done
}
gateway_ready() { # GATEWAY
  [ "$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-gateway \
    --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].status.containerStatuses[0].ready}')" = true ]
}

# flows_through GATEWAY WANT: FLOWS new TCP and UDP flows through GATEWAY must
# all be answered, by WANT when it is set. It prints the backends seen.
flows_through() {
  local gw="$1" want="${2:-}" proto pod seen=""
  pin "${gw}"
  for proto in tcp udp; do
    local answered=0
    for _ in $(seq "${FLOWS}"); do
      pick_port
      pod=$(request "${proto}" "${PORT_PICKED}")
      if [ -z "${pod}" ]; then
        fail "${gw} ${proto} from port ${PORT_PICKED}: no reply"
      elif [ -n "${want}" ] && [ "${pod}" != "${want}" ]; then
        fail "${gw} ${proto} from port ${PORT_PICKED}: answered by ${pod}, want ${want}"
      else
        answered=$((answered + 1))
        seen="${seen} ${pod}"
      fi
    done
    echo "  ${gw} ${proto}: ${answered}/${FLOWS} answered${want:+, all by ${want}}"
  done
  unpin
  SEEN=$(tr ' ' '\n' <<<"${seen}" | sort -u | tr '\n' ' ')
}

# mapping GATEWAY prints "port backend" for each fixed UDP source port
# through GATEWAY.
mapping() {
  local p
  pin "$1"
  for p in "${PORTS[@]}"; do
    echo "${p} $(request udp "${p}")"
  done
  unpin
}

# map_phase NAME records both gateways' mappings for NAME and checks they agree.
map_phase() {
  local name="$1"
  mapping "${GATEWAYS[0]}" >"${work}/${name}.${GATEWAYS[0]}"
  mapping "${GATEWAYS[1]}" >"${work}/${name}.${GATEWAYS[1]}"
  if grep -q ' $' "${work}/${name}.${GATEWAYS[0]}" "${work}/${name}.${GATEWAYS[1]}"; then
    fail "${name}: a fixed port drew no reply"
  fi
  if cmp -s "${work}/${name}.${GATEWAYS[0]}" "${work}/${name}.${GATEWAYS[1]}"; then
    echo "  ok   ${name}: all ${FIXED_PORTS} fixed ports map to the same backend through both gateways"
  else
    fail "${name}: the gateways map fixed ports to different backends:"
    diff "${work}/${name}.${GATEWAYS[0]}" "${work}/${name}.${GATEWAYS[1]}" | sed 's/^/    /' >&2
  fi
}

# moved FROM TO prints how many fixed ports changed backend between phases.
moved() {
  join "${work}/$1.${GATEWAYS[0]}" "${work}/$2.${GATEWAYS[0]}" | awk '$2 != $3' | wc -l
}

ADDR_A=$(kc -n ns60 get vpcattachment backend-a -o jsonpath='{.spec.interface.addresses[0]}')
ADDR_A=${ADDR_A%/*}
ADDR_B=$(kc -n ns60 get vpcattachment backend-b -o jsonpath='{.spec.interface.addresses[0]}')
ADDR_B=${ADDR_B%/*}
POD_A=$(pod_name "${CP}" ns60 app=backend,instance=a)
POD_B=$(pod_name "${CP}" ns60 app=backend,instance=b)
identity() {
  echo "$(kc -n ns60 get pod "${POD_A}" -o jsonpath='{.metadata.uid} {.status.containerStatuses[0].restartCount}')" \
    "$(kc -n ns60 get vpcattachment backend-a -o jsonpath='{.metadata.uid}')"
}
ID_BEFORE=$(identity)

declare -a PORTS=()
for _ in $(seq "${FIXED_PORTS}"); do
  pick_port
  PORTS+=("${PORT_PICKED}")
done
mapfile -t PORTS < <(printf '%s\n' "${PORTS[@]}" | sort)

echo "--- 1. baseline: both backends Healthy, both gateways apply health"
listening || start_listener
wait_for "${DETECT_S}" "backend-a Healthy" both_health_is "${ADDR_A}" Healthy || true
wait_for "${DETECT_S}" "backend-b Healthy" both_health_is "${ADDR_B}" Healthy || true
for gw in "${GATEWAYS[@]}"; do
  f=$(kc -n galactic-system get networkgateway "${gw}" -o jsonpath='{.status.backendHealthFiltering}')
  [ "${f}" = "true" ] || fail "${gw} does not report backendHealthFiltering (got '${f}')"
done
wait_for "${CONVERGE_S}" "both gateways hold 2 backends" gateways_hold 2 || true
map_phase baseline
[ "${rc}" -eq 0 ] || die "baseline is not healthy; fix it before testing a failure"

echo "--- 2. stop backend-a's TCP listener"
stop_listener
listening && die "backend-a's TCP listener is still running"
if wait_for "${DETECT_S}" "backend-a Unhealthy" both_health_is "${ADDR_A}" Unhealthy; then
  echo "  ok   backend-a Unhealthy after ${WAITED}s"
fi
if wait_for "${CONVERGE_S}" "both gateways drop backend-a" gateways_hold 1; then
  echo "  ok   both gateways hold 1 backend ${WAITED}s after the decision was seen"
fi

echo "--- 3. new flows avoid backend-a through each gateway"
for gw in "${GATEWAYS[@]}"; do
  flows_through "${gw}" "${POD_B}"
done
map_phase unhealthy
removed=$(moved baseline unhealthy)
stolen=$(join "${work}/baseline.${GATEWAYS[0]}" "${work}/unhealthy.${GATEWAYS[0]}" |
  awk -v a="${POD_A}" '$2 != a && $2 != $3' | wc -l)
echo "  removal moved ${removed}/${FIXED_PORTS} fixed ports, ${stolen} of them between remaining backends"
[ "${stolen}" -eq 0 ] || fail "removing backend-a moved ${stolen} fixed ports that were on backend-b"

echo "--- 4. restarts while backend-a is Unhealthy"
before=$(backend_health ns60-tcp "${ADDR_A}")
router_pod=$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-router \
  --field-selector "spec.nodeName=${BACKEND_NODE}" -o jsonpath='{.items[0].metadata.name}')
kc -n galactic-system delete pod "${router_pod}" --wait=true >/dev/null
kc -n galactic-system rollout status ds/galactic-router --timeout=180s >/dev/null
sleep 30
after=$(backend_health ns60-tcp "${ADDR_A}")
if [ "${before}" = "${after}" ]; then
  echo "  ok   galactic-router restarted on ${BACKEND_NODE}; backend-a's decision unchanged (${after})"
else
  fail "backend-a's decision changed across a galactic-router restart: '${before}' -> '${after}'"
fi
gw_pod=$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-gateway \
  --field-selector "spec.nodeName=${GATEWAYS[0]}" -o jsonpath='{.items[0].metadata.name}')
kc -n galactic-system delete pod "${gw_pod}" --wait=true >/dev/null
wait_for 120 "${GATEWAYS[0]}'s gateway pod Ready again" gateway_ready "${GATEWAYS[0]}" || true
if wait_for 60 "${GATEWAYS[0]} holds 1 backend after its restart" holds "${GATEWAYS[0]}" 1; then
  echo "  ok   galactic-gateway restarted on ${GATEWAYS[0]}; it holds 1 backend ${WAITED}s after Ready"
fi
flows_through "${GATEWAYS[0]}" "${POD_B}"

echo "--- 5. restart backend-a's TCP listener"
start_listener
if wait_for "${DETECT_S}" "backend-a Healthy again" both_health_is "${ADDR_A}" Healthy; then
  echo "  ok   backend-a Healthy after ${WAITED}s"
fi
if wait_for "${CONVERGE_S}" "both gateways restore backend-a" gateways_hold 2; then
  echo "  ok   both gateways hold 2 backends ${WAITED}s after the decision was seen"
fi
for gw in "${GATEWAYS[@]}"; do
  flows_through "${gw}" ""
  [[ " ${SEEN} " == *" ${POD_A} "* ]] || fail "${gw}: backend-a answered no flow after recovering"
done
map_phase recovered
restored=$(moved unhealthy recovered)
echo "  recovery moved ${restored}/${FIXED_PORTS} fixed ports"
if cmp -s "${work}/baseline.${GATEWAYS[0]}" "${work}/recovered.${GATEWAYS[0]}"; then
  echo "  ok   every fixed port maps where it did before backend-a failed"
else
  fail "the recovered table differs from the baseline:"
  diff "${work}/baseline.${GATEWAYS[0]}" "${work}/recovered.${GATEWAYS[0]}" | sed 's/^/    /' >&2
fi

ID_AFTER=$(identity)
if [ "${ID_BEFORE}" = "${ID_AFTER}" ]; then
  echo "  ok   backend-a's pod, container and attachment never changed (${ID_AFTER})"
else
  fail "backend-a's identity changed during the check: '${ID_BEFORE}' -> '${ID_AFTER}'"
fi

if [ "${rc}" -ne 0 ]; then
  echo "FAIL: the gateways did not follow backend-a's health" >&2
  exit 1
fi
echo "PASS: both gateways dropped backend-a while it was down and restored it once it served again"
