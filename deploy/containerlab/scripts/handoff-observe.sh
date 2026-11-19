#!/bin/bash
# handoff-observe.sh: prove the Local kernel handoffs (docs/handoffs.md) on
# the compute node of the #1432 fixture, with captures, and write the
# results.
#
# Usage: handoff-observe.sh OUTDIR
#
# Needs ns80 (task deploy:ns80) and the ns80-tap fixture (task
# deploy:ns80-tap) deployed, and the probe built from this checkout
# (HANDOFF_PROBE, default bin/handoff-probe at the repository root). When a
# precondition does not hold, it says which in OUTDIR/precondition, changes
# nothing and exits 0.
#
# Each cell builds a receiving device (plain veth, 802.3ad bond, VLAN) on the
# node, places the prototypes in an XDP mode, and runs two capture windows:
#
#   h1/<cell>  local.tap: client to two VIPs, one per VPC, delivered to the
#              TAP guests with the same address; the replies; a denied port
#              each way; a VIP whose tc program leaves policy to tp_deliver
#   h2/<cell>  local.veth_pair: each TAP guest's flow out through the
#              internal veth pair and the shard address, and back; a denied
#              port each way
#
# Then one window, h3, for local.routed_link and local.socket: VRF-bound
# sockets in a pod reach each VPC's veth guest through a routed link and
# read the answer, and the guests reach sockets in the pod; a denied port;
# an unbound socket; a spoofed source.
#
# Every window also captures the node's physical bond members, which must
# carry nothing of the probes, encapsulated or not.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
OUT=${1:?usage: handoff-observe.sh OUTDIR}
mkdir -p "${OUT}/logs"
OUT=$(cd "${OUT}" && pwd)
: >"${OUT}/results.tsv"
: >"${OUT}/volatile.tsv"
rm -f "${OUT}/precondition"
source "${SCRIPT_DIR}/baseline-lib.sh"
source "${SCRIPT_DIR}/handoff-lib.sh"

REPO=$(cd "${SCRIPT_DIR}/../../.." && pwd)
HANDOFF_PROBE=${HANDOFF_PROBE:-${REPO}/bin/handoff-probe}
N=5

handoff_preconditions
trap handoff_cleanup EXIT

NONCE="hp$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"
volatile nonce "${NONCE}"
volatile kernel "$(docker exec "${NODE}" uname -r)"
volatile cni-image "$(kc -n galactic-system get ds -o jsonpath='{range .items[*]}{.spec.template.spec.containers[0].image}{"\n"}{end}' | grep -m1 cni || true)"
volatile checkout "$(git -C "${REPO}" rev-parse HEAD)"
cp "${OUT}/logs/check.txt" "${OUT}/logs/datapath-check.txt"

rig_start
rig /hp/handoff-rig.sh client-up

# Listeners. Each answers a line with the line and who it is.
for v in 80 81; do
  vip=${VIP_A}
  [ "${v}" = 81 ] && vip=${VIP_B}
  listen_udp "pid:${PID[tap${v}]}" "${vip}" 7 "tap${v}"
  listen "pid:${PID[tap${v}]}" "TCP6-LISTEN:8080" "tap${v}"
  listen "pid:${PID[tap${v}]}" "TCP6-LISTEN:9" "tap${v}-open9"
  listen "pid:${PID[veth${v}]}" "TCP6-LISTEN:8080" "vpc${v}"
  listen "pid:${PID[veth${v}]}" "TCP6-LISTEN:9" "vpc${v}-open9"
done
listen_udp "pid:${PID[tap80]}" :: 17 "tap80-wild"
listen_udp client :: 7 client
listen client "TCP6-LISTEN:8080" client
sleep 1
for k in tap80 tap81 veth80 veth81; do
  in_pod "${PID[${k}]}" ss -lntup >"${OUT}/logs/sockets-${k}.txt" 2>&1 || true
done
in_pod "${PID[tap80]}" nstat -az Udp6InDatagrams Udp6NoPorts Udp6InErrors Udp6RcvbufErrors Udp6InCsumErrors \
  >"${OUT}/logs/udp6-tap80.txt" 2>&1 || true
# tc changes on the node for the whole run, collected by handoff_cleanup.
docker exec -d "${NODE}" sh -c "exec tc -ts monitor >'${NODE_CFG}/tc-monitor.txt' 2>&1"
# Link changes on the node for the whole run.
rig_bg sh -c 'exec ip -ts monitor link >/out/logs/link-monitor.txt 2>&1'
docker exec "${NODE}" crictl ps --name galactic-cni -o json 2>/dev/null |
  jq -r '.containers[] | "galactic-cni \(.id[0:12]) started \(.createdAt)"' >"${OUT}/logs/cni.txt" || true

# Cells ---------------------------------------------------------------------
# name kind mode peerMode redirect xdp-ifaces tc-ifaces vlan setup h2 push
# setup: ok, or unsupported when the attach must fail. h2: pass, or how the
# handoff as specified fails to deliver, which the run records:
#   peer-skipped        generic XDP on the peer never runs on a packet tc
#                       redirected (the kernel's skb_is_redirected check)
#   egress-unsupported  the peer translates, but its XDP_REDIRECT to a VLAN
#                       device has no transmit path
# push: 1 where the peer pushes the VLAN tag itself and redirects to the
# VLAN's lower device, the alternative the contract adopts.
CELLS=(
  "plain-native plain native native true hp-dut0 hp-dut0 0 ok pass 0"
  "plain-generic plain generic generic true hp-dut0 hp-dut0 0 ok peer-skipped 0"
  "plain-generic-native-peer plain generic native true hp-dut0 hp-dut0 0 ok pass 0"
  "bond-native bond native native true hp-dut0,hp-dut1 hp-dut0,hp-dut1 0 ok pass 0"
  "bond-generic-native-peer bond generic native true hp-dut0,hp-dut1 hp-dut0,hp-dut1 0 ok pass 0"
  "vlan-native vlan native native true hp-dut0.120 hp-dut0.120 0 unsupported - 0"
  "vlan-lower-native vlan native native true hp-dut0 hp-dut0.120 120 ok pass 1"
  "vlan-generic-native-peer vlan generic native true hp-dut0.120 hp-dut0.120 0 ok pass 1"
  "vlan-generic-redirect vlan generic native true hp-dut0.120 hp-dut0.120 0 ok egress-unsupported 0"
)
if [ -n "${HANDOFF_CELLS:-}" ]; then
  # A comma-separated subset, for a quicker run while working on a cell.
  mapfile -t CELLS < <(for c in "${CELLS[@]}"; do
    case ",${HANDOFF_CELLS}," in *",${c%% *},"*) echo "${c}" ;; esac
  done)
fi

# trace CELL STEP keeps both TAPs' tc ingress filters after a step of a
# cell, so a run shows which step, if any, changes galactic-cni's chain.
trace() {
  local t
  for t in "${TAP_A}" "${TAP_B}"; do
    {
      echo "## $(date -u +%T.%N) $1 $2 ${t}"
      docker exec "${NODE}" tc qdisc show dev "${t}" 2>&1
      docker exec "${NODE}" tc filter show dev "${t}" ingress 2>&1
      docker exec "${NODE}" tc filter show dev "${t}" egress 2>&1
      rig bpftool net show dev "${t}" 2>&1
    } >>"${OUT}/logs/trace.txt"
  done
}

# capture_cell WINDOW DUT-MEMBERS... arms every capture point of a cell.
capture_cell() {
  local w="$1"
  shift
  cap "${w}" client client "${@/hp-dut/hp-cl}"
  cap "${w}" dut node "$@"
  cap "${w}" tap80-host node "${TAP_A}"
  cap "${w}" tap81-host node "${TAP_B}"
  cap "${w}" tap80-guest "pid:${PID[tap80]}" tap0
  cap "${w}" tap81-guest "pid:${PID[tap81]}" tap0
  cap "${w}" pair80 node hpn80t hpn80n
  cap "${w}" pair81 node hpn81t hpn81n
  cap "${w}" physical node "${PHYSICAL_IFS[@]}"
  cap_wait
}

# no_trace WINDOW TAG records that the physical members carried nothing
# with TAG, and nothing encapsulated with it.
no_trace() {
  record "$1" "physical members carry the probes" 0 "$(count "$1" physical "$2")"
  record "$1" "physical members carry them encapsulated" 0 "$(count "$1" physical "$2" --srv6)"
}

run_cell() {
  local name kind mode peer redirect xdp tc vlan setup h2 push dut cfg w tag v vip shard answers err members
  read -r name kind mode peer redirect xdp tc vlan setup h2 push <<<"$1"
  echo "=== cell ${name} ==="
  # The prototypes run after galactic-cni's own filters on the TAPs; a cell
  # without them would prove nothing. Record and skip it.
  local t chain=yes
  for t in "${TAP_A}" "${TAP_B}"; do
    docker exec "${NODE}" tc filter show dev "${t}" ingress >"${OUT}/logs/tap-filters-${name}-${t}.txt" 2>&1 || true
    grep -q galactic_usid_egress "${OUT}/logs/tap-filters-${name}-${t}.txt" || chain=no
  done
  if [ "${chain}" = no ]; then
    record "cell/${name}" "galactic-cni's egress chain is on both TAPs" yes no
    return 0
  fi
  trace "${name}" start
  dut=$(rig /hp/handoff-rig.sh dut-up "${kind}" | tail -1)
  trace "${name}" dut-up
  rig /hp/handoff-rig.sh pairs-up on >/dev/null
  trace "${name}" pairs-up
  cfg=$(cell_config "${name}" "${mode}" "${peer}" "${redirect}" "${xdp}" "${tc}" "${vlan}" "${dut}" "${push}")
  if ! probe setup "${cfg}" >"${OUT}/logs/setup-${name}.txt" 2>&1; then
    err=$(tail -1 "${OUT}/logs/setup-${name}.txt")
    volatile "setup-${name}" "${err}"
    if grep -q 'operation not supported' "${OUT}/logs/setup-${name}.txt"; then
      record "cell/${name}" "XDP attach" "${setup}" unsupported
    else
      record "cell/${name}" "XDP attach" "${setup}" "error"
    fi
    probe teardown "${cfg}" >>"${OUT}/logs/teardown.txt" 2>&1 || true
    rig /hp/handoff-rig.sh pairs-down
    rig /hp/handoff-rig.sh dut-down
    return 0
  fi
  record "cell/${name}" "XDP attach" "${setup}" ok
  trace "${name}" setup
  read -r -a members <<<"${xdp//,/ }"
  [ "${kind}" = vlan ] && members=(hp-dut0)

  # Warm the neighbors on every path, outside the capture windows.
  for v in 80 81; do
    vip=${VIP_A}
    [ "${v}" = 81 ] && vip=${VIP_B}
    ask client 2 "UDP6:[${vip}]:7" warm >/dev/null
    ask "pid:${PID[tap${v}]}" 2 "UDP6:[${CLIENT}]:7" warm >/dev/null
  done

  # local.tap ---------------------------------------------------------------
  w="h1/${name}"
  capture_cell "${w}" "${members[@]}"
  for v in 80 81; do
    vip=${VIP_A}
    [ "${v}" = 81 ] && vip=${VIP_B}
    tag="${NONCE}-${name}-h1-${v}"
    answers=$(for i in $(seq 1 "${N}"); do ask client 2 "UDP6:[${vip}]:7" "${tag}-${i}"; done)
    record "${w}" "client gets tap${v}'s UDP answers from its VIP" "${N}" \
      "$(grep -c " tap${v}\$" <<<"${answers}" || true)"
    echo "${answers}" >>"${OUT}/logs/answers.txt"
  done
  # UDP diagnostics, recorded as observations: the TAP guest's own UDP
  # listener asked from inside the pod, and a wildcard listener on port 17.
  record "${w}" "tap80's UDP listener answers inside the pod" - \
    "$(seen "$(ask "pid:${PID[tap80]}" 2 "UDP6:[${VIP_A}]:7" selftest | grep -c ' tap80$' || true)")"
  record "${w}" "tap80's wildcard UDP listener answers the client" - \
    "$(seen "$(ask client 2 "UDP6:[${VIP_A}]:17" "${NONCE}-${name}-h1-wild" | grep -c ' tap80-wild$' || true)")"
  in_pod "${PID[tap80]}" nstat -az Udp6InDatagrams Udp6NoPorts Udp6InErrors Udp6RcvbufErrors Udp6InCsumErrors \
    >>"${OUT}/logs/udp6-tap80.txt" 2>&1 || true
  in_pod "${PID[tap80]}" ss -uanp >>"${OUT}/logs/udp6-tap80.txt" 2>&1 || true
  tag="${NONCE}-${name}-h1-tcp"
  record "${w}" "client gets tap80's TCP answer" yes \
    "$(seen "$(ask client 3 "TCP6:[${VIP_A}]:8080" "${tag}" | grep -c ' tap80$' || true)")"
  ask client 2 "TCP6:[${VIP_A}]:9" "${NONCE}-${name}-h1-deny-in" >/dev/null
  printf '%s\n' "${NONCE}-${name}-h1-deny-out" | docker exec -i "${RIG}" timeout 3 nsenter -t "${PID[tap80]}" -n \
    socat -u - "UDP6-SENDTO:[${CLIENT}]:9,bind=[${VIP_A}]" || true
  ask client 2 "UDP6:[${VIP_A_UNDECIDED}]:7" "${NONCE}-${name}-h1-undecided" >/dev/null
  probe counters "${cfg}" >"${OUT}/logs/counters-h1-${name}.json"
  cap_stop
  for v in 80 81; do
    vip=${VIP_A}
    [ "${v}" = 81 ] && vip=${VIP_B}
    tag="${NONCE}-${name}-h1-${v}"
    record "${w}" "tap${v} guest receives its VIP's requests" "${N}" \
      "$(count "${w}" "tap${v}-guest" "${tag}" --dst "${vip}")"
    o=81
    [ "${v}" = 81 ] && o=80
    record "${w}" "tap${o} guest receives tap${v}'s requests" 0 "$(count "${w}" "tap${o}-guest" "${tag}")"
    record "${w}" "client receives tap${v}'s answers from its VIP" "${N}" \
      "$(count "${w}" client "${tag}" --src "${vip}" --dst "${CLIENT}")"
  done
  # A denied TCP connection never carries the nonce: count its SYNs.
  record "${w}" "denied TCP 9: reaches the receiving device" yes \
    "$(seen "$(count "${w}" dut "" --dst "${VIP_A}" --proto tcp --dport 9)")"
  record "${w}" "denied TCP 9: reaches no guest" 0 \
    "$(($(count "${w}" tap80-guest "" --proto tcp --dport 9) + $(count "${w}" tap81-guest "" --proto tcp --dport 9)))"
  record "${w}" "denied UDP 9 reply: leaves the guest" yes \
    "$(seen "$(count "${w}" tap80-host "${NONCE}-${name}-h1-deny-out")")"
  record "${w}" "denied UDP 9 reply: reaches no client" 0 "$(count "${w}" client "${NONCE}-${name}-h1-deny-out")"
  record "${w}" "policy left to tp_deliver: reaches the receiving device" yes \
    "$(seen "$(count "${w}" dut "${NONCE}-${name}-h1-undecided")")"
  record "${w}" "policy left to tp_deliver: reaches the guest" 0 \
    "$(count "${w}" tap80-guest "${NONCE}-${name}-h1-undecided")"
  record "${w}" "XDP metadata reaches tc" yes \
    "$(seen "$(counter tc_meta_ok <"${OUT}/logs/counters-h1-${name}.json")")"
  record "${w}" "tc denies on the PublicService path" yes \
    "$(seen "$(counter tc_tenant_deny <"${OUT}/logs/counters-h1-${name}.json")")"
  record "${w}" "tap tc denies the reply on the PublicService path" yes \
    "$(seen "$(counter tap_reply_deny <"${OUT}/logs/counters-h1-${name}.json")")"
  no_trace "${w}" "${NONCE}-${name}-h1"

  trace "${name}" h1
  # local.veth_pair ---------------------------------------------------------
  w="h2/${name}"
  probe renew "${cfg}" >/dev/null
  capture_cell "${w}" "${members[@]}"
  local want=${N} wantyes=yes translates=yes leak=0
  if [ "${h2}" != pass ]; then
    want=0
    wantyes=no
    leak=-
  fi
  [ "${h2}" = peer-skipped ] && translates=no
  for v in 80 81; do
    tag="${NONCE}-${name}-h2-${v}"
    answers=$(for i in $(seq 1 "${N}"); do ask "pid:${PID[tap${v}]}" 2 "UDP6:[${CLIENT}]:7" "${tag}-${i}"; done)
    record "${w}" "tap${v} gets the client's UDP answers" "${want}" "$(grep -c ' client$' <<<"${answers}" || true)"
  done
  record "${w}" "tap80 gets the client's TCP answer" "${wantyes}" \
    "$(seen "$(ask "pid:${PID[tap80]}" 3 "TCP6:[${CLIENT}]:8080" "${NONCE}-${name}-h2-tcp" | grep -c ' client$' || true)")"
  printf '%s\n' "${NONCE}-${name}-h2-deny-out" | docker exec -i "${RIG}" timeout 3 nsenter -t "${PID[tap80]}" -n \
    socat -u - "UDP6-SENDTO:[${CLIENT}]:9" || true
  ask client 2 "TCP6:[${SHARD_A}]:9" "${NONCE}-${name}-h2-deny-in" >/dev/null
  probe counters "${cfg}" >"${OUT}/logs/counters-h2-${name}.json"
  cap_stop
  for v in 80 81; do
    shard=${SHARD_A}
    [ "${v}" = 81 ] && shard=${SHARD_B}
    tag="${NONCE}-${name}-h2-${v}"
    record "${w}" "client receives tap${v}'s flow from its shard address" "${want}" \
      "$(count "${w}" client "${tag}" --src "${shard}" --dst "${CLIENT}")"
    record "${w}" "client receives tap${v}'s flow untranslated" "${leak}" \
      "$(count "${w}" client "${tag}" --src "${TAP_GUEST}")"
    o=81
    [ "${v}" = 81 ] && o=80
    record "${w}" "tap${o} guest receives tap${v}'s answers" 0 "$(count "${w}" "tap${o}-guest" "${tag}" --dst "${TAP_GUEST}")"
  done
  record "${w}" "pair peer XDP translates" "${translates}" \
    "$(seen "$(counter peer_snat <"${OUT}/logs/counters-h2-${name}.json")")"
  record "${w}" "denied UDP 9: leaves the guest" yes "$(seen "$(count "${w}" tap80-host "${NONCE}-${name}-h2-deny-out")")"
  record "${w}" "denied UDP 9: reaches no client" 0 "$(count "${w}" client "${NONCE}-${name}-h2-deny-out")"
  # The dispatcher redirects the return before tcpdump on the receiving
  # device sees it: count it where it is sent and where it is delivered.
  record "${w}" "denied TCP 9 return: leaves the client" yes \
    "$(seen "$(count "${w}" client "" --dst "${SHARD_A}" --proto tcp --dport 9)")"
  record "${w}" "denied TCP 9 return: reaches the pair's tenant end" yes \
    "$(seen "$(count "${w}" pair80 "" --dst "${TAP_GUEST}" --proto tcp --dport 9)")"
  record "${w}" "denied TCP 9 return: reaches no guest" 0 "$(count "${w}" tap80-guest "" --proto tcp --dport 9)"
  no_trace "${w}" "${NONCE}-${name}-h2"

  trace "${name}" h2
  probe teardown "${cfg}" >>"${OUT}/logs/teardown.txt" 2>&1
  trace "${name}" teardown
  rig /hp/handoff-rig.sh pairs-down
  trace "${name}" pairs-down
  rig /hp/handoff-rig.sh dut-down
  trace "${name}" dut-down
}

# What xdpmode.Select decides for the lab's own interfaces.
rig /hp/handoff-rig.sh dut-up plain >/dev/null
record cell/select "xdpmode.Select on ${NODE}" native "$(probe mode hp-dut0 | jq -r .mode)"
probe mode hp-dut0 >"${OUT}/logs/select.json"
rig /hp/handoff-rig.sh dut-down

for c in "${CELLS[@]}"; do
  run_cell "${c}"
done

# local.routed_link and local.socket ----------------------------------------
echo "=== routed link and socket ==="
rig /hp/handoff-rig.sh links-up "${PID[envoy]}"
cfg=$(jq -n --arg pin /sys/fs/bpf/galactic-handoff-proof --arg gpin "${GALACTIC_PIN}" --arg link "${LINK_NET}" \
  --arg vrfA "${VRF_A}" --arg vrfB "${VRF_B}" '{pinDir: $pin, galacticPinDir: $gpin, mode: "native",
    guards: [{iface: "hpr80h", prefix: $link}, {iface: "hpr81h", prefix: $link}],
    passThrough: [{vrf: $vrfA, prefix: $link}, {vrf: $vrfB, prefix: $link}]}' | probe_config routed-link)
probe setup "${cfg}" >"${OUT}/logs/setup-routed-link.txt" 2>&1
E="pid:${PID[envoy]}"
for v in 80 81; do
  rig_bg nsenter -t "${PID[envoy]}" -n socat "TCP6-LISTEN:8081,so-bindtodevice=vrf${v},fork,reuseaddr" \
    "SYSTEM:read -r l; echo \"\$l\" >>/out/logs/envoy${v}.reads; echo \"\$l envoy${v}\""
done
sleep 1
for v in 80 81; do
  ask "${E}" 2 "TCP6:[${VETH_GUEST}]:8080,so-bindtodevice=vrf${v}" warm >/dev/null
done
# The listeners run as root in the rig, so the rig empties their logs.
rig sh -c ': >/out/logs/envoy80.reads; : >/out/logs/envoy81.reads'
w=h3
cap "${w}" veth80-guest "pid:${PID[veth80]}" eth0
cap "${w}" veth81-guest "pid:${PID[veth81]}" eth0
cap "${w}" link80-host node hpr80h
cap "${w}" link81-host node hpr81h
cap "${w}" envoy "${E}" hpr80p hpr81p
cap "${w}" physical node "${PHYSICAL_IFS[@]}"
cap_wait
for v in 80 81; do
  tag="${NONCE}-h3-${v}"
  answers=$(for i in $(seq 1 "${N}"); do
    ask "${E}" 3 "TCP6:[${VETH_GUEST}]:8080,so-bindtodevice=vrf${v}" "${tag}-${i}"
  done)
  record "${w}" "socket bound to vrf${v} reads vpc${v}'s guest" "${N}" "$(grep -c " vpc${v}\$" <<<"${answers}" || true)"
  o=81
  [ "${v}" = 81 ] && o=80
  record "${w}" "socket bound to vrf${v} reads vpc${o}'s guest" 0 "$(grep -c " vpc${o}\$" <<<"${answers}" || true)"
  tag="${NONCE}-h3-rev-${v}"
  answers=$(for i in $(seq 1 "${N}"); do
    ask "pid:${PID[veth${v}]}" 3 "TCP6:[${LINK_POD}]:8081" "${tag}-${i}"
  done)
  record "${w}" "vpc${v}'s guest is answered by the vrf${v} socket" "${N}" \
    "$(grep -c " envoy${v}\$" <<<"${answers}" || true)"
done
ask "${E}" 3 "TCP6:[${VETH_GUEST}]:9,so-bindtodevice=vrf80" "${NONCE}-h3-deny" >/dev/null
ask "${E}" 2 "TCP6:[${VETH_GUEST}]:8080" "${NONCE}-h3-unbound" >"${OUT}/logs/unbound.txt"
in_pod "${PID[envoy]}" ip -6 addr add fd20:80:ff04::5/128 dev hpr80p nodad
printf '%s\n' "${NONCE}-h3-spoof" | docker exec -i "${RIG}" timeout 3 nsenter -t "${PID[envoy]}" -n \
  socat -u - "UDP6-SENDTO:[${VETH_GUEST}]:8080,bind=[fd20:80:ff04::5],so-bindtodevice=vrf80" || true
in_pod "${PID[envoy]}" ip -6 addr del fd20:80:ff04::5/128 dev hpr80p
probe counters "${cfg}" >"${OUT}/logs/counters-h3.json"
cap_stop
for v in 80 81; do
  o=81
  [ "${v}" = 81 ] && o=80
  record "${w}" "vrf${v} socket reads the guests' lines" "${N}" \
    "$(grep -c "^${NONCE}-h3-rev-${v}-" "${OUT}/logs/envoy${v}.reads" || true)"
  record "${w}" "vpc${v}'s guest receives vrf${v}'s requests" "${N}" \
    "$(count "${w}" "veth${v}-guest" "${NONCE}-h3-${v}" --dst "${VETH_GUEST}")"
  record "${w}" "vpc${o}'s guest receives vrf${v}'s requests" 0 \
    "$(count "${w}" "veth${o}-guest" "${NONCE}-h3-${v}")"
done
record "${w}" "denied TCP 9: crosses the routed link" yes \
  "$(seen "$(count "${w}" link80-host "" --dst "${VETH_GUEST}" --proto tcp --dport 9)")"
record "${w}" "denied TCP 9: reaches no guest" 0 \
  "$(($(count "${w}" veth80-guest "" --proto tcp --dport 9) + $(count "${w}" veth81-guest "" --proto tcp --dport 9)))"
record "${w}" "unbound socket: gets no answer" 0 "$(grep -c . "${OUT}/logs/unbound.txt" || true)"
record "${w}" "unbound socket: reaches no guest" 0 \
  "$(($(count "${w}" veth80-guest "${NONCE}-h3-unbound") + $(count "${w}" veth81-guest "${NONCE}-h3-unbound")))"
record "${w}" "spoofed source: crosses the routed link" yes "$(seen "$(count "${w}" link80-host "${NONCE}-h3-spoof")")"
record "${w}" "spoofed source: reaches no guest" 0 "$(count "${w}" veth80-guest "${NONCE}-h3-spoof")"
record "${w}" "link guard drops the spoofed source" yes "$(seen "$(counter guard_drop <"${OUT}/logs/counters-h3.json")")"
no_trace "${w}" "${NONCE}-h3"
# cleanup (the EXIT trap) removes the rig and the probe, and finishes.
