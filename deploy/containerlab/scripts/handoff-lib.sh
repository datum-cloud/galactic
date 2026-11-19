#!/bin/bash
# handoff-lib.sh: shared setup for the Local handoff checks
# (docs/handoffs.md). Sourced by handoff-observe.sh, handoff-measure.sh and
# handoff-twice.sh, after lib.sh. Needs OUT set before rig_start.
#
# Everything a check touches on the compute node is made by the rig container
# (RIG), which shares the node's network and PID namespaces, or by
# handoff-probe, which runs in the node itself. Removing the rig container
# stops every listener and capture it started.

# shellcheck disable=SC2034 # read by the scripts that source this file
NODE=dfw-worker
CP=$(control_plane dfw)
RIG=handoff-rig
PROBE=/usr/local/bin/handoff-probe
# Not under /tmp: a Kind node's /tmp is a tmpfs, which docker cp cannot reach.
NODE_CFG=/var/lib/handoff-probe
GALACTIC_PIN=/sys/fs/bpf/galactic
FIXTURE_NS=ns80-tap
DEBUG_IMAGE=ghcr.io/datum-cloud/galactic-debug@sha256:b64e338f845d06f82f2575ae6bb6855da330af7551a8816b7ade2602a85722f2

VRF_A=G000000080V
VRF_B=G000000081V
TAP_A=G000000080082H
TAP_B=G000000081082H
VETH_A=G000000080080H
VETH_B=G000000081081H
CLIENT=2001:db8:4144:1::2
CLIENT_NET=2001:db8:4144:1::/64
VIP_A=2001:db8:4144:a::80
VIP_B=2001:db8:4144:a::81
# VIP_A_UNDECIDED reaches the same TAP as VIP_A, but its tc program leaves
# the policy decision to tp_deliver.
VIP_A_UNDECIDED=2001:db8:4144:a::82
SHARD_A=2001:db8:4144:5::80
SHARD_B=2001:db8:4144:5::81
TAP_GUEST=fd20:80:ff03::1:0:0
VETH_GUEST=fd20:80:ff01::1:0:0
LINK_NET=fd20:80:ff04::/127
LINK_POD=fd20:80:ff04::1
# The compute node's physical members: bond0 and bond1, to dfw-worker2 and
# dfw-worker3. A Local handoff must put nothing of a probe on them.
PHYSICAL_IFS=(eth1 eth3 eth2 eth4)

SCRIPT_DIR=${SCRIPT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}
PCAP_COUNT=("python3" "-I" "${SCRIPT_DIR}/handoff-pcap.py")

rig() { docker exec -i "${RIG}" "$@"; }
rig_bg() { docker exec -d "${RIG}" "$@"; }
client() { rig ip netns exec hp-client "$@"; }
probe() { docker exec -i "${NODE}" "${PROBE}" "$@"; }
kc() { docker exec -i "${CP}" kubectl "$@"; }

# pod_pid NAMESPACE APP prints the PID of the ready pod's sandbox on NODE.
pod_pid() {
  local id
  id=$(docker exec "${NODE}" crictl pods --namespace "$1" --label "app=$2" --state ready -q | head -1)
  [ -n "${id}" ] || return 1
  docker exec "${NODE}" crictl inspectp "${id}" | jq -r '.info.pid'
}

# in_pod PID CMD... runs CMD with the rig's tools in the pod's network
# namespace.
in_pod() {
  local pid="$1"
  shift
  rig nsenter -t "${pid}" -n "$@"
}

# listen WHERE NAME ADDRESS REPLY starts a socat listener that answers each
# request line with "<line> REPLY". WHERE is client or pid:N.
listen() {
  local where="$1" addr="$2" reply="$3" run=() log
  case "${where}" in
    client) run=(ip netns exec hp-client) ;;
    pid:*) run=(nsenter -t "${where#pid:}" -n) ;;
  esac
  # socat logs to a file per listener, so a listener that fails to start or
  # dies is on record.
  log=$(printf '%s-%s' "${where#pid:}" "${addr%%,*}" | tr -c 'A-Za-z0-9.-' '_')
  rig_bg "${run[@]}" socat -d -lf "/out/logs/listen-${log}.log" "${addr},fork,reuseaddr" \
    "SYSTEM:read -r l; echo \"\$l ${reply}\""
}

# listen_udp WHERE ADDRESS PORT REPLY starts a UDP echo server
# (handoff-echo.py) that answers each datagram with "<line> REPLY" from
# ADDRESS ("::" for any).
listen_udp() {
  local where="$1" addr="$2" port="$3" reply="$4" run=()
  case "${where}" in
    client) run=(ip netns exec hp-client) ;;
    pid:*) run=(nsenter -t "${where#pid:}" -n) ;;
  esac
  rig_bg "${run[@]}" python3 -I /hp/handoff-echo.py "${addr}" "${port}" "${reply}"
}

# ask WHERE TIMEOUT ADDRESS LINE sends LINE and prints the answer, if any.
ask() {
  local where="$1" t="$2" addr="$3" line="$4" run=()
  case "${where}" in
    client) run=(ip netns exec hp-client) ;;
    pid:*) run=(nsenter -t "${where#pid:}" -n) ;;
  esac
  printf '%s\n' "${line}" | docker exec -i "${RIG}" timeout "$((t + 1))" "${run[@]}" socat -T"${t}" - "${addr}" 2>/dev/null || true
}

# rig_start runs the rig container in NODE's network and PID namespaces,
# with OUT mounted at /out and the scripts at /hp.
rig_start() {
  docker rm -f "${RIG}" >/dev/null 2>&1 || true
  docker run -d --rm --name "${RIG}" --privileged \
    --network "container:${NODE}" --pid "container:${NODE}" \
    -v "${OUT}:/out" -v "${SCRIPT_DIR}:/hp:ro" \
    --entrypoint sleep "${DEBUG_IMAGE}" infinity >/dev/null
  rig mkdir -p /out/.cap /out/pcap /out/logs
}

rig_stop() {
  docker rm -f "${RIG}" >/dev/null 2>&1 || true
}

# probe_install copies the probe binary built from this checkout into NODE.
probe_install() {
  docker cp "$1" "${NODE}:${PROBE}" >/dev/null
  docker exec "${NODE}" mkdir -p "${NODE_CFG}"
}

probe_uninstall() {
  docker exec "${NODE}" rm -rf "${PROBE}" "${NODE_CFG}" 2>/dev/null || true
}

# probe_config NAME writes stdin to NODE as a probe configuration and prints
# its path there. A copy stays in OUT/configs.
probe_config() {
  mkdir -p "${OUT}/configs"
  cat >"${OUT}/configs/$1.json"
  docker exec -i "${NODE}" sh -c "mkdir -p '${NODE_CFG}' && cat >'${NODE_CFG}/$1.json'" <"${OUT}/configs/$1.json"
  echo "${NODE_CFG}/$1.json"
}

# Captures ------------------------------------------------------------------

# cap WINDOW POINT WHERE IFACE... captures every IPv6 packet on each IFACE into
# OUT/pcap/WINDOW/POINT.IFACE.pcap. WHERE is node, client or pid:N.
cap() {
  local window="$1" point="$2" where="$3" iface run=() name
  shift 3
  case "${where}" in
    node) run=() ;;
    client) run=(ip netns exec hp-client) ;;
    pid:*) run=(nsenter -t "${where#pid:}" -n) ;;
  esac
  rig mkdir -p "/out/pcap/${window}"
  for iface in "$@"; do
    name="${window}/${point}.${iface}"
    CAP_LOGS+=("${OUT}/pcap/${name}.log")
    rig_bg sh -c "echo \$\$ >'/out/.cap/${point}.${iface}.pid'; exec timeout 300 ${run[*]} \
      tcpdump -U -n -i '${iface}' -w '/out/pcap/${name}.pcap' ip6 2>'/out/pcap/${name}.log'"
  done
}

# CAP_LOGS lists the logs of the captures started since the last cap_wait.
declare -ga CAP_LOGS=()

# cap_wait waits until every capture started since the last call is
# listening. Each is started asynchronously, so its log may not exist yet.
cap_wait() {
  local log i
  for log in "${CAP_LOGS[@]}"; do
    for i in $(seq 1 50); do
      if grep -q 'listening on' "${log}" 2>/dev/null; then
        break
      fi
      if [ "${i}" -eq 50 ]; then
        echo "capture never started: ${log}" >&2
        cat "${log}" >&2 || true
        return 1
      fi
      sleep 0.2
    done
  done
  CAP_LOGS=()
}

# cap_stop stops every running capture and waits for them to flush.
cap_stop() {
  sleep 1
  rig sh -c 'for f in /out/.cap/*.pid; do [ -e "$f" ] || continue; kill -INT "$(cat "$f")" 2>/dev/null; done
    for i in $(seq 1 50); do
      alive=0
      for f in /out/.cap/*.pid; do [ -e "$f" ] || continue; kill -0 "$(cat "$f")" 2>/dev/null && alive=1; done
      [ "$alive" = 0 ] && break
      sleep 0.2
    done
    rm -f /out/.cap/*.pid' || true
}

# count WINDOW POINT NONCE [handoff-pcap.py options] counts POINT's packets
# that carry NONCE, summed over its interfaces. An empty NONCE matches every
# packet, for checks that match on addresses and ports instead.
count() {
  local window="$1" point="$2" nonce="$3"
  shift 3
  "${PCAP_COUNT[@]}" --nonce "${nonce}" "$@" "${OUT}/pcap/${window}/${point}".*.pcap
}

# answers PATTERN counts the lines of stdin equal to PATTERN's lines.
answered() { grep -cxF -- "$1" || true; }

# counter NAME reads one probe counter from the JSON on stdin.
counter() { jq -r --arg k "$1" '.[$k] // 0'; }

# Runs ----------------------------------------------------------------------

# node_monitors stops the run's tc monitor on NODE and keeps its output,
# with Cilium's view of its devices and its log lines about the TAPs.
node_monitors() {
  local pod
  docker exec "${NODE}" pkill -f "tc -ts monitor" 2>/dev/null || true
  docker exec "${NODE}" cat "${NODE_CFG}/tc-monitor.txt" >"${OUT}/logs/tc-monitor.txt" 2>/dev/null || true
  pod=$(kc -n kube-system get pods -l k8s-app=cilium --field-selector "spec.nodeName=${NODE}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  [ -n "${pod}" ] || return 0
  kc -n kube-system exec "${pod}" -c cilium-agent -- cilium-dbg status --verbose \
    >"${OUT}/logs/cilium-status.txt" 2>&1 || true
  kc -n kube-system logs "${pod}" -c cilium-agent --since=2h 2>/dev/null |
    grep -iE "${TAP_A}|${TAP_B}|devices" >"${OUT}/logs/cilium-taps.log" || true
}

# cni_log keeps galactic-cni's log lines on NODE about the fixture's TAPs and
# stale TAP reclaims, for the run's record.
cni_log() {
  local pod
  pod=$(kc -n galactic-system get pods --field-selector "spec.nodeName=${NODE}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -m1 '^galactic-cni' || true)
  [ -n "${pod}" ] || return 0
  kc -n galactic-system logs "${pod}" --since=2h 2>/dev/null |
    grep -E "${TAP_A}|${TAP_B}|stale|reclaim" >"${OUT}/logs/cni-taps.log" || true
}

# precondition REASON records why a run stopped before changing anything.
precondition() {
  echo "PRECONDITION: $*" | tee "${OUT}/precondition"
  exit 0
}

# handoff_preconditions checks, before any change, that the lab, ns80, the
# fixture and the probe are ready and that no earlier run left anything
# behind. It fills PID with the pods' sandbox PIDs. It installs the probe on
# NODE only to ask it, and removes it again when it stops.
handoff_preconditions() {
  local c k
  for c in "${NODE}" "${CP}"; do
    if [ "$(docker inspect -f '{{.State.Running}}' "${c}" 2>/dev/null || true)" != true ]; then
      precondition "lab container ${c} is not running"
    fi
  done
  [ -x "${HANDOFF_PROBE}" ] || precondition "no probe at ${HANDOFF_PROBE} (task handoff:probe)"
  declare -gA PID
  PID[veth80]=$(pod_pid ns80 vpc-a || true)
  PID[veth81]=$(pod_pid ns80 vpc-b || true)
  PID[tap80]=$(pod_pid "${FIXTURE_NS}" vpc-a-tap || true)
  PID[tap81]=$(pod_pid "${FIXTURE_NS}" vpc-b-tap || true)
  PID[envoy]=$(pod_pid "${FIXTURE_NS}" envoy-standin || true)
  for k in veth80 veth81; do
    [ -n "${PID[${k}]}" ] || precondition "ns80's ${k} guest is not ready on ${NODE} (task deploy:ns80)"
  done
  for k in tap80 tap81 envoy; do
    [ -n "${PID[${k}]}" ] || precondition "the ns80-tap fixture's ${k} pod is not ready on ${NODE} (task deploy:ns80-tap)"
  done
  if docker inspect "${RIG}" >/dev/null 2>&1; then
    precondition "a rig container ${RIG} already exists; an earlier run did not clean up"
  fi
  probe_install "${HANDOFF_PROBE}"
  if ! probe leftovers "${VRF_A}" "${VRF_B}" >"${OUT}/logs/leftovers-before.txt" 2>&1; then
    probe_uninstall
    precondition "an earlier run left probe state behind: $(tr '\n' ';' <"${OUT}/logs/leftovers-before.txt")"
  fi
  local rc=0
  probe check "${GALACTIC_PIN}" >"${OUT}/logs/check.txt" 2>&1 || rc=$?
  if [ "${rc}" -ne 0 ]; then
    probe_uninstall
    [ "${rc}" -eq 3 ] && precondition "the running uSID datapath differs from this checkout: $(tail -1 "${OUT}/logs/check.txt")"
    precondition "the probe cannot load: $(tail -1 "${OUT}/logs/check.txt")"
  fi
}

# handoff_cleanup undoes everything a run placed on NODE, checks that
# nothing is left, and finishes the run. HANDOFF_RESTORE, when set, is run
# first, for state a script changed outside the rig.
handoff_cleanup() {
  local cfg
  set +e
  [ -n "${HANDOFF_RESTORE:-}" ] && "${HANDOFF_RESTORE}"
  cap_stop
  cni_log
  node_monitors
  for cfg in "${OUT}"/configs/*.json; do
    [ -e "${cfg}" ] && probe teardown "${NODE_CFG}/$(basename "${cfg}")" >>"${OUT}/logs/teardown.txt" 2>&1
  done
  rig /hp/handoff-rig.sh down >>"${OUT}/logs/teardown.txt" 2>&1
  rig_stop
  if probe leftovers "${VRF_A}" "${VRF_B}" >"${OUT}/logs/leftovers-after.txt" 2>&1; then
    echo "cleanup: nothing left on ${NODE}"
  else
    echo "cleanup: LEFTOVERS on ${NODE}:" >&2
    cat "${OUT}/logs/leftovers-after.txt" >&2
    FAILED=1
  fi
  probe_uninstall
  handoff_finish
}
# handoff_finish writes results.json and exits with the run's outcome.
handoff_finish() {
  jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
    | {scenario: .[0], check: .[1], expect: .[2], got: .[3], result: .[4]})
    | sort_by(.scenario, .check)' "${OUT}/results.tsv" >"${OUT}/results.json"
  echo "=== $(jq length "${OUT}/results.json") checks, $(jq '[.[] | select(.result == "fail")] | length' \
    "${OUT}/results.json") failed; results in ${OUT}/results.json ==="
  exit "${FAILED}"
}

# json_list A,B prints ["A","B"].
json_list() { jq -cn --arg s "$1" '$s | split(",")'; }

# cell_config NAME MODE PEER-MODE REDIRECT XDP TC VLAN DUT [PUSH] writes one
# rig cell's probe configuration to NODE and prints its path there. PUSH=1
# makes the pair peer push the VLAN tag and redirect to the VLAN's lower
# device when its egress is the rig's VLAN device.
cell_config() {
  local name="$1" mode="$2" peer="$3" redirect="$4" xdp="$5" tc="$6" vlan="$7" dut="$8" push="${9:-0}"
  jq -n --arg mode "${mode}" --arg peer "${peer}" --argjson redirect "${redirect}" \
    --argjson xdp "$(json_list "${xdp}")" --argjson tc "$(json_list "${tc}")" --argjson vlan "${vlan}" \
    --arg dut "${dut}" --arg pin "/sys/fs/bpf/galactic-handoff-proof" --arg gpin "${GALACTIC_PIN}" \
    --arg tapA "${TAP_A}" --arg tapB "${TAP_B}" --arg guest "${TAP_GUEST}" \
    --arg vipA "${VIP_A}" --arg vipB "${VIP_B}" --arg vipU "${VIP_A_UNDECIDED}" \
    --arg shardA "${SHARD_A}" --arg shardB "${SHARD_B}" --arg client "${CLIENT_NET}" \
    --arg vrfA "${VRF_A}" --arg vrfB "${VRF_B}" --argjson push "${push}" '{
      pinDir: $pin, galacticPinDir: $gpin, mode: $mode, peerMode: $peer,
      xdp: $xdp, tc: $tc, vlanID: $vlan,
      vips: [
        {vip: $vipA, tap: $tapA, guest: $guest, decide: true},
        {vip: $vipB, tap: $tapB, guest: $guest, decide: true},
        {vip: $vipU, tap: $tapA, guest: $guest, decide: false}],
      taps: [
        {tap: $tapA, dut: $dut, pair: "hpn80t", peer: "hpn80n", vip: $vipA, clientPrefix: $client},
        {tap: $tapB, dut: $dut, pair: "hpn81t", peer: "hpn81n", vip: $vipB, clientPrefix: $client}],
      pairs: [
        {pair: "hpn80t", peer: "hpn80n", tap: $tapA, guest: $guest, shard: $shardA, redirect: $redirect},
        {pair: "hpn81t", peer: "hpn81n", tap: $tapB, guest: $guest, shard: $shardB, redirect: $redirect}],
      passThrough: [{vrf: $vrfA, prefix: $client}, {vrf: $vrfB, prefix: $client}]}
    | if $push == 1 then .pairs[] += {vlan: {device: "hp-dut0.120", lower: "hp-dut0", vid: 120}} else . end' |
    probe_config "${name}"
}
