#!/bin/bash
# handoff-measure.sh: measure the Local handoffs' MTU limits and their
# behavior under GRO, GSO and checksum offload (docs/handoffs.md), on the
# same fixture and rig as handoff-observe.sh.
#
# Usage: handoff-measure.sh OUTDIR
#
# For native XDP and for generic XDP with a native veth peer:
#
#   mtu        UDP to a VIP at 1200 and 1451 bytes (with its newline, the
#              largest unfragmented payload at MTU 1500), and at 1452 and
#              4000 bytes, which the sender fragments
#   bulk       1 MiB over TCP each way, through local.tap and through
#              local.veth_pair, with the client's checksum offload (and so
#              TSO) off, then on
#   pod-veth   NAT flows from ns80's veth guest through an internal veth
#              pair, with the guest's own checksum offload on, then off
#
# Then the receiving device at MTU 9000: whether each mode attaches, and
# what becomes of 4000- and 8000-byte packets for a TAP at MTU 1500.
#
# Expectations are set only where the result is a requirement; the rest are
# recorded observations, compared between runs like any other row.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
OUT=${1:?usage: handoff-measure.sh OUTDIR}
mkdir -p "${OUT}/logs"
OUT=$(cd "${OUT}" && pwd)
: >"${OUT}/results.tsv"
: >"${OUT}/volatile.tsv"
rm -f "${OUT}/precondition"
source "${SCRIPT_DIR}/baseline-lib.sh"
source "${SCRIPT_DIR}/handoff-lib.sh"

REPO=$(cd "${SCRIPT_DIR}/../../.." && pwd)
HANDOFF_PROBE=${HANDOFF_PROBE:-${REPO}/bin/handoff-probe}
SHARD_V=2001:db8:4144:5::180
VETH_TX=""

handoff_preconditions

# restore_guest puts the veth guest's checksum offload back as it was.
restore_guest() {
  if [ -n "${VETH_TX}" ]; then
    in_pod "${PID[veth80]}" ethtool -K eth0 tx "${VETH_TX}" >/dev/null 2>&1 || true
  fi
}
HANDOFF_RESTORE=restore_guest
trap handoff_cleanup EXIT

rig_start
rig /hp/handoff-rig.sh client-up
VETH_TX=$(in_pod "${PID[veth80]}" ethtool -k eth0 | awk '/^tx-checksumming:/ {print $2}')
volatile veth-guest-tx "${VETH_TX}"
rig sh -c 'head -c 1048576 /dev/urandom >/out/blob'
BLOB_SHA=$(sha256sum <"${OUT}/blob" | cut -c1-16)

listen_udp "pid:${PID[tap80]}" "${VIP_A}" 7 tap80
rig_bg nsenter -t "${PID[tap80]}" -n socat TCP6-LISTEN:8081,fork,reuseaddr "SYSTEM:sha256sum | cut -c1-16"
listen_udp client :: 7 client
rig_bg ip netns exec hp-client socat TCP6-LISTEN:8082,fork,reuseaddr "SYSTEM:cat /out/blob"
sleep 1

# udp_to_vip BYTES: does a BYTES-long line to VIP_A get tap80's answer?
udp_to_vip() {
  local line
  line="${NONCE:-m}-$(head -c "$1" /dev/zero | tr '\0' x)"
  line=${line:0:$1}
  seen "$(ask client 3 "UDP6:[${VIP_A}]:7" "${line}" | grep -c ' tap80$' || true)"
}

bulk_h1() {
  docker exec "${RIG}" sh -c "ip netns exec hp-client timeout 30 socat -T10 - TCP6:[${VIP_A}]:8081 </out/blob" 2>/dev/null || true
}

bulk_h2() {
  docker exec "${RIG}" sh -c "timeout 30 nsenter -t ${PID[tap80]} -n socat -T10 -u TCP6:[${CLIENT}]:8082 - | sha256sum | cut -c1-16" 2>/dev/null || true
}

veth_flows() {
  local i n=0
  for i in 1 2 3; do
    n=$((n + $(ask "pid:${PID[veth80]}" 2 "UDP6:[${CLIENT}]:7" "veth-${i}" | grep -c ' client$' || true)))
  done
  echo "${n}"
}

# A cell's configuration plus the veth guest's pair (hpv80t, hpv80n).
measure_config() {
  local name="$1"
  shift
  local json
  cell_config "${name}" "$@" >/dev/null
  json=$(jq --arg veth "${VETH_A}" --arg guest "${VETH_GUEST}" --arg shard "${SHARD_V}" --arg client "${CLIENT_NET}" \
    --arg dut "$(jq -r '.taps[0].dut' "${OUT}/configs/${name}.json")" '
      .taps += [{tap: $veth, dut: $dut, pair: "hpv80t", peer: "hpv80n", vip: "2001:db8:4144:a::ff",
                 clientPrefix: $client}]
      | .pairs += [{pair: "hpv80t", peer: "hpv80n", tap: $veth, guest: $guest, shard: $shard, redirect: true}]' \
    "${OUT}/configs/${name}.json")
  # probe_config rewrites the file jq just read, so it gets the output only
  # once jq is done.
  printf '%s\n' "${json}" | probe_config "${name}"
}

features() {
  local f="${OUT}/logs/features-$1.txt" i
  for i in hp-dut0 "${TAP_A}" hpn80t hpn80n hpv80t; do
    echo "## ${i}" >>"${f}"
    rig ethtool -k "${i}" >>"${f}" 2>&1 || true
  done
  echo "## client hp-cl0" >>"${f}"
  client ethtool -k hp-cl0 >>"${f}" 2>&1 || true
}

NONCE="hm$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"
volatile nonce "${NONCE}"

for c in "native native" "generic native"; do
  read -r mode peer <<<"${c}"
  name="${mode}"
  [ "${mode}" = generic ] && name="generic-native-peer"
  for tx in off on; do
    m="${name}-client-tx-${tx}"
    echo "=== ${m} ==="
    dut=$(rig env CLIENT_TX="${tx}" /hp/handoff-rig.sh dut-up plain | tail -1)
    rig /hp/handoff-rig.sh pairs-up on >/dev/null
    rig /hp/handoff-rig.sh vpair-up
    cfg=$(measure_config "${m}" "${mode}" "${peer}" true hp-dut0 hp-dut0 0 "${dut}")
    probe setup "${cfg}" >"${OUT}/logs/setup-${m}.txt" 2>&1
    features "${m}"
    ask client 2 "UDP6:[${VIP_A}]:7" warm >/dev/null
    ask "pid:${PID[tap80]}" 2 "UDP6:[${CLIENT}]:7" warm >/dev/null
    ask "pid:${PID[veth80]}" 2 "UDP6:[${CLIENT}]:7" warm >/dev/null
    if [ "${tx}" = off ]; then
      # A line of N bytes is an N+1-byte payload: 1451 is the largest that
      # travels unfragmented at MTU 1500. The larger ones are fragmented by
      # the client.
      for size in 1200 1451; do
        record "mtu/${name}" "UDP ${size}+1 bytes to a VIP is answered" yes "$(udp_to_vip "${size}")"
      done
      for size in 1452 4000; do
        record "mtu/${name}" "UDP ${size}+1 bytes, fragmented, to a VIP is answered" - "$(udp_to_vip "${size}")"
      done
    fi
    want=-
    [ "${tx}" = off ] && want=yes
    got=$(bulk_h1)
    record "bulk/${m}" "1 MiB client to VIP arrives intact" "${want}" "$([ "${got}" = "${BLOB_SHA}" ] && echo yes || echo no)"
    got=$(bulk_h2)
    record "bulk/${m}" "1 MiB client to guest through the pair arrives intact" "${want}" \
      "$([ "${got}" = "${BLOB_SHA}" ] && echo yes || echo no)"
    if [ "${tx}" = off ]; then
      for vtx in on off; do
        in_pod "${PID[veth80]}" ethtool -K eth0 tx "${vtx}" >/dev/null
        want=-
        [ "${vtx}" = off ] && want=3
        record "pod-veth/${name}" "veth guest with checksum offload ${vtx}: NAT flows answered" "${want}" "$(veth_flows)"
      done
      restore_guest
    fi
    probe counters "${cfg}" >"${OUT}/logs/counters-${m}.json"
    record "bulk/${m}" "largest frame XDP saw" - "$(counter max_seen_len <"${OUT}/logs/counters-${m}.json")"
    probe teardown "${cfg}" >>"${OUT}/logs/teardown.txt" 2>&1
    rig /hp/handoff-rig.sh vpair-down
    rig /hp/handoff-rig.sh pairs-down
    rig /hp/handoff-rig.sh dut-down
  done
done

# MTU 9000 on the receiving device; the TAP stays at 1500.
for mode in native generic; do
  m="jumbo-${mode}"
  echo "=== ${m} ==="
  dut=$(rig /hp/handoff-rig.sh dut-up plain 9000 | tail -1)
  rig /hp/handoff-rig.sh pairs-up on >/dev/null
  cfg=$(cell_config "${m}" "${mode}" native true hp-dut0 hp-dut0 0 "${dut}")
  if probe setup "${cfg}" >"${OUT}/logs/setup-${m}.txt" 2>&1; then
    record "mtu/${m}" "XDP attaches at MTU 9000" - yes
    record "mtu/${m}" "UDP 1451+1 bytes at MTU 9000 to a TAP at 1500 is answered" yes "$(udp_to_vip 1451)"
    for size in 1452 4000 8000; do
      record "mtu/${m}" "unfragmented UDP ${size}+1 bytes at MTU 9000 to a TAP at 1500 is answered" - \
        "$(udp_to_vip "${size}")"
    done
    probe counters "${cfg}" >"${OUT}/logs/counters-${m}.json"
    record "mtu/${m}" "largest frame XDP saw" - "$(counter max_seen_len <"${OUT}/logs/counters-${m}.json")"
  else
    record "mtu/${m}" "XDP attaches at MTU 9000" - no
    volatile "setup-${m}" "$(tail -1 "${OUT}/logs/setup-${m}.txt")"
  fi
  probe teardown "${cfg}" >>"${OUT}/logs/teardown.txt" 2>&1 || true
  rig /hp/handoff-rig.sh pairs-down
  rig /hp/handoff-rig.sh dut-down
done
