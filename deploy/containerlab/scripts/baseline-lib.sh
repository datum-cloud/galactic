#!/bin/bash
# baseline-lib.sh: capture and result helpers for baseline-observe.sh.
# Sourced, not executed. Needs lib.sh and LAB, OUT already set.
#
# A capture point is one or more interfaces read together, because a flow's
# bond member or ECMP next hop can change between runs while the link it
# crosses does not. Each interface streams a pcap back over `docker exec` or
# `kubectl exec`, so nothing is left on a node.

# Capture targets:
#   node:CONTAINER                     a lab container (Kind node, transit router, remote-host)
#   pod:SITE/NAMESPACE/POD             a pod's own network namespace
#   netns:SITE/NAMESPACE/POD/NETNS     a named network namespace inside POD's mount namespace
target_exec() {
  local target="$1"
  shift
  local kind=${target%%:*} rest=${target#*:}
  case "${kind}" in
    node) docker exec -i "${rest}" "$@" ;;
    pod)
      IFS=/ read -r site ns pod <<<"${rest}"
      docker exec -i "$(control_plane "${site}")" kubectl exec -i -n "${ns}" "${pod}" -- "$@"
      ;;
    netns)
      IFS=/ read -r site ns pod netns <<<"${rest}"
      docker exec -i "$(control_plane "${site}")" kubectl exec -i -n "${ns}" "${pod}" -- ip netns exec "${netns}" "$@"
      ;;
    *)
      echo "target_exec: unknown target ${target}" >&2
      return 2
      ;;
  esac
}

# The capture filter on every interface. BGP, BFD and neighbour discovery
# run on every link all the time and say nothing about the paths under test.
CAPTURE_FILTER='not (tcp port 179 or udp port 3784 or udp port 4784 or (icmp6 and ip6[40] >= 133 and ip6[40] <= 137))'

declare -ga CAP_PIDS=() CAP_STOPS=()

# cap_start SCENARIO POINT TARGET IFACE [IFACE...]
# Starts one tcpdump per interface. Their pcaps land in
# ${OUT}/pcap/SCENARIO/POINT.IFACE.pcap.
cap_start() {
  local scenario="$1" point="$2" target="$3"
  shift 3
  local dir="${OUT}/pcap/${scenario}" iface file
  mkdir -p "${dir}"
  for iface in "$@"; do
    file="${dir}/${point}.${iface}.pcap"
    target_exec "${target}" timeout 300 tcpdump -U -n -i "${iface}" -w - "${CAPTURE_FILTER}" \
      >"${file}" 2>"${file}.log" &
    CAP_PIDS+=($!)
    CAP_STOPS+=("${target}|${iface}|${file}")
  done
}

# cap_ready waits until every running capture reports it is listening, so
# no probe is sent before its first capture point is armed.
cap_ready() {
  local entry file i
  for entry in "${CAP_STOPS[@]}"; do
    file=${entry##*|}
    for i in $(seq 1 50); do
      grep -q 'listening on' "${file}.log" 2>/dev/null && break
      if [ "${i}" -eq 50 ]; then
        echo "capture never started: ${file}" >&2
        cat "${file}.log" >&2 || true
        return 1
      fi
      sleep 0.2
    done
  done
}

# cap_stop_all stops every capture started since the last call, waits for
# each to flush and exit, and clears the list.
cap_stop_all() {
  local entry target iface pid
  sleep 1
  for entry in "${CAP_STOPS[@]}"; do
    IFS='|' read -r target iface _ <<<"${entry}"
    target_exec "${target}" pkill -INT -f "tcpdump -U -n -i ${iface} -w -" >/dev/null 2>&1 || true
  done
  for pid in "${CAP_PIDS[@]}"; do
    wait "${pid}" 2>/dev/null || true
  done
  CAP_PIDS=()
  CAP_STOPS=()
}

# hits SCENARIO POINT REGEX counts decoded packets at POINT whose tcpdump
# line matches REGEX (grep -E), summed across POINT's interfaces. Matching
# the decoded text sees inside SRv6 encapsulation, which tcpdump prints as
# "IP6 outer > outer: IP6 inner > inner: ...".
hits() {
  local scenario="$1" point="$2" regex="$3" f n total=0
  for f in "${OUT}/pcap/${scenario}/${point}".*.pcap; do
    [ -s "${f}" ] || continue
    n=$(tcpdump -nn -r "${f}" 2>/dev/null | grep -cE -- "${regex}" || true)
    total=$((total + n))
  done
  echo "${total}"
}

# record SCENARIO CHECK EXPECT GOT appends one stable result row. EXPECT is
# a number, "yes"/"no", or "-" for a recorded observation with no
# expectation. Only stable values may be recorded here; anything that
# changes run to run (ports, nonces, timestamps, MACs) goes to volatile.
# FAILED is read by baseline-observe.sh, which sources this file.
# shellcheck disable=SC2034
FAILED=0
# shellcheck disable=SC2034
record() {
  local scenario="$1" check="$2" expect="$3" got="$4" ok=pass
  if [ "${expect}" != "-" ] && [ "${expect}" != "${got}" ]; then
    ok=fail
    FAILED=1
  fi
  [ "${expect}" = "-" ] && ok=observed
  printf '%s\t%s\t%s\t%s\t%s\n' "${scenario}" "${check}" "${expect}" "${got}" "${ok}" >>"${OUT}/results.tsv"
  printf '  %-8s %-14s %-58s want %-4s got %s\n' "${ok}" "${scenario}" "${check}" "${expect}" "${got}"
}

# seen N prints "yes" when N > 0.
seen() { [ "$1" -gt 0 ] && echo yes || echo no; }

# volatile KEY VALUE records a run-specific detail outside results.json.
volatile() {
  printf '%s\t%s\n' "$1" "$2" >>"${OUT}/volatile.tsv"
}
