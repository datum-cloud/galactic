#!/bin/bash
# verify-bonds.sh — confirm every LACP bond in the lab has actually
# aggregated, on both ends.
#
# A bond whose interface is up is not the same thing as a bond whose members
# are carrying traffic. An 802.3ad member can have carrier and still sit
# outside the aggregate, or in an aggregate of its own if the two ends
# disagree about who they are talking to, and the bond keeps forwarding over
# whichever member is left. Every datapath attached to the missing member then
# goes unexercised without anything failing. So for every member this checks
# what galactic-gateway's own attach gate checks
# (internal/plumbing/ebpf/edgeattach/gate.go): LACP actor state collecting and
# distributing. It also checks that the member count matches the topology and
# that every member joined the bond's active aggregator with a real partner.
#
# Keep BONDS in step with gvpc.clab.yaml's mkbond.sh exec lines and
# node_files/tr*/startup.sh.
set -euo pipefail

LAB="${LAB:-gvpc}"

# container:bond, two members each.
BONDS=(
  dfw-worker:bond0 dfw-worker:bond1
  dfw-worker2:bond0 dfw-worker2:bond1
  dfw-worker3:bond0 dfw-worker3:bond1
  sjc-worker:bond0
  sjc-worker2:bond0 sjc-worker2:bond1
  iad-worker:bond0
  iad-worker2:bond0 iad-worker2:bond1
  "clab-${LAB}-tr1:bond1" "clab-${LAB}-tr1:bond2"
  "clab-${LAB}-tr2:bond1"
  "clab-${LAB}-tr3:bond1"
)
MEMBERS_PER_BOND=2

# IEEE 802.1AX actor state bits: collecting (0x10) and distributing (0x20).
CARRYING=$((0x30))

fail=0
for entry in "${BONDS[@]}"; do
  node="${entry%%:*}"
  bond="${entry##*:}"
  label="${node}:${bond}"

  if ! state=$(docker exec "${node}" cat "/proc/net/bonding/${bond}" 2>/dev/null); then
    echo "FAIL  ${label}: no such bond"
    fail=1
    continue
  fi

  if ! grep -q '^Bonding Mode: IEEE 802.3ad' <<<"${state}"; then
    echo "FAIL  ${label}: not in 802.3ad mode"
    fail=1
    continue
  fi

  # The bond's active aggregator, from the "802.3ad info" block ahead of the
  # first member.
  active_agg=$(awk '/^Slave Interface:/{exit} /Aggregator ID:/{print $3; exit}' <<<"${state}")
  mapfile -t members < <(awk '/^Slave Interface:/{print $3}' <<<"${state}")

  if [ "${#members[@]}" -ne "${MEMBERS_PER_BOND}" ]; then
    echo "FAIL  ${label}: ${#members[@]} member(s) (${members[*]:-none}), want ${MEMBERS_PER_BOND}"
    fail=1
    continue
  fi

  bond_ok=1
  for member in "${members[@]}"; do
    # This member's own block, up to the next member or end of file.
    block=$(awk -v m="${member}" '
      /^Slave Interface:/ { inblock = ($3 == m) }
      inblock' <<<"${state}")
    mii=$(awk '/^MII Status:/{print $3; exit}' <<<"${block}")
    agg=$(awk '/Aggregator ID:/{print $3; exit}' <<<"${block}")
    partner=$(awk '/details partner lacp pdu:/{p=1} p && /system mac address:/{print $4; exit}' <<<"${block}")
    actor=$(docker exec "${node}" ip -d link show dev "${member}" |
      grep -o 'ad_actor_oper_port_state [0-9]*' | awk '{print $2}')

    problems=()
    [ "${mii}" = "up" ] || problems+=("MII ${mii:-unknown}")
    [ "${agg}" = "${active_agg}" ] || problems+=("aggregator ${agg:-none}, bond's active is ${active_agg:-none}")
    [ -n "${partner}" ] && [ "${partner}" != "00:00:00:00:00:00" ] ||
      problems+=("no LACP partner")
    if [ -z "${actor}" ] || [ $((actor & CARRYING)) -ne "${CARRYING}" ]; then
      problems+=("actor state ${actor:-unknown}, not collecting+distributing")
    fi

    if [ "${#problems[@]}" -gt 0 ]; then
      echo "FAIL  ${label} member ${member}: $(IFS=';'; echo "${problems[*]}")"
      bond_ok=0
      fail=1
    fi
  done

  if [ "${bond_ok}" -eq 1 ]; then
    echo "ok    ${label}: ${members[*]} aggregated (aggregator ${active_agg})"
  fi
done

exit "${fail}"
