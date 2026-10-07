#!/bin/bash
# verify-gateway-ingress.sh — prove each site's VIP serves real TCP and UDP
# through every one of the site's gateway nodes, from outside the fabric.
#
# The client is remote-host on tr4, the one host outside every cluster. Each
# site's transit router splits a VIP's traffic across the site's edge nodes by
# hash, so for each gateway node in turn this pins the VIP to that node with a
# temporary /128 on the transit router (more specific than the /64 the edge
# nodes originate) and removes it on exit. Then, per protocol, FLOWS flows from
# distinct source ports, each of which must:
#
#   - draw a reply from an ns60 backend in the VIP's own site (the reply
#     carries the backend's pod name), and
#   - reach that backend with the client's own address as its source. That is
#     DSR's defining property: the gateway encapsulates the client's packet
#     and changes nothing in it.
#
# Across the flows through each node:
#
#   - the node's own galactic_edge_rule_packets_total for the VIP rises. A
#     node whose XDP datapath is gone can still hand a VIP packet to another
#     gateway through an EVPN-installed route and get an answer, so a reply
#     alone does not prove the pinned node served it.
#   - galactic_edge_return_packets_total rises on some gateway in the site:
#     the backend's reply crossed edge_return rather than the kernel's
#     forwarding path, which survives only while conntrack happens to allow
#     it.
#   - no gateway in the site counts a datapath drop, and none drops a packet
#     as ctstate INVALID in KUBE-FORWARD (#554).
#
# Usage:
#   verify-gateway-ingress.sh               every gateway node in every site
#   verify-gateway-ingress.sh --node NODE   one gateway node only
#   verify-gateway-ingress.sh --unpin       remove any leftover pinned route
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
CLIENT="2001:db8:1:40::2"
PORT=80
FLOWS=8
GATEWAY_METRICS_PORT=8081
SITES=(dfw sjc iad)
declare -A VIP=([dfw]=2001:db8:6060:1::1 [sjc]=2001:db8:6060:2::1 [iad]=2001:db8:6060:3::1)
declare -A GATEWAYS=([dfw]="dfw-worker2 dfw-worker3" [sjc]="sjc-worker2" [iad]="iad-worker2")
# "<transit router> <edge node's address on that link> <transit-side bond>"
# for each gateway node; keep in step with gvpc.clab.yaml and
# node_files/tr*/frr.conf.
declare -A UPLINK=(
  [dfw-worker2]="tr1 2001:db8:1:11::2 bond1"
  [dfw-worker3]="tr1 2001:db8:1:12::2 bond2"
  [sjc-worker2]="tr2 2001:db8:1:21::2 bond1"
  [iad-worker2]="tr3 2001:db8:1:32::2 bond1"
)

only=""
case "${1:-}" in
  --node) only="${2:?--node needs a gateway node name}" ;;
  --unpin) ;;
  "") ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

transit() { docker exec "clab-${LAB}-$1" "${@:2}"; }

unpin_all() {
  local site tr
  for site in "${SITES[@]}"; do
    for tr in tr1 tr2 tr3; do
      transit "${tr}" ip -6 route del "${VIP[${site}]}/128" 2>/dev/null || true
    done
  done
}

if [ "${1:-}" = "--unpin" ]; then
  unpin_all
  exit 0
fi
trap 'unpin_all; rm -rf "${work:-}"' EXIT

rc=0
fail() {
  echo "  FAIL $*" >&2
  rc=1
}

# metric NODE NAME VIP sums NAME's samples labelled with VIP on NODE.
metric() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${GATEWAY_METRICS_PORT}/metrics" |
    awk -v name="$2" -v vip="vip=\"$3\"" \
      'index($0, name"{") == 1 && index($0, vip) {s += $NF} END {print s + 0}'
}

drops() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${GATEWAY_METRICS_PORT}/metrics" |
    awk '/^galactic_edge_drops_total/ {s += $NF} END {print s + 0}'
}

# invalid NODE is KUBE-FORWARD's ctstate INVALID drop count, matched on the
# rule's text: kube-proxy owns the chain and its order.
invalid() {
  docker exec "$1" ip6tables -t filter -L KUBE-FORWARD -n -v -x 2>/dev/null |
    awk '/ctstate INVALID/ {print $1; exit}' | grep . || echo 0
}

# expand6 ADDR prints ADDR as eight four-digit groups, the form socat reports
# a peer in, so the two can be compared.
expand6() {
  local addr="$1" head tail groups=() g missing
  if [[ "${addr}" == *::* ]]; then
    head=${addr%%::*}
    tail=${addr##*::}
    local h=() t=()
    [ -n "${head}" ] && IFS=: read -ra h <<<"${head}"
    [ -n "${tail}" ] && IFS=: read -ra t <<<"${tail}"
    missing=$((8 - ${#h[@]} - ${#t[@]}))
    groups=("${h[@]}")
    for _ in $(seq "${missing}"); do groups+=(0); done
    groups+=("${t[@]}")
  else
    IFS=: read -ra groups <<<"${addr}"
  fi
  for g in "${groups[@]}"; do printf '%04x:' "0x${g}"; done | sed 's/:$//'
  echo
}

# Prometheus counters are floats, so compare in awk.
rose() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(b > a)}'; }

# request PROTO VIP SPORT prints the backend's one-line answer, or nothing.
# socat's own errors go to ${work}/socat.err.
request() {
  local addr
  case "$1" in
    tcp) addr="TCP6:[$2]:${PORT},sourceport=$3,reuseaddr" ;;
    udp) addr="UDP6:[$2]:${PORT},sourceport=$3,reuseaddr" ;;
  esac
  echo probe | docker exec -i "clab-${LAB}-remote-host" \
    timeout 5 socat -t2 -T3 - "${addr}" 2>"${work}/socat.err" | head -1 || true
}

# A random source-port base per run, so the flows are new ones: a port an
# earlier run used can still be in TIME_WAIT on the client.
sport=$((20000 + RANDOM % 30000))
work=$(mktemp -d)

checked=0
for site in "${SITES[@]}"; do
  cp=$(control_plane "${site}")
  vip=${VIP[${site}]}
  backends=$(pod_names "${cp}" ns60 app=backend)
  if [ -z "${backends}" ]; then
    fail "${site}: no ns60 backend pod (run deploy:ns60)"
    continue
  fi

  for gw in ${GATEWAYS[${site}]}; do
    [ -z "${only}" ] || [ "${only}" = "${gw}" ] || continue
    checked=$((checked + 1))
    read -r tr nexthop dev <<<"${UPLINK[${gw}]}"
    echo "--- ${site}: ${vip} through ${gw} (pinned on ${tr}) ---"
    transit "${tr}" ip -6 route replace "${vip}/128" via "${nexthop}" dev "${dev}"

    declare -A was_ret=() was_drp=() was_inv=()
    for n in ${GATEWAYS[${site}]}; do
      was_ret[${n}]=$(metric "${n}" galactic_edge_return_packets_total "${vip}")
      was_drp[${n}]=$(drops "${n}")
      was_inv[${n}]=$(invalid "${n}")
    done
    was_fwd=$(metric "${gw}" galactic_edge_rule_packets_total "${vip}")

    for proto in tcp udp; do
      answered=0
      for _ in $(seq "${FLOWS}"); do
        sport=$((sport + 1))
        read -r pod peer <<<"$(request "${proto}" "${vip}" "${sport}")"
        peer=${peer#[}
        peer=${peer%]}
        if [ -z "${pod:-}" ]; then
          fail "${proto} from port ${sport}: no reply$(sed -n '1s/^.*socat\[[0-9]*\] [A-Z] / (client: /p' "${work}/socat.err" | sed 's/$/)/')"
        elif ! grep -qw -- "${pod}" <<<"${backends}"; then
          fail "${proto} from port ${sport}: answered by '${pod}', not one of ${site}'s backends (${backends})"
        elif [ "$(expand6 "${peer}")" != "$(expand6 "${CLIENT}")" ]; then
          fail "${proto} from port ${sport}: ${pod} saw the client as '${peer}', want ${CLIENT}"
        else
          answered=$((answered + 1))
        fi
      done
      echo "  ${proto}: ${answered}/${FLOWS} flows answered by ${site}'s backends, client address intact"
    done

    now_fwd=$(metric "${gw}" galactic_edge_rule_packets_total "${vip}")
    if rose "${was_fwd}" "${now_fwd}"; then
      echo "  ok   ${gw} matched the VIP (rule packets ${was_fwd} -> ${now_fwd})"
    else
      fail "${gw} never matched the VIP (galactic_edge_rule_packets_total ${was_fwd} -> ${now_fwd}):" \
        "its XDP datapath did not see the traffic"
    fi

    returned=""
    for n in ${GATEWAYS[${site}]}; do
      now=$(metric "${n}" galactic_edge_return_packets_total "${vip}")
      rose "${was_ret[${n}]}" "${now}" && returned="${returned} ${n}"
      now=$(drops "${n}")
      if rose "${was_drp[${n}]}" "${now}"; then
        fail "${n} counted datapath drops (galactic_edge_drops_total ${was_drp[${n}]} -> ${now})"
      fi
      now=$(invalid "${n}")
      if [ "${now}" -gt "${was_inv[${n}]}" ]; then
        fail "${n} dropped $((now - was_inv[${n}])) packet(s) as ctstate INVALID: a reply took the" \
          "kernel's forwarding path instead of edge_return (#554)"
      fi
    done
    if [ -n "${returned}" ]; then
      echo "  ok   replies forwarded by edge_return on${returned}"
    else
      fail "no gateway in ${site} counted a reply (galactic_edge_return_packets_total did not move)"
    fi

    transit "${tr}" ip -6 route del "${vip}/128"
  done
done

if [ "${checked}" -eq 0 ]; then
  echo "FAIL: no gateway node named ${only}" >&2
  exit 2
fi
if [ "${rc}" -ne 0 ]; then
  echo "FAIL: a VIP did not serve TCP and UDP through every gateway node" >&2
  exit 1
fi
echo "PASS: every VIP served TCP and UDP through each of its site's gateway nodes"
