#!/bin/bash
# verify-gateway-ingress-ipv4.sh — prove each site's IPv4 VIP serves real
# IPv4 TCP and UDP from outside the fabric through every one of the site's
# gateway nodes, to backends that have no IPv4 address at all.
#
# The IPv4 twin of verify-gateway-ingress.sh, built the same way. Workloads
# are IPv6 only: the gateway carries the client's IPv4 packet unchanged
# inside SRv6, and the backend's node translates it to IPv6 without keeping
# state, with the client's address embedded under 64:ff9b::/96 (RFC 6052),
# and translates the reply back to IPv4 from the VIP.
#
# The client is remote-host on tr4 (11.1.40.2). It reaches each IPv4 VIP the
# way it reaches the IPv6 ones: the site's edge nodes originate the VIP's /26
# into the IPv4 underlay, since the gateway's -v4 advertisement is an EVPN
# path the transit never sees. For each gateway node in turn the VIP is
# pinned to that node with a temporary /32 on its site's transit router,
# more specific than that /26, and removed on exit. Then, per protocol,
# FLOWS flows from distinct source ports are sent, each of which must:
#
#   - draw a reply from an ns60 backend in the VIP's own site (the reply
#     carries the backend's pod name and the address it saw the client as);
#   - reach that backend from 64:ff9b::b01:2802, the client's own IPv4
#     address embedded under 64:ff9b::/96: no source NAT and no other
#     translation on the way in;
#   - come back to the client from the VIP. remote-host captures every
#     packet it receives from port 80 while the flows run, and each answered
#     flow's reply must be there from the VIP, with no packet from port 80
#     carrying any other source (a backend's or a node's own address, or an
#     egress shard's masquerade address).
#
# Before sending anything, for each site:
#
#   - tr4, remote-host's only router, has a BGP route covering the VIP;
#   - every IPv4 ServiceVIPBinding galactic-router generated for ns60-tcp and
#     ns60-udp is Bound, at least one per rule per backend, and each names
#     the backend's IPv6 address;
#   - every gateway node in the site reports <node>/IPv4Served True with
#     reason Advertised on both rules.
#
# Across the flows through each node:
#
#   - the pinned node's own galactic_edge_rule_packets_total for the VIP
#     rises: its XDP datapath claimed the traffic;
#   - galactic_edge_return_packets_total for the VIP rises on some gateway in
#     the site: the translated reply crossed edge_return;
#   - no gateway in the site counts a datapath drop, and none drops a packet
#     as ctstate INVALID in KUBE-FORWARD, IPv4 or IPv6 (#554);
#   - the compute node's galactic_usid_drops_total does not rise for any
#     vip_* or service_route_* reason (translation, fragment, checksum-less
#     UDP, or the reply path);
#   - the egress shard on every gateway in the site translates nothing:
#     galactic_nat_packets_total and galactic_nat_session_creates_total stay
#     put, so no source NAT touched the flows.
#
# Pass thresholds, all enforced:
#
#   pins          every gateway node of every checked site pinned once
#   MIN_BACKENDS  at least 2 distinct backends answer per site
#   flows         every one of FLOWS flows per protocol per node answered
#   client        every backend saw the client as 64:ff9b::b01:2802
#   reply source  every reply to the client came from the VIP
#   counters      rule packets rise on the pinned node, return packets
#                 rise in the site
#   drops         0 new gateway drops, 0 new ctstate INVALID drops, 0 new
#                 compute vip_*/service_route_* drops
#   NAT           0 new egress shard packets or sessions in the site
#   bindings      every generated IPv4 binding Bound, one per rule per
#                 backend at least
#   IPv4Served    True/Advertised for every gateway node on both rules
#
# Usage:
#   verify-gateway-ingress-ipv4.sh               every gateway node in every site
#   verify-gateway-ingress-ipv4.sh --node NODE   one gateway node only
#   verify-gateway-ingress-ipv4.sh --unpin       remove any leftover pinned route
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
CLIENT="11.1.40.2"
PORT=80
FLOWS=8
MIN_BACKENDS=2
GATEWAY_METRICS_PORT=8081
CNI_METRICS_PORT=9180
NAT_METRICS_PORT=9182
SITES=(dfw sjc iad)
RULES=(ns60-tcp ns60-udp)
declare -A VIP=([dfw]=198.51.100.1 [sjc]=198.51.100.65 [iad]=198.51.100.129)
declare -A GATEWAYS=([dfw]="dfw-worker2 dfw-worker3" [sjc]="sjc-worker2" [iad]="iad-worker2")
declare -A COMPUTE=([dfw]=dfw-worker [sjc]=sjc-worker [iad]=iad-worker)
# "<transit router> <edge node's IPv4 address on that link> <transit-side
# bond>" for each gateway node; keep in step with gvpc.clab.yaml and
# node_files/tr*/frr.conf.
declare -A UPLINK=(
  [dfw-worker2]="tr1 10.1.11.2 bond1"
  [dfw-worker3]="tr1 10.1.12.2 bond2"
  [sjc-worker2]="tr2 10.1.21.2 bond1"
  [iad-worker2]="tr3 10.1.32.2 bond1"
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
client() { docker exec "clab-${LAB}-remote-host" "$@"; }

unpin_all() {
  local site tr
  for site in "${SITES[@]}"; do
    for tr in tr1 tr2 tr3; do
      transit "${tr}" ip -4 route del "${VIP[${site}]}/32" 2>/dev/null || true
    done
  done
}

stop_capture() { client pkill -x tcpdump 2>/dev/null || true; }

if [ "${1:-}" = "--unpin" ]; then
  unpin_all
  exit 0
fi
trap 'unpin_all; stop_capture; rm -rf "${work:-}"' EXIT

rc=0
fail() {
  echo "  FAIL $*" >&2
  rc=1
}

scrape() { docker exec "$1" curl -s --max-time 4 "http://localhost:$2/metrics"; }

# metric NODE NAME VIP sums NAME's samples labelled with VIP on NODE.
metric() {
  scrape "$1" "${GATEWAY_METRICS_PORT}" |
    awk -v name="$2" -v vip="vip=\"$3\"" \
      'index($0, name"{") == 1 && index($0, vip) {s += $NF} END {print s + 0}'
}

drops() {
  scrape "$1" "${GATEWAY_METRICS_PORT}" |
    awk '/^galactic_edge_drops_total/ {s += $NF} END {print s + 0}'
}

# vip_drops NODE sums the uSID datapath's drops for the reasons an IPv4
# VIP's flows can hit on a backend node: its translation, fragments,
# checksum-less UDP, and the reply's service route.
vip_drops() {
  scrape "$1" "${CNI_METRICS_PORT}" |
    awk '/^galactic_usid_drops_total\{/ && /reason="(vip_|service_route_)/ {s += $NF} END {print s + 0}'
}

# nat NODE sums the egress shard's translated packets and new sessions, every
# family and direction: a flow to the VIP must add nothing to either.
nat() {
  scrape "$1" "${NAT_METRICS_PORT}" |
    awk '/^galactic_nat_(packets|session_creates)_total\{/ {s += $NF} END {print s + 0}'
}

# invalid NODE sums KUBE-FORWARD's ctstate INVALID drop counts for both
# families, matched on the rule's text: kube-proxy owns the chain and its
# order.
invalid() {
  local t n=0 c
  for t in iptables ip6tables; do
    c=$(docker exec "$1" "${t}" -t filter -L KUBE-FORWARD -n -v -x 2>/dev/null |
      awk '/ctstate INVALID/ {print $1; exit}')
    n=$((n + ${c:-0}))
  done
  echo "${n}"
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

# embed4 ADDR prints IPv4 ADDR embedded under 64:ff9b::/96 (RFC 6052).
embed4() {
  local a b c d
  IFS=. read -r a b c d <<<"$1"
  printf '64:ff9b::%x:%x\n' $(((a << 8) | b)) $(((c << 8) | d))
}

# Prometheus counters are floats, so compare in awk.
rose() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(b > a)}'; }

# request PROTO VIP SPORT prints the backend's one-line answer, or nothing.
# socat's own errors go to ${work}/socat.err.
request() {
  local addr
  case "$1" in
    tcp) addr="TCP4:$2:${PORT},sourceport=$3,reuseaddr" ;;
    udp) addr="UDP4:$2:${PORT},sourceport=$3,reuseaddr" ;;
  esac
  echo probe | docker exec -i "clab-${LAB}-remote-host" \
    timeout 5 socat -t2 -T3 - "${addr}" 2>"${work}/socat.err" | head -1 || true
}

# check_route SITE: tr4 holds a BGP route covering SITE's VIP, learned from
# the transit mesh, as it does for the site's IPv6 VIP /64.
check_route() {
  local vip=${VIP[$1]} route
  route=$(transit tr4 ip -4 route show match "${vip}" proto bgp | head -1)
  if [ -n "${route}" ]; then
    echo "  ok   tr4 routes ${vip}: ${route}"
  else
    fail "tr4 has no BGP route to ${vip}: is the site's IPv4 VIP /26 originated by its edge nodes?"
  fi
}

# check_control_plane SITE BACKENDS checks SITE's generated IPv4 bindings and
# every gateway's IPv4Served condition on SITE's rules.
check_control_plane() {
  local site="$1" cp vip rule gw nbackends total bound v6 cond
  cp=$(control_plane "${site}")
  vip=${VIP[${site}]}
  nbackends=$(wc -w <<<"$2")
  for rule in "${RULES[@]}"; do
    read -r total bound v6 <<<"$(docker exec "${cp}" kubectl get servicevipbindings -n galactic-system \
      -l "galactic.datum.net/network-rule=${rule},app.kubernetes.io/managed-by=galactic-router" -o json |
      jq -r --arg vip "${vip}" '
        [.items[] | select(.spec.vipAddress == $vip)]
        | "\(length)"
          + " \(map(select(.status.conditions // [] | any(.type == "Bound" and .status == "True"))) | length)"
          + " \(map(select(.spec.backendAddress // "" | contains(":"))) | length)"')"
    total=${total:-0} bound=${bound:-0} v6=${v6:-0}
    if [ "${total}" -lt "${nbackends}" ] || [ "${bound}" -ne "${total}" ] || [ "${v6}" -ne "${total}" ]; then
      fail "${site}: ${rule} has ${bound}/${total} IPv4 ServiceVIPBindings Bound (${v6} to an IPv6 backend)," \
        "want at least ${nbackends}, all Bound, all IPv6"
    else
      echo "  ok   ${site}: ${rule} has ${bound}/${total} IPv4 ServiceVIPBindings Bound, each to an IPv6 backend"
    fi
    for gw in ${GATEWAYS[${site}]}; do
      cond=$(docker exec "${cp}" kubectl get networkservice -n galactic-system "${rule}" -o json |
        jq -r --arg t "${gw}/IPv4Served" '.status.conditions // [] | map(select(.type == $t))[0] // {} |
          "\(.status // "missing") \(.reason // "-")"')
      if [ "${cond}" = "True Advertised" ]; then
        echo "  ok   ${site}: ${rule} ${gw}/IPv4Served True/Advertised"
      else
        fail "${site}: ${rule} ${gw}/IPv4Served is '${cond}', want 'True Advertised'"
      fi
    done
  done
}

EMBEDDED=$(embed4 "${CLIENT}")

# A random source-port base per run, so the flows are new ones: a port an
# earlier run used can still be in TIME_WAIT on the client.
sport=$((20000 + RANDOM % 30000))
work=$(mktemp -d)

pinned=0
want_pins=0
summary=()
for site in "${SITES[@]}"; do
  cp=$(control_plane "${site}")
  vip=${VIP[${site}]}
  # --node checks one gateway, so a site without it is not checked at all.
  [ -z "${only}" ] || [[ " ${GATEWAYS[${site}]} " == *" ${only} "* ]] || continue
  backends=$(pod_names "${cp}" ns60 app=backend)
  if [ -z "${backends}" ]; then
    fail "${site}: no ns60 backend pod (run deploy:ns60)"
    continue
  fi
  echo "--- ${site}: ${vip} reachability and control plane ---"
  check_route "${site}"
  check_control_plane "${site}" "${backends}"
  declare -A served=()
  site_pins=""

  for gw in ${GATEWAYS[${site}]}; do
    [ -z "${only}" ] || [ "${only}" = "${gw}" ] || continue
    want_pins=$((want_pins + 1))
    read -r tr nexthop dev <<<"${UPLINK[${gw}]}"
    echo "--- ${site}: ${vip} through ${gw} (pinned on ${tr}) ---"
    if ! transit "${tr}" ip -4 route replace "${vip}/32" via "${nexthop}" dev "${dev}"; then
      fail "could not pin ${vip} to ${gw} on ${tr}"
      continue
    fi
    pinned=$((pinned + 1))
    site_pins="${site_pins} ${gw}"

    declare -A was_ret=() was_drp=() was_inv=() was_nat=()
    for n in ${GATEWAYS[${site}]}; do
      was_ret[${n}]=$(metric "${n}" galactic_edge_return_packets_total "${vip}")
      was_drp[${n}]=$(drops "${n}")
      was_inv[${n}]=$(invalid "${n}")
      was_nat[${n}]=$(nat "${n}")
    done
    was_fwd=$(metric "${gw}" galactic_edge_rule_packets_total "${vip}")
    was_vdr=$(vip_drops "${COMPUTE[${site}]}")

    # Every packet the client receives from port 80 while the flows run.
    stop_capture
    client sh -c "tcpdump -i eth1 -nn -l -q 'ip and dst host ${CLIENT} and src port ${PORT}' \
      >/tmp/ingress-ipv4.cap 2>/dev/null &"
    sleep 1

    sports=()
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
        elif [[ "${peer:-}" != *:* ]] || [ "$(expand6 "${peer}")" != "$(expand6 "${EMBEDDED}")" ]; then
          fail "${proto} from port ${sport}: ${pod} saw the client as '${peer:-}', want ${EMBEDDED}"
        else
          answered=$((answered + 1))
          served[${pod}]=1
          sports+=("${sport}")
        fi
      done
      echo "  ${proto}: ${answered}/${FLOWS} flows answered by ${site}'s backends, client seen as ${EMBEDDED}"
    done

    sleep 1
    stop_capture
    client cat /tmp/ingress-ipv4.cap >"${work}/cap" 2>/dev/null || true
    # "<time> IP <src>.<sport> > <dst>.<dport>: ..." per packet.
    others=$(awk -v vip="${vip}" '$2 == "IP" {src = $3; sub(/\.[0-9]+$/, "", src); if (src != vip) print src}' \
      "${work}/cap" | sort -u | tr '\n' ' ')
    if [ -n "${others}" ]; then
      fail "the client got port-${PORT} replies from ${others}instead of only the VIP ${vip}"
    fi
    missing=0
    for p in "${sports[@]}"; do
      grep -q " ${vip}\.${PORT} > ${CLIENT}\.${p}:" "${work}/cap" || missing=$((missing + 1))
    done
    if [ "${missing}" -gt 0 ]; then
      fail "${missing} of ${#sports[@]} answered flows had no reply from ${vip} in the client's capture"
    elif [ "${#sports[@]}" -gt 0 ] && [ -z "${others}" ]; then
      echo "  ok   every one of ${#sports[@]} replies reached the client from ${vip}, and nothing else did"
    fi

    now_fwd=$(metric "${gw}" galactic_edge_rule_packets_total "${vip}")
    if rose "${was_fwd}" "${now_fwd}"; then
      echo "  ok   ${gw} matched the VIP (rule packets ${was_fwd} -> ${now_fwd})"
    else
      fail "${gw} never matched the VIP (galactic_edge_rule_packets_total ${was_fwd} -> ${now_fwd}):" \
        "its XDP datapath did not see the traffic"
    fi

    now_vdr=$(vip_drops "${COMPUTE[${site}]}")
    if rose "${was_vdr}" "${now_vdr}"; then
      fail "${COMPUTE[${site}]} dropped VIP packets (vip_*/service_route_* drops ${was_vdr} -> ${now_vdr})"
    else
      echo "  ok   ${COMPUTE[${site}]} dropped no VIP packet (vip_*/service_route_* drops ${now_vdr})"
    fi

    returned=""
    for n in ${GATEWAYS[${site}]}; do
      now=$(metric "${n}" galactic_edge_return_packets_total "${vip}")
      rose "${was_ret[${n}]}" "${now}" && returned="${returned} ${n} (${was_ret[${n}]} -> ${now})"
      now=$(drops "${n}")
      if rose "${was_drp[${n}]}" "${now}"; then
        fail "${n} counted datapath drops (galactic_edge_drops_total ${was_drp[${n}]} -> ${now})"
      else
        echo "  ok   ${n} counted no datapath drop (galactic_edge_drops_total ${now})"
      fi
      now=$(invalid "${n}")
      if [ "${now}" -gt "${was_inv[${n}]}" ]; then
        fail "${n} dropped $((now - was_inv[${n}])) packet(s) as ctstate INVALID: a reply took the" \
          "kernel's forwarding path instead of edge_return (#554)"
      else
        echo "  ok   ${n} dropped nothing as ctstate INVALID (${now})"
      fi
      now=$(nat "${n}")
      if rose "${was_nat[${n}]}" "${now}"; then
        fail "${n}'s egress shard translated packets during the VIP flows (${was_nat[${n}]} -> ${now})"
      else
        echo "  ok   ${n}'s egress shard translated nothing (packets and sessions ${now})"
      fi
    done
    if [ -n "${returned}" ]; then
      echo "  ok   replies forwarded by edge_return on${returned}"
    else
      fail "no gateway in ${site} counted a reply (galactic_edge_return_packets_total did not move)"
    fi

    transit "${tr}" ip -4 route del "${vip}/32"
  done

  hit=0
  for pod in ${backends}; do
    if [ -n "${served[${pod}]:-}" ]; then
      echo "  ok   ${pod} answered flows to ${vip}"
      hit=$((hit + 1))
    else
      fail "${pod} answered none of the flows to ${vip}: the VIP is not spread across ${site}'s backends"
    fi
  done
  if [ "${hit}" -lt "${MIN_BACKENDS}" ]; then
    fail "${site}: ${hit} backend(s) answered, want at least ${MIN_BACKENDS}"
  fi
  summary+=("${site} ${vip}: pinned${site_pins:- none}; ${hit} backend(s) answered")
  unset served
done

if [ "${want_pins}" -eq 0 ]; then
  echo "FAIL: no gateway node named ${only}" >&2
  exit 2
fi
if [ "${pinned}" -lt "${want_pins}" ]; then
  fail "pinned ${pinned} of ${want_pins} gateway nodes"
fi
echo "--- summary ---"
for line in "${summary[@]}"; do echo "  ${line}"; done
if [ "${rc}" -ne 0 ]; then
  echo "FAIL: an IPv4 VIP did not serve TCP and UDP through every gateway node" >&2
  exit 1
fi
echo "PASS: every IPv4 VIP served TCP and UDP through each of its site's gateway nodes" \
  "(${pinned} nodes pinned), client seen as ${EMBEDDED}, replies from the VIP"
