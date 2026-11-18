#!/bin/bash
# baseline-observe.sh: observe today's remote paths on the dedicated-placement
# fixture (resources/tenants/ns80, docs/baseline.md) in both directions, with
# packet captures at every capture point, and write the results.
#
# Usage: baseline-observe.sh OUTDIR
#
# Scenarios, each in its own capture window:
#
#   cross-node-a/-b  ICMPv6 between the dfw and sjc guests of vpc-a, then vpc-b
#   nat66, nat64     both dfw guests fetch from remote-host at once, with one
#                    identical source port, through dfw's egress shards
#   gateway-ipv6/-ipv4
#                    remote-host to dfw's VIPs through dfw-worker2, answered
#                    by ns60's backends with direct server return
#   isolation        UDP to the overlapping address from each VPC's sjc guest:
#                    only the same VPC's dfw guest may receive it
#
# OUTDIR gets results.json (stable fields only, compared between runs),
# volatile.tsv (ports, nonces and other per-run values), pcap/<scenario>/
# and logs/. Exits non-zero when any expectation fails.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
OUT=${1:?usage: baseline-observe.sh OUTDIR}
mkdir -p "${OUT}/logs"
OUT=$(cd "${OUT}" && pwd)
: >"${OUT}/results.tsv"
: >"${OUT}/volatile.tsv"
source "${SCRIPT_DIR}/baseline-lib.sh"
trap cap_stop_all EXIT

NS=ns80
DFW_CP=$(control_plane dfw)
SJC_CP=$(control_plane sjc)
DFW_ADDR=fd20:80:ff01::1:0:0
SJC_ADDR=fd20:80:ff02::1:0:0
CLIENT6=2001:db8:1:40::2
CLIENT4=11.1.40.2
# remote-host's IPv4 address as each side writes it in IPv6: under the lab
# shards' NAT64 prefix for egress (resources/galactic-nat/), and under
# 64:ff9b::/96 as a gateway backend sees an IPv4 client.
EGRESS_NAT64=2001:db8:64::b01:2802
BACKEND_SEES4=64:ff9b::b01:2802
PINGS=5
PROBES=5

# Capture points shared by several scenarios. Each sums every member of the
# link it names (see baseline-lib.sh).
TR1="node:clab-${LAB}-tr1"
TR2="node:clab-${LAB}-tr2"
REMOTE="node:clab-${LAB}-remote-host"
DFW_COMPUTE_IFS=(eth1 eth3 eth2 eth4) # bonds to dfw-worker2 and dfw-worker3
SJC_COMPUTE_IFS=(eth1 eth2)           # bond to sjc-worker2
DFW_EDGE_UPLINKS=(eth1 eth6 eth5 eth7) # tr1's members facing dfw-worker2 and dfw-worker3
SJC_EDGE_UPLINKS=(eth1 eth5)           # tr2's members facing sjc-worker2

pod_of() { pod_name "$1" "${NS}" "app=$2"; }
host_if() { printf 'G%09s%03sH' "$1" "$2" | tr ' ' '0'; }

echo "=== fixture ==="
declare -A POD
for site in dfw sjc; do
  cp=$(control_plane "${site}")
  for app in vpc-a vpc-b; do
    pod=$(pod_of "${cp}" "${app}")
    if [ -z "${pod}" ]; then
      echo "no ${NS} ${app} pod in ${site}: run task deploy:ns80" >&2
      exit 1
    fi
    POD[${site}-${app}]=${pod}
    record fixture "${site} ${app} guest on compute worker" "${site}-worker" "$(pod_scheduling_node "${cp}" "${NS}" "${pod}")"
  done
  a=$(pod_ip6 "${cp}" "${NS}" "${POD[${site}-vpc-a]}")
  b=$(pod_ip6 "${cp}" "${NS}" "${POD[${site}-vpc-b]}")
  want=${DFW_ADDR}
  [ "${site}" = sjc ] && want=${SJC_ADDR}
  record fixture "${site} vpc-a guest address" "${want}" "${a}"
  record fixture "${site} vpc-b guest address equals vpc-a's" "${a}" "${b}"
done

# ---------------------------------------------------------------------------
# Cross-node workload delivery, per VPC: dfw guest <-> sjc guest.
cross_node() {
  local vpc="$1" id="$2" sc="cross-node-${1#vpc-}"
  local dfw_pod=${POD[dfw-${vpc}]} sjc_pod=${POD[sjc-${vpc}]}
  echo "=== ${sc} ==="
  # One unrecorded echo each way first, so neighbour resolution and route
  # warm-up never land inside the counted window.
  docker exec "${DFW_CP}" kubectl exec -n "${NS}" "${dfw_pod}" -- ping -6 -c 1 -W 2 "${SJC_ADDR}" >/dev/null 2>&1 || true
  docker exec "${SJC_CP}" kubectl exec -n "${NS}" "${sjc_pod}" -- ping -6 -c 1 -W 2 "${DFW_ADDR}" >/dev/null 2>&1 || true

  cap_start "${sc}" dfw-guest "pod:dfw/${NS}/${dfw_pod}" eth0
  cap_start "${sc}" dfw-veth-host "node:dfw-worker" "$(host_if "${id}" "${id}")"
  cap_start "${sc}" dfw-compute-underlay "node:dfw-worker" "${DFW_COMPUTE_IFS[@]}"
  cap_start "${sc}" dfw-edge-uplink "${TR1}" "${DFW_EDGE_UPLINKS[@]}"
  cap_start "${sc}" sjc-edge-uplink "${TR2}" "${SJC_EDGE_UPLINKS[@]}"
  cap_start "${sc}" sjc-compute-underlay "node:sjc-worker" "${SJC_COMPUTE_IFS[@]}"
  cap_start "${sc}" sjc-veth-host "node:sjc-worker" "$(host_if "${id}" "${id}")"
  cap_start "${sc}" sjc-guest "pod:sjc/${NS}/${sjc_pod}" eth0
  cap_ready

  local out_ab out_ba
  out_ab=$(docker exec "${DFW_CP}" kubectl exec -n "${NS}" "${dfw_pod}" -- \
    ping -6 -c "${PINGS}" -i 0.2 -W 2 "${SJC_ADDR}" 2>&1 || true)
  out_ba=$(docker exec "${SJC_CP}" kubectl exec -n "${NS}" "${sjc_pod}" -- \
    ping -6 -c "${PINGS}" -i 0.2 -W 2 "${DFW_ADDR}" 2>&1 || true)
  cap_stop_all
  printf '%s\n%s\n' "${out_ab}" "${out_ba}" >"${OUT}/logs/${sc}.ping.log"

  record "${sc}" "dfw->sjc echo replies" "${PINGS}" "$(sed -nE 's/.* ([0-9]+) (packets )?received.*/\1/p' <<<"${out_ab}")"
  record "${sc}" "sjc->dfw echo replies" "${PINGS}" "$(sed -nE 's/.* ([0-9]+) (packets )?received.*/\1/p' <<<"${out_ba}")"

  local fwd="${DFW_ADDR} > ${SJC_ADDR}: ICMP6, echo request"
  local rev="${SJC_ADDR} > ${DFW_ADDR}: ICMP6, echo request"
  local point
  # Each direction's requests, at every point on the path. Points marked
  # "-" are recorded but carry no expectation (docs/baseline.md).
  for point in dfw-guest sjc-guest dfw-edge-uplink sjc-edge-uplink; do
    record "${sc}" "${point} dfw->sjc requests" "${PINGS}" "$(hits "${sc}" "${point}" "${fwd}")"
    record "${sc}" "${point} sjc->dfw requests" "${PINGS}" "$(hits "${sc}" "${point}" "${rev}")"
  done
  # A host veth carries its guest's outbound packets. Inbound ones arrive by
  # bpf_redirect_peer straight into the guest's side of the pair
  # (internal/plumbing/ebpf/prog/usid.c), which tcpdump on the host side
  # never sees, so those are recorded without an expectation.
  record "${sc}" "dfw-veth-host dfw->sjc requests" "${PINGS}" "$(hits "${sc}" dfw-veth-host "${fwd}")"
  record "${sc}" "sjc-veth-host sjc->dfw requests" "${PINGS}" "$(hits "${sc}" sjc-veth-host "${rev}")"
  record "${sc}" "dfw-veth-host sjc->dfw requests (peer redirect)" - "$(hits "${sc}" dfw-veth-host "${rev}")"
  record "${sc}" "sjc-veth-host dfw->sjc requests (peer redirect)" - "$(hits "${sc}" sjc-veth-host "${fwd}")"
  for point in dfw-compute-underlay sjc-compute-underlay; do
    record "${sc}" "${point} dfw->sjc requests" - "$(hits "${sc}" "${point}" "${fwd}")"
    record "${sc}" "${point} sjc->dfw requests" - "$(hits "${sc}" "${point}" "${rev}")"
  done
}
cross_node vpc-a 80
cross_node vpc-b 81

# ---------------------------------------------------------------------------
# NAT66 and NAT64 egress: both dfw guests, one identical source port and
# destination, at once. The shard must give them distinct translated tuples
# and return each reply to the guest that sent it.
SHARDS6=$(docker exec "${DFW_CP}" kubectl -n galactic-system get egressshard -o jsonpath='{.items[*].status.shardAddressIPv6}')
SHARDS4=$(docker exec "${DFW_CP}" kubectl -n galactic-system get egressshard -o jsonpath='{.items[*].status.shardAddressIPv4}')
volatile shards "${SHARDS6} ${SHARDS4}"

nat_scenario() {
  local sc="$1" url_host="$2" seen_dst="$3" shards="$4"
  local port=$((40000 + RANDOM % 20000))
  volatile "${sc}.guest_source_port" "${port}"
  echo "=== ${sc} ==="
  local dfw_a=${POD[dfw-vpc-a]} dfw_b=${POD[dfw-vpc-b]}
  cap_start "${sc}" dfw-guest-a "pod:dfw/${NS}/${dfw_a}" eth0
  cap_start "${sc}" dfw-guest-b "pod:dfw/${NS}/${dfw_b}" eth0
  cap_start "${sc}" dfw-veth-host-a "node:dfw-worker" "$(host_if 80 80)"
  cap_start "${sc}" dfw-veth-host-b "node:dfw-worker" "$(host_if 81 81)"
  cap_start "${sc}" dfw-compute-underlay "node:dfw-worker" "${DFW_COMPUTE_IFS[@]}"
  cap_start "${sc}" public "${TR1}" "${DFW_EDGE_UPLINKS[@]}"
  cap_start "${sc}" peer "${REMOTE}" eth1
  cap_ready

  local fetch="curl -sS -o /dev/null -w %{http_code} --max-time 5 --local-port ${port} http://[${url_host}]/"
  docker exec "${DFW_CP}" kubectl exec -n "${NS}" "${dfw_a}" -- sh -c "${fetch}" >"${OUT}/logs/${sc}.a.code" 2>&1 &
  local pa=$!
  docker exec "${DFW_CP}" kubectl exec -n "${NS}" "${dfw_b}" -- sh -c "${fetch}" >"${OUT}/logs/${sc}.b.code" 2>&1 &
  local pb=$!
  wait "${pa}" || true
  wait "${pb}" || true
  cap_stop_all

  record "${sc}" "vpc-a fetch status" 200 "$(tail -c 3 "${OUT}/logs/${sc}.a.code")"
  record "${sc}" "vpc-b fetch status" 200 "$(tail -c 3 "${OUT}/logs/${sc}.b.code")"

  local g=${DFW_ADDR}
  local out_re="${g}\.${port} > ${url_host}\.80: Flags \[S\]"
  local back_re="${url_host}\.80 > ${g}\.${port}: Flags \[S\.\]"
  local p
  for p in a b; do
    record "${sc}" "dfw-guest-${p} SYN out" yes "$(seen "$(hits "${sc}" "dfw-guest-${p}" "${out_re}")")"
    record "${sc}" "dfw-guest-${p} SYN-ACK back" yes "$(seen "$(hits "${sc}" "dfw-guest-${p}" "${back_re}")")"
    record "${sc}" "dfw-veth-host-${p} SYN out" yes "$(seen "$(hits "${sc}" "dfw-veth-host-${p}" "${out_re}")")"
    record "${sc}" "dfw-veth-host-${p} SYN-ACK back (peer redirect)" - "$(seen "$(hits "${sc}" "dfw-veth-host-${p}" "${back_re}")")"
  done
  record "${sc}" "dfw-compute-underlay SYN out" - "$(seen "$(hits "${sc}" dfw-compute-underlay "${out_re}")")"
  record "${sc}" "dfw-compute-underlay SYN-ACK back" - "$(seen "$(hits "${sc}" dfw-compute-underlay "${back_re}")")"

  # On the public side the guest address is gone: each SYN to the peer
  # carries a shard's masquerade address and a port the shard chose.
  local syn_re="> ${seen_dst}\.80: Flags \[S\]," synack_re="${seen_dst}\.80 > .*: Flags \[S\.\],"
  record "${sc}" "public SYN out" yes "$(seen "$(hits "${sc}" public "${syn_re}")")"
  record "${sc}" "public SYN-ACK back" yes "$(seen "$(hits "${sc}" public "${synack_re}")")"
  local tuples
  tuples=$(for f in "${OUT}/pcap/${sc}"/peer.*.pcap; do tcpdump -nn -r "${f}" 2>/dev/null; done |
    { grep -E "${syn_re}" || true; } | sed -nE 's/^.* IP6? ([^ ]+) > .*/\1/p' | sort -u)
  volatile "${sc}.translated_tuples" "$(paste -sd' ' <<<"${tuples}")"
  record "${sc}" "peer distinct translated tuples" 2 "$(grep -c . <<<"${tuples}" || true)"
  local leaked=no in_shards=yes t
  for t in ${tuples}; do
    [[ "${t}" == "${g}".* ]] && leaked=yes
    [[ " ${shards} " == *" ${t%.*} "* ]] || in_shards=no
  done
  record "${sc}" "peer sees guest address" no "${leaked}"
  record "${sc}" "peer sources are shard addresses" yes "${in_shards}"
  record "${sc}" "peer SYN-ACK sent" yes "$(seen "$(hits "${sc}" peer "${synack_re}")")"
}
nat_scenario nat66 "${CLIENT6}" "${CLIENT6}" "${SHARDS6}"
nat_scenario nat64 "${EGRESS_NAT64}" "${CLIENT4}" "${SHARDS4}"

# ---------------------------------------------------------------------------
# Gateway ingress over IPv6 and IPv4, through dfw-worker2. The lab's own
# checks drive the flows and assert replies, backend identity and DSR; the
# captures add what each point saw.
DFW_BACKEND_IFS=$(docker exec "${DFW_CP}" kubectl get vpcattachment -n ns60 -o json |
  jq -r '.items[] | select(.status.node == "dfw-worker") | .status.hostInterface' | sort | paste -sd' ')
mapfile -t DFW_BACKENDS < <(docker exec "${DFW_CP}" kubectl get pods -n ns60 -l app=backend -o json |
  jq -r '.items[] | select(.spec.nodeName == "dfw-worker") | .metadata.name' | sort)
# backend_hits SCENARIO REGEX sums REGEX over every dfw backend's eth0.
backend_hits() {
  local i total=0
  for i in "${!DFW_BACKENDS[@]}"; do
    total=$((total + $(hits "$1" "backend-guest-${i}" "$2")))
  done
  echo "${total}"
}
gateway_scenario() {
  local sc="$1" script="$2" vip="$3" client="$4" backend_client="$5" peer_capture="$6"
  echo "=== ${sc} ==="
  # verify-gateway-ingress-ipv4.sh captures on remote-host itself and stops
  # every tcpdump there, ours included, so its own client-side checks stand
  # in for the peer capture point.
  [ "${peer_capture}" = yes ] && cap_start "${sc}" peer "${REMOTE}" eth1
  cap_start "${sc}" public "${TR1}" "${DFW_EDGE_UPLINKS[@]}"
  cap_start "${sc}" dfw-compute-underlay "node:dfw-worker" "${DFW_COMPUTE_IFS[@]}"
  # shellcheck disable=SC2086 # one interface per backend attachment
  cap_start "${sc}" backend-veth-host "node:dfw-worker" ${DFW_BACKEND_IFS}
  local i
  for i in "${!DFW_BACKENDS[@]}"; do
    cap_start "${sc}" "backend-guest-${i}" "pod:dfw/ns60/${DFW_BACKENDS[${i}]}" eth0
  done
  cap_ready
  local rc=0
  LAB=${LAB} "${SCRIPT_DIR}/${script}" --node dfw-worker2 >"${OUT}/logs/${sc}.log" 2>&1 || rc=$?
  cap_stop_all
  # The lab's ingress checks intermittently lose a TCP flow whose request
  # reached a backend: the ns60 responder closes without writing a reply
  # (docs/baseline.md). So the exact flow counts and the check's exit status
  # are per-run values; the stable result is that each protocol had answered
  # flows, which shows delivery in both directions.
  volatile "${sc}.check_exit" "${rc}"
  local proto answered
  for proto in tcp udp; do
    answered=$(sed -nE "s/^  ${proto}: ([0-9]+)\/[0-9]+ flows answered.*/\1/p" "${OUT}/logs/${sc}.log" | head -1)
    volatile "${sc}.${proto}_flows_answered" "${answered:-0}/8"
    record "${sc}" "${proto} flows answered by a backend" yes "$(seen "${answered:-0}")"
  done
  local in_re="${client}\.[0-9]+ > ${vip}\.80:" out_re="${vip}\.80 > ${client}\.[0-9]+:"
  if [ "${peer_capture}" = yes ]; then
    record "${sc}" "peer requests out" yes "$(seen "$(hits "${sc}" peer "${in_re}")")"
    record "${sc}" "peer replies back" yes "$(seen "$(hits "${sc}" peer "${out_re}")")"
  fi
  record "${sc}" "public requests in" yes "$(seen "$(hits "${sc}" public "${in_re}")")"
  record "${sc}" "public replies out" yes "$(seen "$(hits "${sc}" public "${out_re}")")"
  record "${sc}" "backend-guest requests from client" yes \
    "$(seen "$(backend_hits "${sc}" "${backend_client}\.[0-9]+ > ")")"
  record "${sc}" "backend-guest replies to client" yes \
    "$(seen "$(backend_hits "${sc}" "> ${backend_client}\.[0-9]+:")")"
  record "${sc}" "backend-veth-host replies to client" yes \
    "$(seen "$(hits "${sc}" backend-veth-host "> ${backend_client}\.[0-9]+:")")"
  record "${sc}" "backend-veth-host requests from client (peer redirect)" - \
    "$(seen "$(hits "${sc}" backend-veth-host "${backend_client}\.[0-9]+ > ")")"
  record "${sc}" "dfw-compute-underlay requests" - "$(seen "$(hits "${sc}" dfw-compute-underlay "${in_re}")")"
}
gateway_scenario gateway-ipv6 verify-gateway-ingress.sh 2001:db8:6060:1::1 "${CLIENT6}" "${CLIENT6}" yes
gateway_scenario gateway-ipv4 verify-gateway-ingress-ipv4.sh 198.51.100.1 "${CLIENT4}" "${BACKEND_SEES4}" no

# ---------------------------------------------------------------------------
# Negative isolation control. Each VPC's sjc guest sends PROBES datagrams to
# the address both dfw guests hold. Only the dfw guest in the sender's VPC
# may see them; the other VPC's guest, and its host veth, must see none.
echo "=== isolation ==="
sc=isolation
iport=$((20000 + RANDOM % 10000))
nonce=$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')
volatile isolation.udp_port "${iport}"
volatile isolation.nonce "${nonce}"
cap_start "${sc}" dfw-guest-a "pod:dfw/${NS}/${POD[dfw-vpc-a]}" eth0
cap_start "${sc}" dfw-guest-b "pod:dfw/${NS}/${POD[dfw-vpc-b]}" eth0
cap_start "${sc}" dfw-veth-host-a "node:dfw-worker" "$(host_if 80 80)"
cap_start "${sc}" dfw-veth-host-b "node:dfw-worker" "$(host_if 81 81)"
cap_ready
# A different source port per VPC, so each one's probes are told apart at
# the receiving end.
declare -A SPORT=([a]=$((iport + 1)) [b]=$((iport + 2)))
for from in a b; do
  for i in $(seq 1 "${PROBES}"); do
    echo "${nonce}-${from}-${i}" | docker exec -i "${SJC_CP}" kubectl exec -i -n "${NS}" "${POD[sjc-vpc-${from}]}" -- \
      socat -u - "UDP6-SENDTO:[${DFW_ADDR}]:${iport},sourceport=${SPORT[${from}]},reuseaddr" || true
    sleep 0.1
  done
done
cap_stop_all
for to in a b; do
  for from in a b; do
    sp=${SPORT[${from}]}
    want=0
    [ "${from}" = "${to}" ] && want=${PROBES}
    re="${SJC_ADDR}\.${sp} > ${DFW_ADDR}\.${iport}: UDP"
    record "${sc}" "dfw-guest-${to} receives from vpc-${from}" "${want}" "$(hits "${sc}" "dfw-guest-${to}" "${re}")"
    # Inbound, so delivered by peer redirect past the host veth: recorded
    # only. The guest's own eth0 is the isolation evidence.
    record "${sc}" "dfw-veth-host-${to} carries from vpc-${from} (peer redirect)" - "$(hits "${sc}" "dfw-veth-host-${to}" "${re}")"
  done
done

# ---------------------------------------------------------------------------
jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
  | {scenario: .[0], check: .[1], expect: .[2], got: .[3], result: .[4]})
  | sort_by(.scenario, .check)' "${OUT}/results.tsv" >"${OUT}/results.json"
total=$(jq length "${OUT}/results.json")
failed=$(jq '[.[] | select(.result == "fail")] | length' "${OUT}/results.json")
echo "=== ${total} checks, ${failed} failed; results in ${OUT}/results.json ==="
exit "${FAILED}"
