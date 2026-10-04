#!/bin/bash
# verify-mss-clamp.sh — prove full-size TCP segments cross the fabric.
#
# Every lab link is 1500 bytes and the fabric adds a 40-byte outer IPv6
# header, so a pod whose own interface is 1500 bytes advertises an MSS the
# path cannot carry. The uSID datapath clamps the MSS in each SYN to fit:
# 1400 for IPv6 tenants, 1420 for IPv4. Without it, small requests work and
# every full-size segment is dropped, which is why this checks bulk
# transfers rather than a ping or a small page.
#
#   1. Every galactic-cni node reports the clamp sized for a 1500-byte fabric.
#   2. From each site's IPv6-only tenant, a 1 MiB download from the
#      off-fabric host completes over NAT64 and NAT66, the host sees MSS 1400
#      in the SYN, and the site's shard drops nothing for being too big.
#   3. A 3 MB transfer between two sites completes for an IPv6 (ns10) and an
#      IPv4 (ns20) tenant.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The clamp for a 1500-byte fabric: 1500 minus the 40-byte outer header,
# the inner IP header, and 20 bytes of TCP.
WANT_V4=1420
WANT_V6=1400
CNI_METRICS_PORT=9180
NAT_METRICS_PORT=9182
CNI_NODES=(dfw-worker dfw-worker2 dfw-worker3 sjc-worker sjc-worker2 iad-worker iad-worker2)
SITES=(dfw sjc iad)
declare -A FIRST_SHARD=([dfw]=dfw-worker2 [sjc]=sjc-worker2 [iad]=iad-worker2)

REMOTE=clab-gvpc-remote-host
HOST6="2001:db8:1:40::2"
# 11.1.40.2 synthesized into the fabric's NAT64 prefix.
HOST4_SYNTH="2001:db8:64::b01:2802"
LARGE=large.bin
LARGE_BYTES=1048576
XFER_BYTES=3000000

rc=0
fail() { echo "  FAIL $*" >&2; rc=1; }

running_pod() {
  docker exec "$(control_plane "$1")" kubectl -n "$2" get pods \
    --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'
}

in_pod() {
  local site="$1" ns="$2" pod="$3"
  shift 3
  docker exec "$(control_plane "${site}")" kubectl -n "${ns}" exec "${pod}" -- "$@"
}

frag_drops() {
  docker exec "$1" curl -s --max-time 4 "http://localhost:${NAT_METRICS_PORT}/metrics" \
    | awk '/^galactic_nat_drops_total\{reason="fib_frag_needed"\}/ {print $2; found=1} END {if (!found) print 0}'
}

echo "--- 1. clamp configured on every galactic-cni node ---"
for node in "${CNI_NODES[@]}"; do
  metrics=$(docker exec "${node}" curl -s --max-time 4 "http://localhost:${CNI_METRICS_PORT}/metrics" || true)
  v4=$(awk -F' ' '/^galactic_usid_tcp_mss_clamp_limit_bytes\{family="ipv4"\}/ {print $2}' <<<"${metrics}")
  v6=$(awk -F' ' '/^galactic_usid_tcp_mss_clamp_limit_bytes\{family="ipv6"\}/ {print $2}' <<<"${metrics}")
  if [ "${v4}" = "${WANT_V4}" ] && [ "${v6}" = "${WANT_V6}" ]; then
    echo "  ok   ${node}: ipv4 ${v4}, ipv6 ${v6}"
  else
    fail "${node}: clamp is ipv4 '${v4:-missing}', ipv6 '${v6:-missing}', want ${WANT_V4} and ${WANT_V6}"
  fi
done

# Created by the remote host's startup script; recreated here so a lab
# brought up before that existed needs no restart.
docker exec "${REMOTE}" sh -c "[ -s /var/www/localhost/htdocs/${LARGE} ] || head -c ${LARGE_BYTES} /dev/urandom > /var/www/localhost/htdocs/${LARGE}"

echo "--- 2. 1 MiB through each site's egress shard ---"
for site in "${SITES[@]}"; do
  pod=$(running_pod "${site}" ns10)
  shard=${FIRST_SHARD[${site}]}

  # A pod that once received an ICMPv6 Packet Too Big caches a lower MTU on
  # its route and advertises a smaller MSS on its own, which would pass this
  # check without the clamp doing anything.
  if in_pod "${site}" ns10 "${pod}" ip -6 route show default | grep -q ' mtu '; then
    fail "${site}: ${pod}'s default route carries a cached MTU, so it proves nothing about the clamp; delete the pod and re-run"
    continue
  fi

  before=$(frag_drops "${shard}")
  capture=$(mktemp)
  docker exec "${REMOTE}" timeout 30 tcpdump -i eth1 -nn -v -c 2 \
    'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst port 80' >"${capture}" 2>/dev/null &
  dumper=$!
  sleep 2

  for target in "NAT64 [${HOST4_SYNTH}]" "NAT66 [${HOST6}]"; do
    label=${target%% *}
    addr=${target#* }
    got=$(in_pod "${site}" ns10 "${pod}" curl -sS -o /dev/null -w '%{size_download}' --max-time 15 \
      "http://${addr}/${LARGE}" 2>/dev/null || true)
    if [ "${got}" = "${LARGE_BYTES}" ]; then
      echo "  ok   ${site} ${label}: ${got} bytes"
    else
      fail "${site} ${label}: received '${got:-0}' of ${LARGE_BYTES} bytes"
    fi
  done
  wait "${dumper}" || true

  mss=$(grep -oE 'mss [0-9]+' "${capture}" | awk '{print $2}' | sort -u | tr '\n' ' ')
  rm -f "${capture}"
  if [ "${mss}" = "${WANT_V6} " ]; then
    echo "  ok   ${site}: the off-fabric host saw MSS ${WANT_V6}"
  else
    fail "${site}: the off-fabric host saw MSS '${mss:-none}', want ${WANT_V6}"
  fi

  after=$(frag_drops "${shard}")
  if [ "${after}" = "${before}" ]; then
    echo "  ok   ${site}: ${shard} dropped nothing for size (fib_frag_needed ${after})"
  else
    fail "${site}: ${shard}'s fib_frag_needed went ${before} -> ${after}"
  fi
done

echo "--- 3. 3 MB between sites ---"
# The listener stops after 6 idle seconds (-T), so a stalled transfer ends
# with a short count instead of hanging this script.
xfer() {
  local ns="$1" from="$2" to="$3" family="$4" addr="$5"
  local srv cli out
  srv=$(running_pod "${to}" "${ns}")
  cli=$(running_pod "${from}" "${ns}")
  out=$(mktemp)
  timeout 40 docker exec "$(control_plane "${to}")" kubectl -n "${ns}" exec "${srv}" -- \
    sh -c "socat -u -T 6 ${family}-LISTEN:5003,reuseaddr - | wc -c" >"${out}" 2>/dev/null &
  local listener=$!
  sleep 2
  timeout 30 docker exec "$(control_plane "${from}")" kubectl -n "${ns}" exec "${cli}" -- \
    sh -c "head -c ${XFER_BYTES} /dev/urandom | timeout 20 socat -u - ${family}:${addr}:5003" >/dev/null 2>&1 || true
  wait "${listener}" || true
  local got
  got=$(tr -d '[:space:]' <"${out}")
  rm -f "${out}"
  if [ "${got}" = "${XFER_BYTES}" ]; then
    echo "  ok   ${ns} ${from} -> ${to}: ${got} bytes"
  else
    fail "${ns} ${from} -> ${to}: received '${got:-0}' of ${XFER_BYTES} bytes"
  fi
}

sjc6=$(pod_ip6 "$(control_plane sjc)" ns10 "$(running_pod sjc ns10)")
sjc4=$(pod_ip4 "$(control_plane sjc)" ns20 "$(running_pod sjc ns20)")
xfer ns10 dfw sjc TCP6 "[${sjc6}]"
xfer ns20 dfw sjc TCP4 "${sjc4}"

if [ "${rc}" -ne 0 ]; then
  echo "FAIL: full-size TCP segments do not cross the fabric" >&2
  exit 1
fi
echo "PASS: full-size TCP segments cross the fabric, to the internet and between sites"
