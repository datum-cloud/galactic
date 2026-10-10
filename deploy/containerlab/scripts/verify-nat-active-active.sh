#!/bin/bash
# verify-nat-active-active.sh — acceptance check for hashed (active/active)
# egress on dfw, the lab's only site with two egress shards (dfw-worker2,
# dfw-worker3). The lab runs ordered mode; this switches dfw's galactic-cni to
# hashed mode for its duration and restores whatever it found at the end,
# whatever happens: the egress environment variables, both shards' drain
# flags, galactic-cni's ClusterRole, every route and address it adds.
#
# Every probe fails unless every request succeeds and every packet arrives at
# the off-fabric host from an expected masquerade address. A probe that sees
# no traffic fails; it never passes vacuously.
#
#    0. Preflight: both shards Ready and Programmed with distinct SIDs and
#       masquerade addresses, each address routed back to its shard from the
#       transit, the EgressShard CRD carrying spec.drain (read back after a
#       write), galactic-cni allowed to watch EgressShards. A self-test then
#       blackholes a fresh tenant address and checks the probe fails.
#    1. Flow hash, pins off: one tenant's TCP and UDP flows use both shards,
#       over NAT66 and NAT64; ICMP works through both families.
#    2. Source hash, default pins: every flow from one tenant address, TCP,
#       UDP and ICMP alike, leaves from one shard per family.
#    3. galactic-cni restart: a download in progress survives it, and every
#       tenant keeps its shard (pins and slot generations survive).
#    4. Local failure [prohibit route]: one shard made unreachable from the
#       compute node by a prohibit route over its locator, which is what the
#       resolver sees when a route goes; this is not BGP. Its tenants move,
#       new tenants go to the survivor, a download on the survivor completes.
#    5. BGP withdrawal [real BGP]: the shard node's FRR stops originating its
#       SID; the compute node learns of it over BGP. Reports how long the
#       group took to drop it, and to take it back after re-origination.
#    6. Drain: a download on the drained shard completes there, the tenant
#       that owns it keeps its shard while it stays active, and fresh tenant
#       addresses all go to the other shard, over NAT66 and NAT64.
#    7. All shards unavailable [prohibit routes]: fresh tenants get nothing,
#       and the drops are counted as group_empty.
#    8. EgressShard watch failure: with its permission revoked and
#       galactic-cni restarted, the watch never syncs, the metric says so,
#       and the groups it published before keep forwarding.
#    9. Rollback: back to ordered mode, no route names a group, the groups
#       are retired, and every tenant leaves from dfw-worker2, the first
#       shard in dfw's list.
#
# SKIP_BGP=1 skips step 5, which waits on real BGP and can take minutes.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

CP=dfw-control-plane
COMPUTE=dfw-worker
REMOTE=clab-gvpc-remote-host
TRANSIT=clab-gvpc-tr4
HOST6=2001:db8:1:40::2
HOST4=11.1.40.2
# HOST4 synthesized into the fabric's NAT64 prefix.
HOST4_SYNTH=2001:db8:64::b01:2802
NAT64_CLASS='nat64:2001:db8:64::/96'
SHARDS=(dfw-worker2-egress dfw-worker3-egress)
SOAK_MB=12
SOAK_BYTES=$((SOAK_MB * 1024 * 1024))
CNI_METRICS=http://localhost:9180/metrics

kc() { docker exec "${CP}" kubectl "$@"; }
log() { echo "$*"; }
die() {
  echo "FAIL: $*" >&2
  exit 1
}

STATE=$(mktemp -d)

# --- shard identities --------------------------------------------------------

declare -A V6 V4 SID NODE
for s in "${SHARDS[@]}"; do
  V6[${s}]=$(kc -n galactic-system get egressshard "${s}" -o jsonpath='{.status.shardAddressIPv6}')
  V4[${s}]=$(kc -n galactic-system get egressshard "${s}" -o jsonpath='{.status.shardAddressIPv4}')
  SID[${s}]=$(kc -n galactic-system get egressshard "${s}" -o jsonpath='{.status.shardSID}')
  NODE[${s}]=$(kc -n galactic-system get egressshard "${s}" -o jsonpath='{.spec.targetRef.name}')
done

shard_of() {
  local s
  for s in "${SHARDS[@]}"; do
    if [ "$1" = "${V6[${s}]}" ] || [ "$1" = "${V4[${s}]}" ]; then
      echo "${s}"
      return
    fi
  done
  echo unknown
}

# locator SHARD prints the /68 covering SHARD's SID and every tenant copy of it.
locator() {
  python3 -c 'import ipaddress,sys; print(ipaddress.IPv6Network(sys.argv[1] + "/68", strict=False))' "${SID[$1]}"
}

# sid64 SHARD prints the /64 the shard's node originates.
sid64() {
  python3 -c 'import ipaddress,sys; print(ipaddress.IPv6Network(sys.argv[1] + "/64", strict=False))' "${SID[$1]}"
}

# --- metrics ------------------------------------------------------------------

metric() {
  docker exec "${COMPUTE}" curl -s --max-time 4 "${CNI_METRICS}" | awk -v m="$1" '$1 == m {print $2}'
}

metric_sum() {
  docker exec "${COMPUTE}" curl -s --max-time 4 "${CNI_METRICS}" |
    awk -v p="$1" 'index($1, p) == 1 {s += $2} END {print s + 0}'
}

wait_metric() { # NAME WANT TIMEOUT
  local deadline=$((SECONDS + $3)) got=""
  while [ ${SECONDS} -lt ${deadline} ]; do
    got=$(metric "$1")
    if [ "${got}" = "$2" ]; then return 0; fi
    sleep 2
  done
  die "$1 = ${got:-missing}, want $2 after $3s"
}

members() { echo "galactic_cni_egress_pool_members{class=\"$1\",state=\"$2\"}"; }

# --- tenants --------------------------------------------------------------------

# Tenant pods on the compute node, as ns/pod.
mapfile -t TENANTS < <(kc get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {.spec.nodeName}{"\n"}{end}' |
  awk -v n="${COMPUTE}" '$2 == n && $1 ~ /^ns[0-9]+\// {print $1}')
[ "${#TENANTS[@]}" -ge 3 ] || die "need at least 3 tenant pods on ${COMPUTE}, found ${#TENANTS[@]}"
FRESH_POD=$(kc -n ns10 get pods -o jsonpath='{.items[0].metadata.name}')
FRESH_POD="ns10/${FRESH_POD}"

pod_exec() {
  local t="$1"
  shift
  kc -n "${t%%/*}" exec "${t#*/}" -- "$@"
}

# pod_netns TENANT prints the network namespace name of TENANT on its node.
pod_netns() {
  local sandbox
  sandbox=$(docker exec "${COMPUTE}" crictl pods --name "${1#*/}" -q | head -1)
  basename "$(docker exec "${COMPUTE}" crictl inspectp "${sandbox}" | grep -m1 -oE '/var/run/netns/cni-[0-9a-f-]+')"
}

FRESH_NETNS=$(pod_netns "${FRESH_POD}")
FRESH_BASE=$(pod_exec "${FRESH_POD}" sh -c "ip -6 -o addr show dev eth0 scope global | awk '{print \$4}' | head -1")
FRESH_BASE=${FRESH_BASE%/*}
FRESH_LEN=96
echo 0 >"${STATE}/fresh_n"

# fresh prints a tenant address no pin has seen: a new address on the fresh
# tenant's interface, inside its attachment prefix, numbered from a counter
# kept in a file because fresh runs in a command substitution. Each is
# removed at exit. A failure to add the address ends the run.
fresh() {
  local n addr
  n=$(($(cat "${STATE}/fresh_n") + 1))
  echo "${n}" >"${STATE}/fresh_n"
  addr=$(python3 -c 'import ipaddress,sys
b = bytearray(ipaddress.IPv6Address(sys.argv[1]).packed)
b[12] = 0x77; b[13] = 0x77; b[14] = int(sys.argv[2]) >> 8; b[15] = int(sys.argv[2]) & 0xff
print(ipaddress.IPv6Address(bytes(b)))' "${FRESH_BASE}" "${n}")
  if ! docker exec "${COMPUTE}" ip netns exec "${FRESH_NETNS}" ip -6 addr add "${addr}/${FRESH_LEN}" dev eth0 nodad >&2; then
    echo "FAIL: could not add fresh tenant address ${addr}" >&2
    kill -TERM $$
    return 1
  fi
  echo "${addr}" >>"${STATE}/fresh"
  echo "${addr}"
}

# --- probes -----------------------------------------------------------------------

# probe KIND TENANT SRC COUNT ALLOWED... sends COUNT probes of KIND (tcp6,
# tcp4, udp6, udp4, icmp6 or icmp4) from TENANT, sourced from SRC (or the
# tenant's own address when SRC is "-"), toward the off-fabric host, and
# checks every one succeeded and arrived from an address in ALLOWED. The
# addresses seen are written to ${STATE}/seen. It fails, with the reason, on
# any failed request, on a capture that did not see every probe, and on any
# unexpected source.
probe() {
  local kind="$1" tenant="$2" src="$3" count="$4"
  shift 4
  local allowed=("$@") dst filter cmd cap ok=0 seen
  local opt_tcp="" opt_udp="" opt_ping=""
  if [ "${src}" != "-" ]; then
    opt_tcp="--interface ${src}" opt_udp="-s ${src}" opt_ping="-I ${src}"
  fi
  case "${kind}" in
    tcp6 | udp6 | icmp6) dst=${HOST6} ;;
    *) dst=${HOST4_SYNTH} ;;
  esac
  case "${kind}" in
    tcp6) filter="ip6 and dst ${HOST6} and tcp dst port 80 and ip6[53] & 0x12 == 0x02" ;;
    tcp4) filter="ip and dst ${HOST4} and tcp dst port 80 and tcp[13] & 0x12 == 0x02" ;;
    udp6) filter="ip6 and dst ${HOST6} and udp dst port 33434" ;;
    udp4) filter="ip and dst ${HOST4} and udp dst port 33434" ;;
    icmp6) filter="icmp6 and dst ${HOST6} and ip6[40] == 128" ;;
    icmp4) filter="icmp and dst ${HOST4} and icmp[0] == 8" ;;
  esac
  case "${kind}" in
    tcp*) cmd="for i in \$(seq ${count}); do curl -s -o /dev/null -w '%{http_code}\n' --max-time 4 ${opt_tcp} 'http://[${dst}]/'; done" ;;
    udp*) cmd="for i in \$(seq ${count}); do echo probe | nc -u -w1 ${opt_udp} ${dst} 33434; done; echo sent" ;;
    icmp*) cmd="ping -6 -c ${count} -i 0.3 -W 2 ${opt_ping} ${dst}" ;;
  esac
  cap="${STATE}/cap.$$"
  docker exec "${REMOTE}" timeout $((count * 4 + 15)) tcpdump -i eth1 -nn -l -c "${count}" "${filter}" >"${cap}" 2>&1 &
  local tcpdump_pid=$!
  sleep 2
  local out
  out=$(pod_exec "${tenant}" sh -c "${cmd}" 2>&1) || true
  local cap_rc=0
  wait "${tcpdump_pid}" || cap_rc=$?
  case "${kind}" in
    tcp*) ok=$(grep -c '^200$' <<<"${out}" || true) ;;
    udp*) ok=${count} ;; # judged by arrival below; UDP has no answer to count
    icmp*) ok=$(sed -n 's/.* \([0-9]*\) received.*/\1/p' <<<"${out}" | head -1) ;;
  esac
  # A TCP or UDP source is printed as address.port; ICMP has no port, and an
  # IPv4 address's last octet must not be taken for one.
  local strip='s/\.[0-9]+$//'
  case "${kind}" in icmp*) strip='s/^//' ;; esac
  seen=$(grep -oE '^[0-9:.]+ IP6? [0-9a-f:.]+ >' "${cap}" | awk '{print $3}' |
    sed -E "${strip}" | sort -u || true)
  local captured
  captured=$(grep -cE '^[0-9:.]+ IP6? ' "${cap}" || true)
  printf '%s\n' "${seen}" | sed '/^$/d' >"${STATE}/seen"
  rm -f "${cap}"
  if [ "${ok:-0}" != "${count}" ]; then
    echo "    ${kind} from ${tenant} (${src}): ${ok:-0}/${count} succeeded" >&2
    probe_diagnostics "${tenant}" "${src}" "${out}"
    return 1
  fi
  if [ "${cap_rc}" -ne 0 ] || [ "${captured}" -lt "${count}" ]; then
    echo "    ${kind} from ${tenant} (${src}): the host saw ${captured}/${count} probes" >&2
    return 1
  fi
  local addr a found
  while read -r addr; do
    [ -n "${addr}" ] || continue
    found=0
    for a in "${allowed[@]}"; do
      if [ "${addr}" = "${a}" ]; then found=1; fi
    done
    if [ "${found}" -eq 0 ]; then
      echo "    ${kind} from ${tenant} (${src}): arrived from ${addr} ($(shard_of "${addr}")), want one of ${allowed[*]}" >&2
      return 1
    fi
  done <"${STATE}/seen"
  return 0
}

# probe_diagnostics prints what a failed probe needs to be understood: the
# tenant's output, whether its source address exists, and how galactic-cni's
# groups stood.
probe_diagnostics() {
  [ -n "${QUIET_DIAG:-}" ] && return 0
  {
    echo "      output: $(tr '\n' ' ' <<<"$3")"
    if [ "$2" != "-" ]; then
      docker exec "${COMPUTE}" ip netns exec "${FRESH_NETNS}" ip -6 -o addr show to "$2/128" |
        awk '{print "      address present: " $4}'
    fi
    docker exec "${COMPUTE}" curl -s --max-time 4 "${CNI_METRICS}" |
      grep -E '^galactic_cni_egress_(pool_members|shard_selections_total|group_routes|shard_watch_synced)' |
      sed 's/^/      /'
  } >&2
}

# expect is probe that ends the run on failure.
expect() {
  probe "$@" || die "$1 probe failed"
}

# seen_count prints how many distinct sources the last probe saw.
seen_count() { wc -l <"${STATE}/seen" | tr -d ' '; }
seen_first() { head -1 "${STATE}/seen"; }

# --- configuration, saved and restored ------------------------------------------

ENV_VARS=(GALACTIC_CNI_EGRESS_MODE GALACTIC_CNI_EGRESS_HASH GALACTIC_CNI_EGRESS_PIN_IDLE GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE)
declare -A SAVED_ENV
env_of() {
  kc -n galactic-system get ds galactic-cni -o json |
    python3 -c 'import json,sys
d = json.load(sys.stdin)
for c in d["spec"]["template"]["spec"]["containers"]:
    if c["name"] == "credential-refresh":
        for e in c.get("env", []):
            if e["name"] == sys.argv[1]: print(e.get("value", "")); sys.exit(0)
print("<unset>")' "$1"
}
for v in "${ENV_VARS[@]}"; do SAVED_ENV[${v}]=$(env_of "${v}"); done
declare -A SAVED_DRAIN
for s in "${SHARDS[@]}"; do
  SAVED_DRAIN[${s}]=$(kc -n galactic-system get egressshard "${s}" -o jsonpath='{.spec.drain}')
done
kc get clusterrole galactic-cni -o json >"${STATE}/clusterrole.json"

# replace_clusterrole [drop-egressshards] replaces galactic-cni's ClusterRole
# with the saved copy, optionally without the egressshards rule.
replace_clusterrole() {
  python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields"): d["metadata"].pop(k, None)
if len(sys.argv) > 2:
    d["rules"] = [r for r in d["rules"] if "egressshards" not in r.get("resources", [])]
json.dump(d, sys.stdout)' "${STATE}/clusterrole.json" "$@" | docker exec -i "${CP}" kubectl replace -f - >/dev/null
}

rollout_cni() {
  kc -n galactic-system rollout status daemonset/galactic-cni --timeout=900s >/dev/null
  # The metrics endpoint answers once the new process has started.
  local deadline=$((SECONDS + 120))
  until [ "$(metric "galactic_cni_egress_mode{mode=\"$1\"}")" = 1 ]; do
    [ ${SECONDS} -lt ${deadline} ] || die "galactic-cni on ${COMPUTE} does not report mode $1"
    sleep 2
  done
}

set_mode() { # MODE HASH PIN_IDLE
  kc -n galactic-system set env daemonset/galactic-cni -c credential-refresh \
    GALACTIC_CNI_EGRESS_MODE="$1" GALACTIC_CNI_EGRESS_HASH="$2" GALACTIC_CNI_EGRESS_PIN_IDLE="$3" \
    GALACTIC_CNI_EGRESS_POOL_MIN_ACTIVE=2 >/dev/null
  rollout_cni "$1"
}

restore_env() {
  local args=() v
  for v in "${ENV_VARS[@]}"; do
    if [ "${SAVED_ENV[${v}]}" = "<unset>" ]; then args+=("${v}-"); else args+=("${v}=${SAVED_ENV[${v}]}"); fi
  done
  kc -n galactic-system set env daemonset/galactic-cni -c credential-refresh "${args[@]}" >/dev/null
}

set_drain() { # SHARD true|false|""
  local value=null
  [ -n "$2" ] && value=$2
  kc -n galactic-system patch egressshard "$1" --type=merge -p "{\"spec\":{\"drain\":${value}}}" >/dev/null
}

PROHIBITED=()
prohibit() {
  docker exec "${COMPUTE}" ip -6 route add prohibit "$1"
  PROHIBITED+=("$1")
}
unprohibit() {
  docker exec "${COMPUTE}" ip -6 route del prohibit "$1" 2>/dev/null || true
}

WITHDRAWN=""
frr() { # SHARD vtysh-args...
  local node pod
  node=${NODE[$1]}
  shift
  pod=$(kc -n galactic-system get pods -o wide | awk -v n="${node}" '/fabric-router/ && $7 == n {print $1}')
  kc -n galactic-system exec "${pod}" -c frr -- vtysh "$@"
}
originate() { # SHARD yes|no
  local no=""
  [ "$2" = no ] && no="no "
  frr "$1" -c 'conf t' -c 'router bgp 65000' -c 'address-family ipv6 unicast' -c "${no}network $(sid64 "$1")" >/dev/null
}

cleanup() {
  local rc=$?
  set +e
  for p in "${PROHIBITED[@]}"; do unprohibit "${p}"; done
  [ -n "${WITHDRAWN}" ] && originate "${WITHDRAWN}" yes
  if [ -f "${STATE}/fresh" ]; then
    while read -r a; do
      docker exec "${COMPUTE}" ip netns exec "${FRESH_NETNS}" ip -6 route del prohibit "${HOST6}/128" from "${a}" 2>/dev/null
      docker exec "${COMPUTE}" ip netns exec "${FRESH_NETNS}" ip -6 addr del "${a}/${FRESH_LEN}" dev eth0 2>/dev/null
    done <"${STATE}/fresh"
  fi
  for s in "${SHARDS[@]}"; do set_drain "${s}" "${SAVED_DRAIN[${s}]}"; done
  replace_clusterrole
  docker exec "${REMOTE}" rm -f /var/www/localhost/htdocs/active-active-soak
  restore_env
  kc -n galactic-system rollout status daemonset/galactic-cni --timeout=900s >/dev/null
  rm -rf "${STATE}"
  exit "${rc}"
}
trap cleanup EXIT
# A failure inside a command substitution (fresh) ends the run with TERM;
# exiting normally on it runs cleanup.
trap 'exit 143' TERM

# --- background download ----------------------------------------------------------

# soak_start TENANT starts a slow download from TENANT and records which shard
# its connection left from. soak_check waits for it and fails unless it
# completed intact.
SOAK_PID=""
SOAK_SHARD=""
soak_start() {
  local cap="${STATE}/soakcap"
  docker exec "${REMOTE}" timeout 20 tcpdump -i eth1 -nn -l -c 1 \
    "ip6 and dst ${HOST6} and tcp dst port 80 and ip6[53] & 0x12 == 0x02" >"${cap}" 2>&1 &
  local tcpdump_pid=$!
  sleep 2
  pod_exec "$1" curl -s -o /dev/null -w '%{size_download} %{exitcode}' --limit-rate 150k --max-time 300 \
    "http://[${HOST6}]/active-active-soak" >"${STATE}/soak" 2>"${STATE}/soak.err" &
  SOAK_PID=$!
  wait "${tcpdump_pid}" || die "could not see the download's connection at the host"
  SOAK_SHARD=$(shard_of "$(grep -oE 'IP6 [0-9a-f:.]+ >' "${cap}" | awk '{print $2}' | sed -E 's/\.[0-9]+$//')")
  [ "${SOAK_SHARD}" != unknown ] || die "the download left from no shard address: $(cat "${cap}")"
}
soak_check() {
  local rc=0 got="" code=""
  wait "${SOAK_PID}" || rc=$?
  read -r got code <"${STATE}/soak" || true
  if [ "${rc}" -ne 0 ] || [ "${got}" != "${SOAK_BYTES}" ] || [ "${code}" != 0 ]; then
    die "$1: the download ended at ${got:-nothing} of ${SOAK_BYTES} bytes (curl ${code:-none}, exec ${rc}): $(cat "${STATE}/soak.err")"
  fi
}

docker exec "${REMOTE}" dd if=/dev/urandom of=/var/www/localhost/htdocs/active-active-soak bs=1M count=${SOAK_MB} 2>/dev/null

# ==================================================================================

log "--- 0. preflight ---"
for s in "${SHARDS[@]}"; do
  for cond in Ready Programmed; do
    st=$(kc -n galactic-system get egressshard "${s}" -o jsonpath="{.status.conditions[?(@.type==\"${cond}\")].status}")
    [ "${st}" = True ] || die "${s} ${cond}=${st:-missing}"
  done
  [ -n "${V6[${s}]}" ] && [ -n "${V4[${s}]}" ] || die "${s} lacks an IPv6 or IPv4 masquerade address"
  frr "${s}" -c "show bgp ipv6 unicast $(sid64 "${s}")" | grep -q best || die "${s}'s SID is not originated"
  docker exec "${TRANSIT}" vtysh -c "show bgp ipv6 unicast ${V6[${s}]}" | grep -q best ||
    die "transit has no route back to ${s}'s ${V6[${s}]}"
  docker exec "${TRANSIT}" vtysh -c "show bgp ipv4 unicast ${V4[${s}]}" | grep -q best ||
    die "transit has no route back to ${s}'s ${V4[${s}]}"
done
if [ "${V6[${SHARDS[0]}]}" = "${V6[${SHARDS[1]}]}" ] || [ "${V4[${SHARDS[0]}]}" = "${V4[${SHARDS[1]}]}" ] ||
  [ "$(sid64 "${SHARDS[0]}")" = "$(sid64 "${SHARDS[1]}")" ]; then
  die "the shards share a SID locator or masquerade address"
fi
schema=$(kc get crd egressshards.network.datumapis.com \
  -o jsonpath='{.spec.versions[?(@.name=="v1alpha1")].schema.openAPIV3Schema.properties.spec.properties.drain.type}')
[ "${schema}" = boolean ] || die "the EgressShard CRD has no spec.drain; install the network CRD that adds it"
set_drain "${SHARDS[1]}" true
[ "$(kc -n galactic-system get egressshard "${SHARDS[1]}" -o jsonpath='{.spec.drain}')" = true ] ||
  die "spec.drain does not persist: the API server pruned it"
set_drain "${SHARDS[1]}" "${SAVED_DRAIN[${SHARDS[1]}]}"
[ "$(kc auth can-i watch egressshards.network.datumapis.com -n galactic-system \
  --as=system:serviceaccount:galactic-system:galactic-cni)" = yes ] || die "galactic-cni may not watch EgressShards"
log "ok   shards distinct and routed back, spec.drain persists, galactic-cni may watch EgressShards"

# Self-test: a blackholed fresh tenant must fail the probe the drain check uses.
a=$(fresh)
docker exec "${COMPUTE}" ip netns exec "${FRESH_NETNS}" ip -6 route add prohibit "${HOST6}/128" from "${a}"
if QUIET_DIAG=1 probe tcp6 "${FRESH_POD}" "${a}" 3 "${V6[@]}" 2>/dev/null; then
  die "self-test: a blackholed tenant passed the probe; the checks below would prove nothing"
fi
docker exec "${COMPUTE}" ip netns exec "${FRESH_NETNS}" ip -6 route del prohibit "${HOST6}/128" from "${a}"
expect tcp6 "${FRESH_POD}" "${a}" 3 "${V6[@]}"
log "ok   self-test: a blackholed fresh tenant fails the probe, the same tenant unblocked passes"

log "--- 1. hashed, flow hash, pins off ---"
set_mode hashed flow 0
wait_metric "$(members nat66 active)" 2 120
wait_metric "$(members "${NAT64_CLASS}" active)" 2 120
for kind in tcp6 tcp4 udp6 udp4; do
  case "${kind}" in *6) allowed=("${V6[@]}") ;; *) allowed=("${V4[@]}") ;; esac
  expect "${kind}" "${FRESH_POD}" - 24 "${allowed[@]}"
  [ "$(seen_count)" = 2 ] || die "24 ${kind} flows from one tenant used $(seen_count) shard(s), want both"
  log "ok   ${kind}: one tenant's flows used both shards"
done
expect icmp6 "${FRESH_POD}" - 4 "${V6[@]}"
expect icmp4 "${FRESH_POD}" - 4 "${V4[@]}"
log "ok   icmp6 and icmp4 answered through a shard"
for s in "${SHARDS[@]}"; do
  base=$(python3 -c 'import ipaddress,sys; b=bytearray(ipaddress.IPv6Address(sys.argv[1]).packed); b[8]&=0xF0; b[9]=0; print(ipaddress.IPv6Address(bytes(b)))' "${SID[${s}]}")
  for class in nat66 "${NAT64_CLASS}"; do
    p=$(metric "galactic_cni_egress_shard_packets_total{class=\"${class}\",shard_sid=\"${base}\"}")
    awk -v p="${p:-0}" 'BEGIN {exit !(p > 0)}' || die "no ${class} packets counted toward ${s}"
  done
done
log "ok   galactic-cni counted NAT66 and NAT64 packets toward both shards"

log "--- 2. hashed, source hash, default pins ---"
set_mode hashed source 2h4m
wait_metric "$(members nat66 active)" 2 120
declare -A SHARD6 SHARD4
for t in "${TENANTS[@]}"; do
  expect tcp6 "${t}" - 6 "${V6[@]}"
  [ "$(seen_count)" = 1 ] || die "${t}'s NAT66 connections left from $(seen_count) addresses, want one"
  SHARD6[${t}]=$(shard_of "$(seen_first)")
  expect tcp4 "${t}" - 6 "${V4[@]}"
  [ "$(seen_count)" = 1 ] || die "${t}'s NAT64 connections left from $(seen_count) addresses, want one"
  SHARD4[${t}]=$(shard_of "$(seen_first)")
  log "ok   ${t}: NAT66 via ${SHARD6[${t}]}, NAT64 via ${SHARD4[${t}]}"
done
expect udp6 "${FRESH_POD}" - 4 "${V6[${SHARD6[${FRESH_POD}]}]}"
expect icmp6 "${FRESH_POD}" - 3 "${V6[${SHARD6[${FRESH_POD}]}]}"
expect udp4 "${FRESH_POD}" - 4 "${V4[${SHARD4[${FRESH_POD}]}]}"
expect icmp4 "${FRESH_POD}" - 3 "${V4[${SHARD4[${FRESH_POD}]}]}"
log "ok   ${FRESH_POD}'s UDP and ICMP leave from the same shard as its TCP, per family"

A=${FRESH_POD}
SHARD_A=${SHARD6[${A}]}
B=""
for t in "${TENANTS[@]}"; do
  if [ "${SHARD6[${t}]}" != "${SHARD_A}" ]; then
    B=${t}
    break
  fi
done
[ -n "${B}" ] || die "every tenant on ${COMPUTE} hashed to ${SHARD_A}; cannot test a failure between shards"
SHARD_B=${SHARD6[${B}]}

log "--- 3. galactic-cni restart keeps sessions and placement ---"
soak_start "${A}"
kc -n galactic-system rollout restart daemonset/galactic-cni >/dev/null
rollout_cni hashed
soak_check "galactic-cni restart"
for t in "${TENANTS[@]}"; do
  expect tcp6 "${t}" - 3 "${V6[${SHARD6[${t}]}]}"
done
log "ok   a download survived the restart and every tenant kept its shard"

log "--- 4. [prohibit route] ${SHARD_B} unreachable from ${COMPUTE} ---"
soak_start "${A}"
[ "${SOAK_SHARD}" = "${SHARD_A}" ] || die "${A}'s download left from ${SOAK_SHARD}, want its pinned ${SHARD_A}"
loc_b=$(locator "${SHARD_B}")
prohibit "${loc_b}"
wait_metric "$(members nat66 active)" 1 30
expect tcp6 "${B}" - 3 "${V6[${SHARD_A}]}"
expect tcp6 "${FRESH_POD}" "$(fresh)" 3 "${V6[${SHARD_A}]}"
soak_check "${SHARD_B} unreachable"
unprohibit "${loc_b}"
wait_metric "$(members nat66 active)" 2 30
log "ok   ${B} moved to ${SHARD_A}, a fresh tenant went there, ${A}'s download on ${SHARD_A} completed"

if [ "${SKIP_BGP:-0}" != 1 ]; then
  log "--- 5. [real BGP] ${SHARD_B}'s SID withdrawn by its node ---"
  WITHDRAWN=${SHARD_B}
  start=${SECONDS}
  originate "${SHARD_B}" no
  wait_metric "$(members nat66 unreachable)" 1 300
  log "     withdrawal reached the group in $((SECONDS - start))s"
  for _ in 1 2 3; do expect tcp6 "${FRESH_POD}" "$(fresh)" 2 "${V6[${SHARD_A}]}"; done
  start=${SECONDS}
  originate "${SHARD_B}" yes
  WITHDRAWN=""
  wait_metric "$(members nat66 active)" 2 300
  log "ok   fresh tenants went to ${SHARD_A} while ${SHARD_B}'s SID was withdrawn; re-origination took $((SECONDS - start))s"
else
  log "--- 5. [real BGP] skipped (SKIP_BGP=1) ---"
fi

log "--- 6. drain ${SHARD_A} ---"
soak_start "${A}"
[ "${SOAK_SHARD}" = "${SHARD_A}" ] || die "${A}'s download left from ${SOAK_SHARD}, want ${SHARD_A}"
set_drain "${SHARD_A}" true
wait_metric "$(members nat66 draining)" 1 60
expect tcp6 "${A}" - 3 "${V6[${SHARD_A}]}"
log "     ${A}, still active, keeps its pin on draining ${SHARD_A}: a busy tenant keeps a shard draining"
for _ in 1 2 3 4; do
  expect tcp6 "${FRESH_POD}" "$(fresh)" 2 "${V6[${SHARD_B}]}"
done
expect tcp4 "${FRESH_POD}" "$(fresh)" 2 "${V4[${SHARD_B}]}"
soak_check "drain"
set_drain "${SHARD_A}" "${SAVED_DRAIN[${SHARD_A}]}"
wait_metric "$(members nat66 draining)" 0 60
log "ok   every fresh tenant went to ${SHARD_B}; ${A}'s download completed on draining ${SHARD_A}"

log "--- 7. [prohibit routes] every shard unavailable ---"
empty_before=$(metric 'galactic_cni_egress_shard_selections_total{result="group_empty"}')
for s in "${SHARDS[@]}"; do prohibit "$(locator "${s}")"; done
wait_metric "$(members nat66 active)" 0 30
if QUIET_DIAG=1 probe tcp6 "${FRESH_POD}" "$(fresh)" 2 "${V6[@]}" 2>/dev/null; then
  die "a fresh tenant reached the internet with every shard unavailable"
fi
empty_after=$(metric 'galactic_cni_egress_shard_selections_total{result="group_empty"}')
awk -v a="${empty_after:-0}" -v b="${empty_before:-0}" 'BEGIN {exit !(a > b)}' ||
  die "the drops were not counted as group_empty (${empty_before:-0} -> ${empty_after:-0})"
for s in "${SHARDS[@]}"; do unprohibit "$(locator "${s}")"; done
wait_metric "$(members nat66 active)" 2 30
expect tcp6 "${FRESH_POD}" "$(fresh)" 2 "${V6[@]}"
log "ok   no egress and group_empty counted while no shard was reachable; egress back once they were"

log "--- 8. EgressShard watch failure ---"
replace_clusterrole drop-egressshards
kc -n galactic-system rollout restart daemonset/galactic-cni >/dev/null
rollout_cni hashed
sleep 15
[ "$(metric galactic_cni_egress_shard_watch_synced)" = 0 ] || die "the watch reports synced without permission"
[ "$(metric 'galactic_cni_egress_pool_enabled{class="nat66"}')" = 1 ] || die "the published group was lost"
for t in "${A}" "${B}"; do expect tcp6 "${t}" - 2 "${V6[@]}"; done
replace_clusterrole
wait_metric galactic_cni_egress_shard_watch_synced 1 300
log "ok   without its watch galactic-cni said so and kept forwarding; the watch synced once permitted again"

log "--- 9. rollback to ordered mode ---"
restore_env
rollout_cni ordered
deadline=$((SECONDS + 180))
until [ "$(metric_sum galactic_cni_egress_group_routes)" = 0 ] &&
  [ "$(metric_sum galactic_cni_egress_pool_enabled)" = 0 ]; do
  [ ${SECONDS} -lt ${deadline} ] || die "routes still name a group, or a group is still enabled, after 180s"
  sleep 3
done
first=${SHARDS[0]}
for t in "${TENANTS[@]}"; do
  expect tcp6 "${t}" - 2 "${V6[${first}]}"
  expect tcp4 "${t}" - 2 "${V4[${first}]}"
done
log "ok   no route names a group, the groups are retired, every tenant is back on ${first}"

echo "PASS: hashed egress on dfw: both shards in both families, restart, local and BGP failure, drain, total outage, watch outage and rollback"
