#!/bin/bash
# The checks pass their conditions to eval in single quotes on purpose.
# shellcheck disable=SC2016
#
# verify-gateway-local.sh: a gateway hands the VIP flows of backends on its
# own node to their TAPs through Galactic Worker's Local handoff, and
# encapsulates toward every other backend (#1438, resources/gateway-local/).
#
# It adds a TAP-backed guest in ns80's VPC 80 on each of dfw's edge nodes,
# dfw-worker2 (w2) and dfw-worker3 (w3), and serves ns80's vpc-a on
# dfw-worker (w1) and vpc-a2 on dfw-worker4 (w4) as VIP backends too. Each
# backend has its own TCP and UDP NetworkServices with an IPv6 and an IPv4
# VIP, so the backend that must answer a request is known; a pool service
# holds all four. It runs galactic-worker on both edge nodes and points both
# gateways at it. Every client is remote-host, outside the fabric.
#
# A request goes through a chosen gateway G as in verify-gateway-ingress.sh:
# a /128 (IPv6) or /32 (IPv4) route on tr1 toward G's uplink address, more
# specific than the site prefixes both edge nodes originate. Steps:
#
#   1. Matrix. For G in dfw-worker2 and dfw-worker3, each backend (Local when
#      it runs on G, Fabric otherwise), each VIP family and TCP and UDP: one
#      request, whose answer must name the backend and the client address it
#      expects (64:ff9b::b01:2802 for IPv4). tcpdump on the backend's host
#      TAP or veth must show the request arrive and the reply leave, and at
#      the client the reply must come from VIP:80. G's rule counter must
#      rise. A Local cell must raise G's galactic_edge_local_handoffs_total
#      and Worker's rx_deliver on G (lt_stats); a Fabric cell must raise
#      neither on either edge node.
#   2. Hook removal (G = dfw-worker2). local_rx comes off G's receiving
#      device. Worker re-attaches it at its next resync, in the same pass
#      that reads the scope, so no status reports it missing. Expected:
#      local_rx back within the resync interval, no packet G sends from its
#      own locator to itself (w2's flows dropped, never encapsulated), the
#      other backends' VIPs and the pool's other backends still answering,
#      and w2 Local again afterwards with no further local_unavailable drop.
#   3. TAP carrier loss (G = dfw-worker2). w2's hypervisor stand-in stops
#      reading its TAP, which Worker cannot repair. Expected: LocalHandoff
#      False, w2 not ready in status.localBackends, w2's bindings
#      Unhealthy/LocalHandoffNotReady, w2 out of the pool on both gateways,
#      the pool answered by the others through both, local_unavailable at
#      most transient, then recovery once the TAP has a reader again.
#   4. Public path (G = dfw-worker2). public_uplink_table on G loses its next
#      hop (its value is zeroed, which galactic-cni's uplink watcher never
#      rewrites; removing the neighbor alone only moves the row to another
#      uplink). Expected: PublicPath False/FamilyWithdrawn, every gwlocal
#      -v4/-v6 BGPAdvertisement of G deleted, galactic_edge_family_withdrawn
#      1 for both families, w2 not ready with reason PublicUplinkMissing,
#      Unhealthy/LocalHandoffNotReady and out of the pool on both gateways,
#      the pool answered through dfw-worker3 and, for its remote backends,
#      through G, then re-advertisement and w2 back once the row is back.
#      The lab's edge nodes originate the site's VIP /64 and /26 from FRR,
#      which the gateway can neither see nor withdraw (D44). With the pins
#      off, the check withdraws G's FRR network statement for one family at
#      a time (vtysh in G's fabric-router, as verify:nat-active-active does)
#      and asserts that tr1 loses its route via G, that unpinned clients'
#      flows enter through dfw-worker3 (its rule counters rise, G's do not)
#      and are answered, and that the route via G is back once re-added.
#
# Throughout, the egress shards' translation counters on both edge nodes
# must not move: no VIP reply may take the NAT path. A TCP request that
# draws no reply is retried once from a new port; a retry that passes is
# reported as "RARE-NO-REPLY observed".
#
# Worker takes over every VPC scope on dfw-worker2 and dfw-worker3 and never
# hands one back. On exit this restores what it changed, deletes what it
# created and stops Worker; the lab then needs task destroy, task deploy and
# task baseline:twice, as after verify:nat-local-shard.
#
# It stops with a PRECONDITION line, exit 0, before changing anything, when
# backend health (GALACTIC_GATEWAY_BACKEND_HEALTH, D48) is off on any dfw
# gateway or NetworkGateway, or dfw-worker2's FRR does not originate both
# site prefixes. Its own gateway patch sets backend health again, and a
# gateway without it after the patch fails the run.
#
# Usage:
#   verify-gateway-local.sh                  run the check
#   verify-gateway-local.sh --check-harness  only the harness precondition
#   verify-gateway-local.sh --unpin          remove leftover tr1 pins and
#                                            re-originate the site prefixes
#
# EXPECT_HEAD, when set, must be this checkout's HEAD. EVIDENCE_DIR names the
# directory for captures and the log (default: a new directory under /tmp).
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LAB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPO_DIR=$(cd "${LAB_DIR}/../.." && pwd)
FIXTURE="${LAB_DIR}/resources/gateway-local"
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
CP=$(control_plane dfw)
CLIENT_HOST="clab-${LAB}-remote-host"
CLIENT6=2001:db8:1:40::2
CLIENT4=11.1.40.2
CLIENT4_SEEN=64:ff9b::b01:2802
PORT=80
FLOWS=8
WORKER_RESYNC_S=30
GW_METRICS=8081
NAT_METRICS=9182
LOCAL_PIN=/sys/fs/bpf/galactic-local
CNI_PIN=/sys/fs/bpf/galactic
INTEGRATION_REF=origin/integration/galactic-worker
GATEWAYS=(dfw-worker2 dfw-worker3)
# "<edge node's address on its tr1 link> <tr1's bond toward it>", as in
# verify-gateway-ingress.sh and verify-gateway-ingress-ipv4.sh.
declare -A UPLINK6=([dfw-worker2]="2001:db8:1:11::2 bond1" [dfw-worker3]="2001:db8:1:12::2 bond2")
declare -A UPLINK4=([dfw-worker2]="10.1.11.2 bond1" [dfw-worker3]="10.1.12.2 bond2")
BACKENDS=(w1 w2 w3 w4)
declare -A B_NODE=([w1]=dfw-worker [w2]=dfw-worker2 [w3]=dfw-worker3 [w4]=dfw-worker4)
declare -A B_ADDR=([w1]=fd20:80:ff01::1:0:0 [w2]=fd20:80:ff01::4:0:0 [w3]=fd20:80:ff01::5:0:0 [w4]=fd20:80:ff01::2:0:0)
declare -A B_IFACE=([w1]=G000000080080H [w2]=G000000080088H [w3]=G000000080089H [w4]=G000000080084H)
declare -A B_ATTACH=([w1]=vpc-a [w2]=gwlocal-w2 [w3]=gwlocal-w3 [w4]=vpc-a2)
declare -A VIP6=([w1]=2001:db8:6060:1::11 [w2]=2001:db8:6060:1::12 [w3]=2001:db8:6060:1::13
  [w4]=2001:db8:6060:1::14 [pool]=2001:db8:6060:1::10)
declare -A VIP4=([w1]=198.51.100.11 [w2]=198.51.100.12 [w3]=198.51.100.13 [w4]=198.51.100.14
  [pool]=198.51.100.10)
RULES=(gwlocal-w1-tcp gwlocal-w1-udp gwlocal-w2-tcp gwlocal-w2-udp gwlocal-w3-tcp gwlocal-w3-udp
  gwlocal-w4-tcp gwlocal-w4-udp gwlocal-pool-tcp gwlocal-pool-udp)
# Every rule's backends write one binding per VIP family: eight per-backend
# rules with one backend and two pool rules with four.
WANT_BINDINGS=32
LABEL_ONE=lab.galactic.datumapis.com/gateway-local
LABEL_POOL=lab.galactic.datumapis.com/gateway-local-pool

kc() { docker exec "${CP}" kubectl "$@"; }
kci() { docker exec -i "${CP}" kubectl "$@"; }
transit() { docker exec "clab-${LAB}-$1" "${@:2}"; }
log() { echo "== $*"; }

precondition() {
  echo "PRECONDITION: $*; nothing changed"
  exit 0
}

# --- pins --------------------------------------------------------------------

unpin() {
  local k
  for k in "${!VIP6[@]}"; do
    transit tr1 ip -6 route del "${VIP6[${k}]}/128" 2>/dev/null || true
    transit tr1 ip -4 route del "${VIP4[${k}]}/32" 2>/dev/null || true
  done
}

# pin GATEWAY sends every gwlocal VIP, both families, through GATEWAY.
pin() {
  local k a6 d6 a4 d4
  read -r a6 d6 <<<"${UPLINK6[$1]}"
  read -r a4 d4 <<<"${UPLINK4[$1]}"
  for k in "${!VIP6[@]}"; do
    transit tr1 ip -6 route replace "${VIP6[${k}]}/128" via "${a6}" dev "${d6}"
    transit tr1 ip -4 route replace "${VIP4[${k}]}/32" via "${a4}" dev "${d4}"
  done
}

# --- the site aggregate -----------------------------------------------------------

# dfw's edge nodes originate the site's VIP prefixes from FRR, in AS 65000
# (resources/fabric-router/dfw/frr.conf.dfw-worker2). The public-path step
# withdraws them on dfw-worker2 at runtime through vtysh, as
# verify-nat-active-active.sh does a shard's SID; the fabric-router
# ConfigMap is untouched, and every exit path re-adds them.
EDGE_ASN=65000
declare -A SITE_PREFIX=([6]=2001:db8:6060:1::/64 [4]=198.51.100.0/26)
AGGREGATE_NODE=dfw-worker2
FRR_WITHDRAWN=()
edge_frr() { # NODE vtysh-args...
  local node=$1 pod
  shift
  pod=$(kc -n galactic-system get pods -l app.kubernetes.io/name=fabric-router \
    --field-selector "spec.nodeName=${node}" -o jsonpath='{.items[0].metadata.name}')
  kc -n galactic-system exec "${pod}" -c frr -- vtysh "$@"
}
originate_site() { # FAMILY yes|no
  local no="" af=ipv6
  [ "$1" = 4 ] && af=ipv4
  [ "$2" = no ] && no="no "
  edge_frr "${AGGREGATE_NODE}" -c 'conf t' -c "router bgp ${EDGE_ASN}" -c "address-family ${af} unicast" \
    -c "${no}network ${SITE_PREFIX[$1]}" >/dev/null
}
# tr1_routes FAMILY prints tr1's routes covering the family's pool VIP.
tr1_routes() {
  if [ "$1" = 6 ]; then
    transit tr1 ip -6 route show match "${VIP6[pool]}"
  else
    transit tr1 ip -4 route show match "${VIP4[pool]}"
  fi
}
# tr1_via GATEWAY FAMILY counts tr1's next hops toward GATEWAY among them.
tr1_via() {
  # tr1 learns the IPv6 site prefix with link-local next hops (via fe80::...
  # dev bondN), so match the next hop's device, tr1's bond toward the edge
  # node, rather than the edge node's global address. IPv4 next hops carry
  # the same device.
  local d routes
  if [ "$2" = 6 ]; then read -r _ d <<<"${UPLINK6[$1]}"; else read -r _ d <<<"${UPLINK4[$1]}"; fi
  routes=$(tr1_routes "$2")
  grep -cE "via [^ ]+ dev ${d}( |\$)" <<<"${routes}" || true
}

case "${1:-}" in
  --unpin)
    unpin
    # Re-adding a network statement FRR already has changes nothing.
    originate_site 6 yes || true
    originate_site 4 yes || true
    exit 0
    ;;
  --check-harness | "") ;;
  *)
    echo "unknown argument: $1" >&2
    exit 2
    ;;
esac

# --- preconditions -------------------------------------------------------------

# harness_check stops unless deploy/containerlab is the integration branch's
# plus this change's own additions: the nat-local and gateway-local fixtures
# and scripts, and lines added, none removed, to the Taskfile and the two
# documents that list the checks.
harness_check() {
  local integ changed stale f d removed head
  head=$(git -C "${REPO_DIR}" rev-parse HEAD)
  if [ -n "${EXPECT_HEAD:-}" ] && [ "${head}" != "${EXPECT_HEAD}" ]; then
    precondition "${REPO_DIR} is at ${head}, not EXPECT_HEAD ${EXPECT_HEAD}"
  fi
  # A payload captures the integration head once, at its start, and exports
  # it as INTEGRATION_SHA, so an integration merge while the payload runs
  # does not void the case. Without it, the live ref is used.
  if [ -n "${INTEGRATION_SHA:-}" ]; then
    integ=$(git -C "${REPO_DIR}" rev-parse --verify -q "${INTEGRATION_SHA}^{commit}" || true)
    [ -n "${integ}" ] || precondition "${REPO_DIR} does not have INTEGRATION_SHA ${INTEGRATION_SHA}; fetch it"
  else
    integ=$(git -C "${REPO_DIR}" rev-parse --verify -q "${INTEGRATION_REF}^{commit}" || true)
    [ -n "${integ}" ] || precondition "${REPO_DIR} has no ${INTEGRATION_REF}; fetch it"
  fi
  git -C "${REPO_DIR}" merge-base --is-ancestor "${integ}" HEAD ||
    precondition "integration (${integ}) is not in this branch; merge it first"
  changed=$({
    git -C "${REPO_DIR}" diff --name-only "${integ}" -- deploy/containerlab
    git -C "${REPO_DIR}" ls-files --others --exclude-standard -- deploy/containerlab
  } | sort -u)
  stale=$(grep -vE '^deploy/containerlab/(resources/(nat|gateway)-local/|scripts/verify-(nat|gateway)-local\.sh$|Taskfile\.yaml$|README\.md$|docs/verification\.md$)' <<<"${changed}" || true)
  stale=$(sed '/^$/d' <<<"${stale}")
  [ -z "${stale}" ] || precondition "deploy/containerlab differs from ${INTEGRATION_REF} (${integ}) beyond this change: $(tr '\n' ' ' <<<"${stale}")"
  for f in Taskfile.yaml README.md docs/verification.md; do
    d=$(git -C "${REPO_DIR}" diff "${integ}" -- "deploy/containerlab/${f}")
    removed=$(grep -E '^-' <<<"${d}" | grep -cvE '^--- (a/|/dev/null)' || true)
    [ "${removed}" -eq 0 ] || precondition "deploy/containerlab/${f} removes ${removed} line(s) of ${INTEGRATION_REF}"
  done
  echo "harness matches ${INTEGRATION_REF} ${integ} apart from this change's fixtures"
}

harness_check
if [ "${1:-}" = --check-harness ]; then
  echo "HARNESS OK"
  exit 0
fi

scrape() { docker exec "$1" curl -s --max-time 4 "http://localhost:$2/metrics" || true; }

# msum NODE PORT NAME [SUBSTRING...] sums NAME's samples on NODE that contain
# every SUBSTRING, or prints "missing" when there is none.
msum() {
  local node=$1 port=$2 name=$3 text
  shift 3
  text=$(scrape "${node}" "${port}")
  awk -v n="${name}" -v f="$*" 'BEGIN {k = split(f, fs, " ")}
    index($0, n "{") == 1 || index($0, n " ") == 1 {
      ok = 1
      for (i = 1; i <= k; i++) if (!index($0, fs[i])) ok = 0
      if (ok) {s += $NF; c++}
    }
    END {if (c) printf "%.0f\n", s; else print "missing"}' <<<"${text}"
}

# health_report sets HEALTH_MISSING to every NetworkGateway in dfw's
# galactic-system without status.backendHealthFiltering, and every gateway pod
# there whose container lacks GALACTIC_GATEWAY_BACKEND_HEALTH=true, or "".
health_report() {
  local gws pods
  gws=$(kc -n galactic-system get networkgateways -o json |
    jq -r '.items[] | select(.status.backendHealthFiltering != true) | "NetworkGateway \(.metadata.name), "')
  pods=$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-gateway -o json |
    jq -r '.items[] | select([.spec.containers[] | select(.name == "galactic-gateway") | .env // [] | .[] |
      select(.name == "GALACTIC_GATEWAY_BACKEND_HEALTH" and .value == "true")] | length == 0)
      | "pod \(.metadata.name), "')
  HEALTH_MISSING=$(tr -d '\n' <<<"${gws}${pods}")
}

lab_preconditions() {
  local c gw text n
  for c in "${CP}" dfw-worker dfw-worker2 dfw-worker3 dfw-worker4 "clab-${LAB}-tr1" "${CLIENT_HOST}"; do
    [ "$(docker inspect -f '{{.State.Running}}' "${c}" 2>/dev/null || true)" = true ] ||
      precondition "lab container ${c} is not running (task deploy)"
  done
  command -v go >/dev/null || precondition "no go toolchain: scripts/worker-fabric.sh builds Worker"
  # worker-fabric.sh builds Worker on this host, which needs the generated
  # eBPF bindings; task deploy builds its images in containers and leaves
  # none in the checkout.
  [ -n "$(ls "${REPO_DIR}"/internal/plumbing/ebpf/prog/*_bpfel.go 2>/dev/null)" ] ||
    precondition "no generated eBPF bindings in ${REPO_DIR}: run task build:ebpf there"
  command -v jq >/dev/null || precondition "no jq on this host"
  sudo -n true 2>/dev/null || precondition "sudo needs a password: Worker's lt_stats and public_uplink_table are read with the host's bpftool"
  sudo -n bpftool version >/dev/null 2>&1 || precondition "no bpftool on this host"
  text=$(kc get crd networkgateways.galactic.datumapis.com -o json 2>/dev/null || true)
  n=$(grep -c localBackends <<<"${text}" || true)
  [ "${n}" -gt 0 ] || precondition "the NetworkGateway CRD has no status.localBackends: deploy this branch (task deploy:system)"
  [ "$(kc auth can-i list networkgateways.galactic.datumapis.com \
    --as=system:serviceaccount:galactic-system:galactic-router 2>/dev/null || true)" = yes ] ||
    precondition "galactic-router cannot list NetworkGateways: deploy this branch's RBAC (task deploy:system)"
  for gw in "${GATEWAYS[@]}"; do
    [ "$(kc -n galactic-system get pods -l app.kubernetes.io/name=galactic-gateway --field-selector "spec.nodeName=${gw}" \
      -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null || true)" = true ] ||
      precondition "${gw}'s galactic-gateway is not ready"
    text=$(scrape "${gw}" "${GW_METRICS}")
    n=$(grep -cE '^galactic_edge_(local_handoffs_total|family_withdrawn)' <<<"${text}" || true)
    [ "${n}" -ge 2 ] || precondition "${gw}'s galactic-gateway predates #1438 (no galactic_edge_local_handoffs_total or galactic_edge_family_withdrawn): deploy this branch's images"
    n=$(docker exec "${gw}" sh -c 'pgrep -f "^/opt/galactic-worker/galactic-worker" || true' | wc -l)
    [ "${n}" -eq 0 ] || precondition "galactic-worker already runs on ${gw}: an earlier run did not stop it (task destroy, task deploy)"
    n=$(docker exec "${gw}" sh -c 'cat /var/lib/galactic-edge/ownership/vpc-*.json 2>/dev/null || true' | grep -c 'galactic-worker:' || true)
    [ "${n}" -eq 0 ] || precondition "a galactic-worker owns VPC scopes on ${gw} since the last deploy (task destroy, task deploy)"
  done
  # Backend health is what takes a backend whose Local handoff is not ready
  # out of every gateway's Maglev table (D48), and a gateway applies it only
  # while every NetworkGateway in the namespace reports it.
  health_report
  [ -z "${HEALTH_MISSING}" ] ||
    precondition "backend health is off: ${HEALTH_MISSING}(GALACTIC_GATEWAY_BACKEND_HEALTH=true, resources/galactic-gateway/base/; task deploy:galactic-gateway)"
  for fam in 6 4; do
    text=$(edge_frr "${AGGREGATE_NODE}" -c 'show running-config' 2>/dev/null || true)
    pfx=${SITE_PREFIX[${fam}]}
    n=$(grep -cE "^[[:space:]]*network ${pfx//./\\.}[[:space:]]*\$" <<<"${text}" || true)
    [ "${n}" -ge 1 ] || precondition "${AGGREGATE_NODE}'s FRR does not originate ${SITE_PREFIX[${fam}]} (network statement missing; task deploy:fabric)"
    [ "$(tr1_via "${AGGREGATE_NODE}" "${fam}")" -gt 0 ] ||
      precondition "tr1 does not route ${SITE_PREFIX[${fam}]} via ${AGGREGATE_NODE}"
  done
  for c in guest-a guest-a2; do
    [ "$(kc -n ns80 get deployment "${c}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)" = 1 ] ||
      precondition "ns80's ${c} is not ready (task deploy:ns80)"
  done
  for c in vpc-a vpc-a2; do
    kc -n ns80 get trafficpolicybinding "${c}" >/dev/null 2>&1 || precondition "ns80 has no TrafficPolicyBinding ${c}"
  done
  if kc -n ns80 get deployment gwlocal-w2 >/dev/null 2>&1 ||
    kc -n galactic-system get networkservice gwlocal-pool-tcp >/dev/null 2>&1; then
    precondition "the gateway-local fixture is already deployed: an earlier run did not remove it"
  fi
  for c in "${!VIP6[@]}"; do
    [ -z "$(transit tr1 ip -6 route show "${VIP6[${c}]}/128")$(transit tr1 ip -4 route show "${VIP4[${c}]}/32")" ] ||
      precondition "tr1 holds a pinned route for ${c}'s VIP: an earlier run did not remove it (--unpin)"
  done
}
lab_preconditions

OUT=${EVIDENCE_DIR:-/tmp/verify-gateway-local-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "${OUT}"
exec > >(tee -a "${OUT}/run.log") 2>&1
echo "evidence: ${OUT}"
git -C "${REPO_DIR}" log -1 --format='revision %H %s' || true
git -C "${REPO_DIR}" status --short -- . | sed 's/^/  dirty: /' || true

# --- results ---------------------------------------------------------------------

RESULTS=()
RARE=0
# record PASS|FAIL|INFO NAME DETAIL
record() {
  local line
  line=$(printf '%-4s %-46s %s' "$1" "$2" "${3:-}")
  RESULTS+=("${line}")
  echo "  ${line}"
}
check() { # NAME DETAIL CONDITION...
  local name=$1 detail=$2
  shift 2
  if "$@"; then record PASS "${name}" "${detail}"; else record FAIL "${name}" "${detail}"; fi
}
die() {
  record FAIL aborted "$*"
  exit 1
}

# --- saved state and cleanup -----------------------------------------------------

STATE=$(mktemp -d)
for gw in "${GATEWAYS[@]}"; do
  kc -n galactic-system get ds "galactic-gateway-${gw}" -o json >"${STATE}/ds-${gw}.json"
done
declare -A SAVED_REFS
for c in vpc-a vpc-a2; do
  SAVED_REFS[${c}]=$(kc -n ns80 get trafficpolicybinding "${c}" \
    -o jsonpath='{.spec.ingressPolicyRef.name} {.spec.egressPolicyRef.name}')
done
CLEAN_FIXTURE=0 CLEAN_LABELS=0 CLEAN_BINDINGS=0 CLEAN_RESPONDERS=0 CLEAN_SERVICES=0
CLEAN_WORKER=0 CLEAN_DS=0 HOLD=0 UPLINK_SAVED=""

restore_ds() {
  python3 -c 'import json,sys
d = json.load(open(sys.argv[1]))
for k in ("resourceVersion", "uid", "creationTimestamp", "managedFields", "generation"): d["metadata"].pop(k, None)
d.pop("status", None)
json.dump(d, sys.stdout)' "$1" | kci replace -f - >/dev/null
}

summary() {
  local fails r
  fails=$(printf '%s\n' "${RESULTS[@]}" | grep -c '^FAIL' || true)
  echo
  echo "==== verify:gateway-local evidence summary ===="
  for r in "${RESULTS[@]}"; do echo "${r}"; done
  echo "RARE-NO-REPLY observed: ${RARE} time(s)"
  echo "evidence: ${OUT}"
  if [ "$1" -ne 0 ] || [ "${fails}" -ne 0 ]; then
    echo "RESULT: FAIL (${fails} FAIL)"
    return 1
  fi
  echo "RESULT: PASS"
}

cleanup() {
  local rc=$? c gw f
  set +e
  log "restoring"
  unpin
  for f in "${FRR_WITHDRAWN[@]}"; do originate_site "${f}" yes; done
  [ -z "${UPLINK_SAVED}" ] || uplink_write dfw-worker2 "${UPLINK_SAVED}"
  if [ "${HOLD}" -eq 1 ]; then
    kc -n ns80 exec deploy/gwlocal-w2 -c vmm -- rm -f /tmp/hold
  fi
  if [ "${CLEAN_RESPONDERS}" -eq 1 ]; then
    for j in "${RESPONDER_JOBS[@]}"; do kill "${j}" 2>/dev/null || true; done
    for c in guest-a guest-a2; do
      kc -n ns80 exec "deploy/${c}" -- sh -c 'pkill -f "TCP6-LISTEN:8[01]," ; pkill -f "UDP6-RECVFROM:8[01]," ; true'
    done
  fi
  if [ "${CLEAN_BINDINGS}" -eq 1 ]; then
    for c in vpc-a vpc-a2; do
      read -r ing egr <<<"${SAVED_REFS[${c}]}"
      kc -n ns80 patch trafficpolicybinding "${c}" --type=merge \
        -p "{\"spec\":{\"ingressPolicyRef\":{\"name\":\"${ing}\"},\"egressPolicyRef\":{\"name\":\"${egr}\"}}}" >/dev/null
    done
  fi
  if [ "${CLEAN_LABELS}" -eq 1 ]; then
    for c in vpc-a vpc-a2; do
      kc -n ns80 label vpcattachment "${c}" "${LABEL_ONE}-" "${LABEL_POOL}-" >/dev/null
    done
  fi
  [ "${CLEAN_SERVICES}" -eq 0 ] || kci delete --ignore-not-found -f - <"${FIXTURE}/networkservices.yaml" >/dev/null
  if [ "${CLEAN_DS}" -eq 1 ]; then
    for gw in "${GATEWAYS[@]}"; do restore_ds "${STATE}/ds-${gw}.json"; done
  fi
  if [ "${CLEAN_FIXTURE}" -eq 1 ]; then
    for c in guests bindings policies nad vpcattachments; do
      kci delete --ignore-not-found -f - <"${FIXTURE}/${c}.yaml" >/dev/null
    done
  fi
  [ "${CLEAN_WORKER}" -eq 0 ] || NODES="${GATEWAYS[*]}" "${SCRIPT_DIR}/worker-fabric.sh" stop
  for gw in "${GATEWAYS[@]}"; do
    kc -n galactic-system rollout status "daemonset/galactic-gateway-${gw}" --timeout=600s >/dev/null
  done
  rm -rf "${STATE}"
  echo "The lab needs task destroy, task deploy and task baseline:twice: Worker kept the VPC scopes of ${GATEWAYS[*]}."
  summary "${rc}" || rc=1
  exit "${rc}"
}
trap cleanup EXIT

# --- helpers -----------------------------------------------------------------------

node_pid() { docker inspect -f '{{.State.Pid}}' "$1"; }

# lt_stat NODE INDEX prints Worker's lt_stats slot INDEX on NODE, summed over
# CPUs, or "missing". Slots follow localprog.StatNames.
LT_RX_DELIVER=6
lt_stat() {
  local json
  json=$(sudo -n bpftool -j map lookup pinned "/proc/$(node_pid "$1")/root${LOCAL_PIN}/lt_stats" \
    key "$2" 0 0 0 2>/dev/null || true)
  python3 -c 'import json,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("missing"); sys.exit(0)
if isinstance(d, list): d = d[0]
f = d.get("formatted")
vals = (f or {}).get("values") or d.get("values") or []
s = 0
for v in vals:
    x = v.get("value")
    s += int.from_bytes(bytes(int(b, 16) for b in x), "little") if isinstance(x, list) else int(x)
print(s if vals else "missing")' "${json}"
}

# lt_dump NODE writes every lt_stats slot on NODE to the evidence.
lt_dump() {
  local dump
  dump=$(sudo -n bpftool -j map dump pinned "/proc/$(node_pid "$1")/root${LOCAL_PIN}/lt_stats" 2>&1 || true)
  echo "${dump}" >"${OUT}/lt_stats-$1-$2.json"
}

# uplink_read NODE prints public_uplink_table's value on NODE as hex.
uplink_read() {
  local json
  json=$(sudo -n bpftool -j map lookup pinned "/proc/$(node_pid "$1")/root${CNI_PIN}/public_uplink_table" \
    key 0 0 0 0 2>/dev/null || true)
  python3 -c 'import json,struct,sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    sys.exit(0)
if isinstance(d, list): d = d[0]
v = d.get("value")
if isinstance(v, list) and v and isinstance(v[0], str):
    b = bytes(int(x, 16) for x in v)
else:
    f = d["formatted"]["value"]
    b = struct.pack("<I", f["link_ifindex"]) + bytes(f["dmac"]) + bytes(f["smac"])
print(b.hex())' "${json}"
}

# uplink_write NODE HEX writes public_uplink_table's value on NODE.
uplink_write() {
  local bytes
  # shellcheck disable=SC2001 # a space after every byte
  bytes=$(sed 's/../& /g' <<<"$2")
  # shellcheck disable=SC2086 # one argument per byte
  sudo -n bpftool map update pinned "/proc/$(node_pid "$1")/root${CNI_PIN}/public_uplink_table" \
    key 0 0 0 0 value hex ${bytes}
}

expand6() {
  python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]).exploded)' "$1" 2>/dev/null || echo "invalid:$1"
}

rose() { [ "$1" != missing ] && [ "$2" != missing ] && [ "$2" -gt "$1" ]; }
same() { [ "$1" != missing ] && [ "$1" = "$2" ]; }
zero_if_missing() { if [ "$1" = missing ]; then echo 0; else echo "$1"; fi; }

local_handoffs() { msum "$1" "${GW_METRICS}" galactic_edge_local_handoffs_total; }
local_unavailable() {
  zero_if_missing "$(msum "$1" "${GW_METRICS}" galactic_edge_drops_total 'reason="local_unavailable"')"
}
rule_packets() { msum "$1" "${GW_METRICS}" galactic_edge_rule_packets_total "vip=\"$2\""; }
rp_sum() { # NODE VIP... sums rule packets over the VIPs, a missing series as 0
  local node=$1 v n=0
  shift
  for v in "$@"; do n=$((n + $(zero_if_missing "$(rule_packets "${node}" "${v}")"))); done
  echo "${n}"
}
rule_backends() { msum "$1" "${GW_METRICS}" galactic_edge_rule_backends "vip=\"$2\"" "proto=\"$3\"" 'port="80"'; }

nat_total() {
  local gw text n s=0
  for gw in "${GATEWAYS[@]}"; do
    text=$(scrape "${gw}" "${NAT_METRICS}")
    n=$(awk '/^galactic_nat_(packets|session_creates)_total\{/ {s += $NF; c++} END {if (c) printf "%.0f\n", s; else print "missing"}' <<<"${text}")
    if [ "${n}" = missing ]; then
      echo missing
      return
    fi
    s=$((s + n))
  done
  echo "${s}"
}
nat_check() { # PHASE BEFORE
  local now
  now=$(nat_total)
  check "$1: no egress shard translation" "galactic_nat_packets/session_creates on both edge nodes ${2} -> ${now}" same "$2" "${now}"
}

attach_uid() { kc -n ns80 get vpcattachment "$1" -o jsonpath='{.metadata.uid}'; }

ng_cond() { # NODE TYPE -> "status reason message"
  kc -n galactic-system get networkgateway "$1" -o json | jq -r --arg t "$2" \
    '(.status.conditions // [] | map(select(.type == $t))[0]) // {} | "\(.status // "missing") \(.reason // "-") \(.message // "")"'
}
ng_local() { # NODE UID -> "ready reason"
  kc -n galactic-system get networkgateway "$1" -o json | jq -r --arg u "$2" \
    '(.status.localBackends // [] | map(select(.attachmentUID == $u))[0]) // {} | "\(if .ready == null then "missing" else .ready end) \(.reason // "-")"'
}
cond_is() { local c; c=$(ng_cond "$1" "$2"); [[ "${c}" == "$3 $4"* ]]; }

# binding_health RULE NODE prints "vip state reason" for each binding NODE
# writes for RULE.
binding_health() {
  kc -n galactic-system get servicevipbindings \
    -l "galactic.datum.net/network-rule=$1,galactic.datum.net/binding-node=$2" -o json |
    jq -r '.items[] | "\(.spec.vipAddress) \(.status.health.state // "none") \(.status.health.reason // "-")"'
}
# w2_health_is REASON|clear: every binding dfw-worker2 writes for the pool
# rules names REASON, or none does.
w2_health_is() {
  local h n bad
  h=$( (binding_health gwlocal-pool-tcp dfw-worker2; binding_health gwlocal-pool-udp dfw-worker2) | sed '/^$/d')
  n=$(wc -l <<<"${h}")
  [ "${n}" -ge 4 ] || return 1
  if [ "$1" = clear ]; then
    bad=$(grep -c LocalHandoffNotReady <<<"${h}" || true)
  else
    bad=$(grep -vc " $1\$" <<<"${h}" || true)
  fi
  [ "${bad}" -eq 0 ]
}

# pool_holds COUNT: every gateway holds COUNT pool backends for both
# protocols and both VIP families.
pool_holds() {
  local gw p v
  for gw in "${GATEWAYS[@]}"; do
    for p in tcp udp; do
      for v in "${VIP6[pool]}" "${VIP4[pool]}"; do
        [ "$(rule_backends "${gw}" "${v}" "${p}")" = "$1" ] || return 1
      done
    done
  done
}

bound_bindings() {
  local sel
  sel=$(
    IFS=,
    echo "${RULES[*]}"
  )
  kc -n galactic-system get servicevipbindings -l "galactic.datum.net/network-rule in (${sel})" -o json |
    jq '[.items[] | select(.status.conditions // [] | any(.type == "Bound" and .status == "True"))] | length'
}

# rule_advs NODE counts NODE's gwlocal -v4/-v6 BGPAdvertisements.
rule_advs() {
  local names
  names=$(kc get bgpadvertisements -A -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
  grep -cE "^gwlocal-.*-$1-[0-9a-f]+-v[46]\$" <<<"${names}" || true
}

local_rx_devs() { # NODE -> "dev:pref" for each device carrying local_rx
  local node=$1 dev out pref
  for dev in bond0 bond1 bond2; do
    out=$(docker exec "${node}" tc filter show dev "${dev}" ingress 2>/dev/null || true)
    pref=$(awk '/galactic_local_rx/ {for (i = 1; i < NF; i++) if ($i == "pref") {print $(i + 1); exit}}' <<<"${out}")
    [ -z "${pref}" ] || echo "${dev}:${pref}"
  done
}

# wait_until SECONDS CMD... polls CMD every 2s until it succeeds, and fails
# past SECONDS.
wait_until() {
  local limit=$1 start=${SECONDS}
  shift
  until "$@"; do
    [ $((SECONDS - start)) -lt "${limit}" ] || return 1
    sleep 2
  done
}

# request PROTO FAMILY VIP SPORT prints the backend's one-line answer.
request() {
  local addr
  case "$2$1" in
    6tcp) addr="TCP6:[$3]:${PORT},sourceport=$4,reuseaddr" ;;
    6udp) addr="UDP6:[$3]:${PORT},sourceport=$4,reuseaddr" ;;
    4tcp) addr="TCP4:$3:${PORT},sourceport=$4,reuseaddr" ;;
    4udp) addr="UDP4:$3:${PORT},sourceport=$4,reuseaddr" ;;
  esac
  echo probe | docker exec -i "${CLIENT_HOST}" timeout 5 socat -t2 -T3 - "${addr}" 2>/dev/null | head -1 || true
}

# ask PROTO FAMILY VIP sends one request from a new port, and a TCP request
# that draws no answer once more from another, which is reported as
# RARE-NO-REPLY when it passes. It sets ANSWER_NAME and ANSWER_PEER.
ask() {
  local reply try
  ANSWER_NAME="" ANSWER_PEER=""
  for try in 1 2; do
    pick_port
    reply=$(request "$1" "$2" "$3" "${PORT_PICKED}")
    if [ -n "${reply}" ]; then
      read -r ANSWER_NAME ANSWER_PEER <<<"${reply}"
      ANSWER_PEER=${ANSWER_PEER#[}
      ANSWER_PEER=${ANSWER_PEER%]}
      if [ "${try}" -eq 2 ]; then
        RARE=$((RARE + 1))
        echo "  RARE-NO-REPLY observed: $1/IPv$2 to $3, answered on retry"
      fi
      return 0
    fi
    [ "$1" = tcp ] || return 1
  done
  return 1
}

# flows GATEWAY_LABEL PROTO FAMILY VIP N sends N requests and sets F_OK and
# F_BY, the answering backends with their counts.
flows() {
  local i
  F_OK=0
  declare -gA F_COUNT=()
  for i in $(seq "$5"); do
    if ask "$2" "$3" "$4"; then
      F_OK=$((F_OK + 1))
      F_COUNT[${ANSWER_NAME}]=$((${F_COUNT[${ANSWER_NAME}]:-0} + 1))
    fi
  done
  F_BY=""
  for i in "${!F_COUNT[@]}"; do F_BY="${F_BY} ${i}=${F_COUNT[${i}]}"; done
}

client_seen() { if [ "$1" = 6 ]; then echo "${CLIENT6}"; else echo "${CLIENT4_SEEN}"; fi; }
other_gw() { if [ "$1" = dfw-worker2 ]; then echo dfw-worker3; else echo dfw-worker2; fi; }

# --- 1. setup ------------------------------------------------------------------------

log "1. setup: edge guests, VIP rules, galactic-worker and the gateways' claims"
CLEAN_FIXTURE=1
for f in policies bindings vpcattachments nad guests; do
  kci apply -f - >/dev/null <"${FIXTURE}/${f}.yaml"
done
for c in gwlocal-w2 gwlocal-w3; do
  kc -n ns80 rollout status deployment "${c}" --timeout=300s >/dev/null || die "${c} is not ready"
done
"${SCRIPT_DIR}/publish-attachments.sh" ns80 dfw

CLEAN_LABELS=1
kc -n ns80 label vpcattachment vpc-a --overwrite "${LABEL_ONE}=w1" "${LABEL_POOL}=true" >/dev/null
kc -n ns80 label vpcattachment vpc-a2 --overwrite "${LABEL_ONE}=w4" "${LABEL_POOL}=true" >/dev/null
CLEAN_BINDINGS=1
for c in vpc-a vpc-a2; do
  kc -n ns80 patch trafficpolicybinding "${c}" --type=merge \
    -p '{"spec":{"ingressPolicyRef":{"name":"gateway-local-ingress"},"egressPolicyRef":{"name":"gateway-local-egress"}}}' >/dev/null
done
CLEAN_RESPONDERS=1
# The responder guests.yaml runs, which is ns60's
# (resources/tenants/ns60/base/backend.yaml). A process started in a
# kubectl exec dies when the exec ends, setsid or not, so each guest's exec
# stays open as a background job of this script for the whole run, and
# cleanup ends it.
RESPONDER_JOBS=()
for spec in "guest-a dfw-worker" "guest-a2 dfw-worker4"; do
  read -r c node <<<"${spec}"
  # shellcheck disable=SC2016 # expanded inside the guest
  kc -n ns80 exec "deploy/${c}" -- env BACKEND="${node}" sh -c '
reply="echo \"\$BACKEND \$SOCAT_PEERADDR\""
for p in 80 81; do
  socat TCP6-LISTEN:${p},reuseaddr,fork SYSTEM:"$reply"!!/dev/null </dev/null >/dev/null 2>&1 &
  socat UDP6-RECVFROM:${p},reuseaddr,fork SYSTEM:"$reply"!!/dev/null </dev/null >/dev/null 2>&1 &
done
wait' >/dev/null 2>&1 &
  RESPONDER_JOBS+=($!)
done
# Each guest must listen on TCP and UDP ports 80 and 81 before the matrix.
for c in guest-a guest-a2; do
  for i in $(seq 30); do
    n=$(kc -n ns80 exec "deploy/${c}" -- sh -c 'ss -Hlnut 2>/dev/null' | grep -cE '[]:]8[01] ' || true)
    [ "${n}" -ge 4 ] && break
    sleep 1
  done
  [ "${n}" -ge 4 ] || die "${c}'s responders are not listening on TCP and UDP ports 80 and 81 (${n} of 4 sockets)"
  record PASS "setup ${c} responders" "listening on TCP and UDP ports 80 and 81"
done
CLEAN_SERVICES=1
kci apply -f - >/dev/null <"${FIXTURE}/networkservices.yaml"

CLEAN_WORKER=1
NODES="${GATEWAYS[*]}" WORKER_ALLOWLIST="${FIXTURE}/allowlist.yaml" "${SCRIPT_DIR}/worker-fabric.sh" start
CLEAN_DS=1
for gw in "${GATEWAYS[@]}"; do
  kc -n galactic-system patch ds "galactic-gateway-${gw}" --type=strategic \
    --patch "$(cat "${FIXTURE}/gateway-worker-patch.yaml")" >/dev/null
done
for gw in "${GATEWAYS[@]}"; do
  kc -n galactic-system rollout status "daemonset/galactic-gateway-${gw}" --timeout=600s >/dev/null ||
    die "galactic-gateway-${gw} did not roll out with the Worker socket"
done
# gateway-worker-patch.yaml sets GALACTIC_GATEWAY_BACKEND_HEALTH itself, so
# a gateway without it now is this check's failure, not the lab's.
health_on() {
  health_report
  [ -z "${HEALTH_MISSING}" ]
}
if wait_until 60 health_on; then
  record PASS "setup backend health on every gateway" "every NetworkGateway reports backendHealthFiltering, every pod sets it"
else
  die "backend health is off after the gateway patch: ${HEALTH_MISSING}"
fi

declare -A UID_OF
for b in "${BACKENDS[@]}"; do UID_OF[${b}]=$(attach_uid "${B_ATTACH[${b}]}"); done

session_up() { [ "$(msum "$1" "${GW_METRICS}" galactic_edge_worker_session_up)" = 1 ]; }
local_ready() { # GATEWAY BACKEND
  cond_is "$1" LocalHandoff True Ready && [[ "$(ng_local "$1" "${UID_OF[$2]}")" == "true "* ]]
}
for gw in "${GATEWAYS[@]}"; do
  wait_until 120 session_up "${gw}" || die "${gw}'s gateway holds no Worker session after 120s"
done
wait_until 300 local_ready dfw-worker2 w2 ||
  die "dfw-worker2: LocalHandoff not Ready for w2 after 300s: $(ng_cond dfw-worker2 LocalHandoff); $(ng_local dfw-worker2 "${UID_OF[w2]}")"
wait_until 300 local_ready dfw-worker3 w3 ||
  die "dfw-worker3: LocalHandoff not Ready for w3 after 300s: $(ng_cond dfw-worker3 LocalHandoff); $(ng_local dfw-worker3 "${UID_OF[w3]}")"
for gw in "${GATEWAYS[@]}"; do
  record INFO "setup ${gw} LocalHandoff" "$(ng_cond "${gw}" LocalHandoff)"
  record INFO "setup ${gw} PublicPath" "$(ng_cond "${gw}" PublicPath)"
done
bound_ok() { [ "$(bound_bindings)" -ge "${WANT_BINDINGS}" ]; }
wait_until 300 bound_ok || die "only $(bound_bindings)/${WANT_BINDINGS} gwlocal ServiceVIPBindings Bound after 300s"
wait_until 120 pool_holds 4 || die "the gateways do not hold all four pool backends after 120s"
kc -n galactic-system get networkgateways -o yaml >"${OUT}/networkgateways-setup.yaml"
kc -n galactic-system get networkservices -o yaml >"${OUT}/networkservices-setup.yaml"

# Warm-up: traffic policy and every node's bindings are in place once each
# backend answers its own VIP, through dfw-worker2.
pin dfw-worker2
warm() { ask "$2" "$3" "$4" && [ "${ANSWER_NAME}" = "$1" ]; }
for b in "${BACKENDS[@]}"; do
  for fam in 6 4; do
    if [ "${fam}" = 6 ]; then vip=${VIP6[${b}]}; else vip=${VIP4[${b}]}; fi
    wait_until 180 warm "${B_NODE[${b}]}" udp "${fam}" "${vip}" ||
      die "${b} (${B_NODE[${b}]}) never answered ${vip} through dfw-worker2 within 180s"
  done
done
unpin
record PASS setup "Worker sessions, Local handoffs Ready, ${WANT_BINDINGS} bindings Bound, every backend answers"

# --- 2. matrix ----------------------------------------------------------------------------

# cell GATEWAY BACKEND FAMILY PROTO
cell() {
  local gw=$1 b=$2 fam=$3 proto=$4 og node kind vip seen addr iface name tap cli try
  local lh0 lh1 lho0 lho1 rx0 rx1 rxo0 rxo1 rp0 rp1 ok=1 why=""
  og=$(other_gw "${gw}")
  node=${B_NODE[${b}]}
  [ "${node}" = "${gw}" ] && kind=Local || kind=Fabric
  if [ "${fam}" = 6 ]; then vip=${VIP6[${b}]}; else vip=${VIP4[${b}]}; fi
  seen=$(client_seen "${fam}")
  addr=${B_ADDR[${b}]}
  iface=${B_IFACE[${b}]}
  name="matrix ${gw} ${b}@${node} ${kind} v${fam} ${proto}"
  tap="${OUT}/cap-${gw}-${b}-v${fam}-${proto}-tap.txt"
  cli="${OUT}/cap-${gw}-${b}-v${fam}-${proto}-client.txt"

  lh0=$(local_handoffs "${gw}") lho0=$(local_handoffs "${og}")
  rx0=$(lt_stat "${gw}" "${LT_RX_DELIVER}") rxo0=$(lt_stat "${og}" "${LT_RX_DELIVER}")
  rp0=$(rule_packets "${gw}" "${vip}")

  ANSWER_NAME=""
  for try in 1 2; do
    pick_port
    docker exec "${node}" timeout 8 tcpdump -i "${iface}" -nn -l -c 2 "ip6 and port ${PORT_PICKED}" >"${tap}" 2>&1 &
    local tpid=$!
    docker exec "${CLIENT_HOST}" timeout 8 tcpdump -i eth1 -nn -l -c 1 \
      "dst port ${PORT_PICKED} and src port ${PORT}" >"${cli}" 2>&1 &
    local cpid=$!
    sleep 1.5
    local reply
    reply=$(request "${proto}" "${fam}" "${vip}" "${PORT_PICKED}")
    wait "${tpid}" || true
    wait "${cpid}" || true
    if [ -n "${reply}" ]; then
      read -r ANSWER_NAME ANSWER_PEER <<<"${reply}"
      ANSWER_PEER=${ANSWER_PEER#[}
      ANSWER_PEER=${ANSWER_PEER%]}
      if [ "${try}" -eq 2 ]; then
        RARE=$((RARE + 1))
        echo "  RARE-NO-REPLY observed: ${name}, answered on retry"
      fi
      break
    fi
    [ "${proto}" = tcp ] || break
  done
  lh1=$(local_handoffs "${gw}") lho1=$(local_handoffs "${og}")
  rx1=$(lt_stat "${gw}" "${LT_RX_DELIVER}") rxo1=$(lt_stat "${og}" "${LT_RX_DELIVER}")
  rp1=$(rule_packets "${gw}" "${vip}")

  local sport=${PORT_PICKED} t c n
  if [ -z "${ANSWER_NAME}" ]; then
    ok=0 why="${why} no-reply"
  else
    [ "${ANSWER_NAME}" = "${node}" ] || { ok=0 why="${why} answered-by=${ANSWER_NAME}"; }
    [ "$(expand6 "${ANSWER_PEER}")" = "$(expand6 "${seen}")" ] || { ok=0 why="${why} client-seen=${ANSWER_PEER}"; }
  fi
  t=$(cat "${tap}")
  n=$(grep -cF -- "IP6 ${seen}.${sport} > ${addr}.${PORT}:" <<<"${t}" || true)
  [ "${n}" -ge 1 ] || { ok=0 why="${why} tap-no-request"; }
  n=$(grep -cF -- "IP6 ${addr}.${PORT} > ${seen}.${sport}:" <<<"${t}" || true)
  [ "${n}" -ge 1 ] || { ok=0 why="${why} tap-no-reply"; }
  c=$(cat "${cli}")
  if [ "${fam}" = 6 ]; then
    n=$(grep -cF -- "IP6 ${vip}.${PORT} > ${CLIENT6}.${sport}:" <<<"${c}" || true)
  else
    n=$(grep -cF -- "IP ${vip}.${PORT} > ${CLIENT4}.${sport}:" <<<"${c}" || true)
  fi
  [ "${n}" -ge 1 ] || { ok=0 why="${why} client-reply-not-from-${vip}.${PORT}"; }
  rose "${rp0}" "${rp1}" || { ok=0 why="${why} ${gw}-rule-packets=${rp0}->${rp1}"; }
  if [ "${kind}" = Local ]; then
    rose "${lh0}" "${lh1}" || { ok=0 why="${why} local_handoffs=${lh0}->${lh1}"; }
    rose "${rx0}" "${rx1}" || { ok=0 why="${why} rx_deliver=${rx0}->${rx1}"; }
  else
    same "${lh0}" "${lh1}" || { ok=0 why="${why} ${gw}-local_handoffs=${lh0}->${lh1}"; }
    same "${lho0}" "${lho1}" || { ok=0 why="${why} ${og}-local_handoffs=${lho0}->${lho1}"; }
    same "${rx0}" "${rx1}" || { ok=0 why="${why} ${gw}-rx_deliver=${rx0}->${rx1}"; }
    same "${rxo0}" "${rxo1}" || { ok=0 why="${why} ${og}-rx_deliver=${rxo0}->${rxo1}"; }
  fi
  if [ "${ok}" -eq 1 ]; then
    record PASS "${name}" "answered by ${node} as ${seen}; handoffs ${lh0}->${lh1} rx_deliver ${rx0}->${rx1}"
  else
    record FAIL "${name}" "${why# }"
  fi
}

log "2. matrix: every gateway, backend, VIP family and protocol"
NAT0=$(nat_total)
for gw in "${GATEWAYS[@]}"; do
  lt_dump "${gw}" before-matrix
done
for gw in "${GATEWAYS[@]}"; do
  pin "${gw}"
  for b in "${BACKENDS[@]}"; do
    for fam in 6 4; do
      for proto in tcp udp; do
        cell "${gw}" "${b}" "${fam}" "${proto}"
      done
    done
  done
  unpin
done
for gw in "${GATEWAYS[@]}"; do
  lt_dump "${gw}" after-matrix
done
nat_check matrix "${NAT0}"

# --- 3. hook removal ------------------------------------------------------------------------

# own_locator NODE prints NODE's uSID /64, the blackhole route that covers
# every SID the node issues (gvpc.clab.yaml).
own_locator() {
  docker exec "$1" ip -6 route show type blackhole | awk '/metric 2048/ {print $1; exit}'
}

# hairpin_start NODE NET / hairpin_count NODE count packets NODE sends on its
# bonds from NET to NET: an SRv6 packet a gateway encapsulated toward its own
# node's locator. A Local backend's flows must never take that path.
hairpin_start() {
  local d
  for d in bond0 bond1 bond2; do
    docker exec -d "$1" sh -c "timeout 300 tcpdump -i ${d} -nn -U -w /tmp/gwlocal-hairpin-${d}.pcap 'ip6 and src net $2 and dst net $2' >/dev/null 2>&1"
  done
  sleep 1
}
hairpin_count() {
  local d n total=0
  docker exec "$1" sh -c 'pkill -INT -f gwlocal-hairpin- || true'
  sleep 1
  for d in bond0 bond1 bond2; do
    n=$(docker exec "$1" sh -c "tcpdump -nn -r /tmp/gwlocal-hairpin-${d}.pcap 2>/dev/null | wc -l")
    total=$((total + n))
    docker exec "$1" rm -f "/tmp/gwlocal-hairpin-${d}.pcap"
  done
  echo "${total}"
}

G=dfw-worker2
OG=dfw-worker3
log "3. hook removal: local_rx off ${G}'s receiving device; Worker must repair it"
NAT0=$(nat_total)
devs=$(local_rx_devs "${G}")
G_LOCATOR=$(own_locator "${G}")
if [ -z "${devs}" ] || [ -z "${G_LOCATOR}" ]; then
  record FAIL "hook ${G} local_rx present" "devices '${devs}', own locator '${G_LOCATOR}'"
else
  record INFO "hook ${G} local_rx before" "$(tr '\n' ' ' <<<"${devs}"); own locator ${G_LOCATOR}"
  pin "${G}"
  ua0=$(local_unavailable "${G}")
  hairpin_start "${G}" "${G_LOCATOR}"
  for d in ${devs}; do
    docker exec "${G}" tc filter del dev "${d%%:*}" ingress pref "${d##*:}"
  done
  t0=${SECONDS}
  restored="" seen_false=""
  probes=0 probes_ok=0 pool_probes=0 pool_ok=0 pool_w2=0 pool_n=0 pool_other=0
  while [ $((SECONDS - t0)) -lt $((WORKER_RESYNC_S + 30)) ]; do
    c=$(ng_cond "${G}" LocalHandoff)
    [[ -n "${seen_false}" || "${c}" != False* ]] || seen_false="$((SECONDS - t0))s: ${c}"
    if [ -z "${restored}" ] && [ -n "$(local_rx_devs "${G}")" ]; then restored=$((SECONDS - t0)); fi
    probes=$((probes + 1))
    if ask udp 6 "${VIP6[w2]}" && [ "${ANSWER_NAME}" = dfw-worker2 ]; then probes_ok=$((probes_ok + 1)); fi
    # The pool's other backends answer whatever happens to w2's flows.
    for b in w1 w3 w4; do
      pool_probes=$((pool_probes + 1))
      if ask udp 6 "${VIP6[${b}]}" && [ "${ANSWER_NAME}" = "${B_NODE[${b}]}" ]; then pool_ok=$((pool_ok + 1)); fi
    done
    # w2 stays in the pool during the gap, so the pool's flows Maglev sends
    # to w2 go unanswered; the rest must be answered by the others.
    pool_n=$((pool_n + 1))
    if ask udp 6 "${VIP6[pool]}"; then
      if [ "${ANSWER_NAME}" = dfw-worker2 ]; then pool_w2=$((pool_w2 + 1)); else pool_other=$((pool_other + 1)); fi
    fi
    if [ -n "${restored}" ] && [ $((SECONDS - t0 - restored)) -ge 8 ]; then break; fi
    sleep 1
  done
  ua1=$(local_unavailable "${G}")
  hairpins=$(hairpin_count "${G}")
  if [ -n "${restored}" ] && [ "${restored}" -le $((WORKER_RESYNC_S + 10)) ]; then
    record PASS "hook Worker re-attached local_rx" "after ${restored}s (resync interval ${WORKER_RESYNC_S}s)"
  else
    record FAIL "hook Worker re-attached local_rx" "${restored:-not}${restored:+s, past} within $((WORKER_RESYNC_S + 10))s"
  fi
  check "hook w2 flows never encapsulated" "${hairpins} packet(s) from ${G_LOCATOR} to itself on ${G}'s bonds; local_unavailable ${ua0} -> ${ua1}" \
    [ "${hairpins}" -eq 0 ]
  check "hook other backends answered via ${G}" "w1, w3 and w4's VIPs ${pool_ok}/${pool_probes}" \
    [ "${pool_ok}" -eq "${pool_probes}" ]
  check "hook pool VIP answered by its other backends" "${pool_other}/${pool_n} by w1/w3/w4, ${pool_w2} by w2, $((pool_n - pool_other - pool_w2)) unanswered (Maglev's w2 share)" \
    [ "${pool_other}" -gt 0 ]
  record INFO "hook w2 VIP through ${G} during the gap" "${probes_ok}/${probes} answered"
  record INFO "hook LocalHandoff during the gap" "${seen_false:-stayed True}"
  echo "  note: Worker repairs local_rx at its resync and reads the scope Ready in the same pass" \
    "(plan, apply, read), so no status reports the hook missing; flows to w2 through ${G} have no" \
    "receiver until then, and are dropped rather than encapsulated"
  wait_until 90 local_ready "${G}" w2 || true
  lh0=$(local_handoffs "${G}") rx0=$(lt_stat "${G}" "${LT_RX_DELIVER}")
  flows "${G}" tcp 6 "${VIP6[w2]}" 4
  ok_tcp=${F_OK}
  flows "${G}" udp 6 "${VIP6[w2]}" 4
  ok_udp=${F_OK}
  lh1=$(local_handoffs "${G}") rx1=$(lt_stat "${G}" "${LT_RX_DELIVER}")
  check "hook restored: w2 Local through ${G}" "tcp ${ok_tcp}/4 udp ${ok_udp}/4; handoffs ${lh0}->${lh1} rx_deliver ${rx0}->${rx1}" \
    eval '[ "${ok_tcp}" -eq 4 ] && [ "${ok_udp}" -eq 4 ] && rose "${lh0}" "${lh1}" && rose "${rx0}" "${rx1}"'
  ua2=$(local_unavailable "${G}")
  check "hook no local_unavailable after repair" "${ua1} -> ${ua2}" [ "${ua2}" = "${ua1}" ]
  unpin
fi
nat_check hook "${NAT0}"

# --- 4. TAP carrier loss ----------------------------------------------------------------------

log "4. TAP carrier loss: w2's TAP on ${G} loses its reader"
NAT0=$(nat_total)
check "carrier pool held 4 before" "" pool_holds 4
ua0=$(local_unavailable "${G}")
HOLD=1
kc -n ns80 exec deploy/gwlocal-w2 -c vmm -- sh -c 'touch /tmp/hold; kill "$(cat /tmp/bridge.pid)"'
t0=${SECONDS}
not_ready() { cond_is "${G}" LocalHandoff False LocalHandoffNotReady; }
if wait_until 90 not_ready; then
  record PASS "carrier LocalHandoff False" "after $((SECONDS - t0))s; w2 $(ng_local "${G}" "${UID_OF[w2]}")"
else
  record FAIL "carrier LocalHandoff False" "not within 90s: $(ng_cond "${G}" LocalHandoff)"
fi
w2_local=$(ng_local "${G}" "${UID_OF[w2]}")
check "carrier w2 in localBackends not ready" "${w2_local}" eval '[[ "${w2_local}" == "false "* ]]'
w2_notready() { w2_health_is LocalHandoffNotReady; }
if wait_until 60 w2_notready; then
  record PASS "carrier w2 binding LocalHandoffNotReady" "after $((SECONDS - t0))s"
else
  record FAIL "carrier w2 binding LocalHandoffNotReady" "$( (binding_health gwlocal-pool-tcp dfw-worker2; binding_health gwlocal-pool-udp dfw-worker2) | tr '\n' ';')"
fi
if wait_until 30 pool_holds 3; then
  record PASS "carrier w2 out of the pool on every gateway" "after $((SECONDS - t0))s"
else
  record FAIL "carrier w2 out of the pool on every gateway" "$(for gw in "${GATEWAYS[@]}"; do echo -n "${gw}=$(rule_backends "${gw}" "${VIP6[pool]}" tcp) "; done)"
fi
kc -n galactic-system get networkservices gwlocal-pool-tcp gwlocal-pool-udp -o yaml >"${OUT}/pool-services-w2-out.yaml"
kc -n galactic-system get networkgateway "${G}" -o yaml >"${OUT}/networkgateway-${G}-w2-out.yaml"
ua1=$(local_unavailable "${G}")
for gw in "${GATEWAYS[@]}"; do
  pin "${gw}"
  for fam in 6 4; do
    if [ "${fam}" = 6 ]; then vip=${VIP6[pool]}; else vip=${VIP4[pool]}; fi
    for proto in tcp udp; do
      flows "${gw}" "${proto}" "${fam}" "${vip}" "${FLOWS}"
      check "carrier pool v${fam} ${proto} through ${gw}" "${F_OK}/${FLOWS} answered:${F_BY}" \
        eval '[ "${F_OK}" -eq "${FLOWS}" ] && [ -z "${F_COUNT[dfw-worker2]:-}" ]'
    done
  done
  unpin
done
ua2=$(local_unavailable "${G}")
check "carrier local_unavailable at most transient" "${ua0} -> ${ua1} until w2 left the pool, ${ua2} after" [ "${ua2}" = "${ua1}" ]

kc -n ns80 exec deploy/gwlocal-w2 -c vmm -- rm -f /tmp/hold
HOLD=0
t0=${SECONDS}
if wait_until 120 local_ready "${G}" w2; then
  record PASS "carrier recovered: LocalHandoff Ready" "after $((SECONDS - t0))s"
else
  record FAIL "carrier recovered: LocalHandoff Ready" "$(ng_cond "${G}" LocalHandoff); $(ng_local "${G}" "${UID_OF[w2]}")"
fi
w2_clear() { w2_health_is clear; }
check "carrier recovered: w2 health cleared" "" wait_until 60 w2_clear
check "carrier recovered: pool holds 4 on every gateway" "" wait_until 60 pool_holds 4
pin "${G}"
lh0=$(local_handoffs "${G}")
flows "${G}" tcp 6 "${VIP6[w2]}" 4
ok_tcp=${F_OK}
flows "${G}" udp 4 "${VIP4[w2]}" 4
ok_udp=${F_OK}
lh1=$(local_handoffs "${G}")
check "carrier recovered: w2 Local through ${G}" "tcp/v6 ${ok_tcp}/4 udp/v4 ${ok_udp}/4; handoffs ${lh0}->${lh1}" \
  eval '[ "${ok_tcp}" -eq 4 ] && [ "${ok_udp}" -eq 4 ] && rose "${lh0}" "${lh1}"'
unpin
nat_check carrier "${NAT0}"

# --- 5. public path -----------------------------------------------------------------------------

log "5. public path: ${G}'s public_uplink_table loses its next hop"
NAT0=$(nat_total)
saved=$(uplink_read "${G}")
if [ -z "${saved}" ] || [ "${saved:0:8}" = 00000000 ]; then
  record FAIL "public ${G} public_uplink_table row" "no next hop before the step (${saved:-unreadable})"
else
  record INFO "public ${G} public_uplink_table before" "${saved}"
  advs0=$(rule_advs "${G}")
  advso0=$(rule_advs "${OG}")
  transit tr1 ip -6 route show match "${VIP6[w1]}" >"${OUT}/tr1-routes-before.txt"
  transit tr1 ip -4 route show match "${VIP4[w1]}" >>"${OUT}/tr1-routes-before.txt"
  ZERO=$(printf '0%.0s' $(seq $((${#saved}))))
  UPLINK_SAVED=${saved}
  uplink_write "${G}" "${ZERO}"
  t0=${SECONDS}
  withdrawn() { cond_is "${G}" PublicPath False FamilyWithdrawn; }
  if wait_until 45 withdrawn; then
    record PASS "public PublicPath False/FamilyWithdrawn" "after $((SECONDS - t0))s: $(ng_cond "${G}" PublicPath | cut -c1-160)"
  else
    record FAIL "public PublicPath False/FamilyWithdrawn" "$(ng_cond "${G}" PublicPath)"
  fi
  fw6=$(msum "${G}" "${GW_METRICS}" galactic_edge_family_withdrawn 'family="ipv6"')
  fw4=$(msum "${G}" "${GW_METRICS}" galactic_edge_family_withdrawn 'family="ipv4"')
  check "public galactic_edge_family_withdrawn" "ipv6=${fw6} ipv4=${fw4}" eval '[ "${fw6}" = 1 ] && [ "${fw4}" = 1 ]'
  uplink_missing() { [[ "$(ng_local "${G}" "${UID_OF[w2]}")" == "false PublicUplinkMissing"* ]]; }
  if wait_until 45 uplink_missing; then
    record PASS "public w2 reported PublicUplinkMissing" "status.localBackends: $(ng_local "${G}" "${UID_OF[w2]}")"
  else
    record FAIL "public w2 reported PublicUplinkMissing" "status.localBackends: $(ng_local "${G}" "${UID_OF[w2]}")"
  fi
  w2_notready() { w2_health_is LocalHandoffNotReady; }
  check "public w2 binding LocalHandoffNotReady" "" wait_until 60 w2_notready
  if wait_until 30 pool_holds 3; then
    record PASS "public w2 out of the pool on every gateway" "after $((SECONDS - t0))s"
  else
    record FAIL "public w2 out of the pool on every gateway" "$(for gw in "${GATEWAYS[@]}"; do echo -n "${gw}=$(rule_backends "${gw}" "${VIP6[pool]}" tcp) "; done)"
  fi
  advs_gone() { [ "$(rule_advs "${G}")" -eq 0 ]; }
  if wait_until 45 advs_gone; then
    record PASS "public ${G} -v4/-v6 BGPAdvertisements deleted" "${advs0} -> 0; ${OG} keeps $(rule_advs "${OG}")/${advso0}"
  else
    record FAIL "public ${G} -v4/-v6 BGPAdvertisements deleted" "${advs0} -> $(rule_advs "${G}")"
  fi
  # galactic-cni's GC tick may rebuild the row; hold it at zero.
  [ "$(uplink_read "${G}")" = "${ZERO}" ] || {
    record INFO "public row rebuilt during the step" "zeroed again"
    uplink_write "${G}" "${ZERO}"
  }
  # The transit learns the site's VIP prefixes from the edge nodes' FRR,
  # which originates them to Null0, not from the gateway's -v4/-v6
  # advertisements (EVPN paths the transit never receives). The gateway can
  # neither see nor withdraw that aggregate (docs/gateway/architecture.md,
  # D44), so the lab withdraws it on ${G} for one family at a time, as an
  # operator's tooling would with the gateway's withdrawal, and checks that
  # clients then enter through ${OG}. The pins are off for this, or they
  # would hide the withdrawal.
  unpin
  for fam in 6 4; do
    vips=()
    for b in w1 w3 w4 pool; do
      if [ "${fam}" = 6 ]; then vips+=("${VIP6[${b}]}"); else vips+=("${VIP4[${b}]}"); fi
    done
    n=$(tr1_via "${G}" "${fam}")
    if [ "${n}" -eq 0 ]; then
      record FAIL "public v${fam} tr1 routes via ${G} before" "no route via ${G}: $(tr1_routes "${fam}" | tr '\n' ';')"
      continue
    fi
    FRR_WITHDRAWN+=("${fam}")
    originate_site "${fam}" no
    t0=${SECONDS}
    gone() { [ "$(tr1_via "${G}" "$1")" -eq 0 ] && [ "$(tr1_via "${OG}" "$1")" -gt 0 ]; }
    if wait_until 60 gone "${fam}"; then
      record PASS "public v${fam} route via ${G} gone at tr1" "after $((SECONDS - t0))s; via ${OG} only"
    else
      record FAIL "public v${fam} route via ${G} gone at tr1" "$(tr1_routes "${fam}" | tr '\n' ';')"
    fi
    {
      tr1_routes "${fam}"
      transit tr1 vtysh -c "show bgp ipv${fam} unicast ${vips[3]}" 2>&1 || true
    } >"${OUT}/tr1-routes-v${fam}-withdrawn.txt"
    rpg0=$(rp_sum "${G}" "${vips[@]}") rpo0=$(rp_sum "${OG}" "${vips[@]}")
    ok=0 total=0
    for vip in "${vips[@]}"; do
      for proto in tcp udp; do
        flows unpinned "${proto}" "${fam}" "${vip}" 2
        ok=$((ok + F_OK)) total=$((total + 2))
      done
    done
    rpg1=$(rp_sum "${G}" "${vips[@]}") rpo1=$(rp_sum "${OG}" "${vips[@]}")
    check "public v${fam} unpinned clients enter through ${OG}" \
      "${ok}/${total} answered; rule packets ${G} ${rpg0}->${rpg1}, ${OG} ${rpo0}->${rpo1}" \
      eval '[ "${ok}" -eq "${total}" ] && [ "${rpg1}" -eq "${rpg0}" ] && [ "${rpo1}" -gt "${rpo0}" ]'
    originate_site "${fam}" yes
    FRR_WITHDRAWN=()
    back() { [ "$(tr1_via "${G}" "$1")" -gt 0 ]; }
    check "public v${fam} route via ${G} back at tr1" "" wait_until 60 back "${fam}"
  done
  for gw in "${OG}" "${G}"; do
    pin "${gw}"
    for fam in 6 4; do
      if [ "${fam}" = 6 ]; then vip=${VIP6[pool]}; else vip=${VIP4[pool]}; fi
      for proto in tcp udp; do
        flows "${gw}" "${proto}" "${fam}" "${vip}" "${FLOWS}"
        check "public pool v${fam} ${proto} through ${gw}" "${F_OK}/${FLOWS} answered:${F_BY}" \
          eval '[ "${F_OK}" -eq "${FLOWS}" ] && [ -z "${F_COUNT[dfw-worker2]:-}" ]'
      done
    done
    unpin
  done
  pin "${OG}"
  for b in w1 w3 w4; do
    for fam in 6 4; do
      if [ "${fam}" = 6 ]; then vip=${VIP6[${b}]}; else vip=${VIP4[${b}]}; fi
      for proto in tcp udp; do
        flows "${OG}" "${proto}" "${fam}" "${vip}" 2
        check "public ${b} v${fam} ${proto} through ${OG}" "${F_OK}/2:${F_BY}" \
          eval '[ "${F_OK}" -eq 2 ] && [ -n "${F_COUNT[${B_NODE[${b}]}]:-}" ]'
      done
    done
  done
  nat_check public "${NAT0}"
  # Not asserted: w2's own rule keeps its only backend, Unhealthy or not,
  # and w2's replies need ${G}'s public_uplink_table, which is unset, so they
  # may fall to the VPC's NAT route.
  nat_w0=$(nat_total)
  flows "${OG}" tcp 6 "${VIP6[w2]}" 2
  record INFO "public w2 (Local on ${G}) through ${OG}" "${F_OK}/2 answered; egress shard counters ${nat_w0} -> $(nat_total)"
  unpin

  uplink_write "${G}" "${saved}"
  UPLINK_SAVED=""
  t0=${SECONDS}
  covered() { cond_is "${G}" PublicPath True Covered; }
  if wait_until 45 covered; then
    record PASS "public restored: PublicPath True/Covered" "after $((SECONDS - t0))s"
  else
    record FAIL "public restored: PublicPath True/Covered" "$(ng_cond "${G}" PublicPath)"
  fi
  fw6=$(msum "${G}" "${GW_METRICS}" galactic_edge_family_withdrawn 'family="ipv6"')
  fw4=$(msum "${G}" "${GW_METRICS}" galactic_edge_family_withdrawn 'family="ipv4"')
  check "public restored: family_withdrawn 0" "ipv6=${fw6} ipv4=${fw4}" eval '[ "${fw6}" = 0 ] && [ "${fw4}" = 0 ]'
  check "public restored: w2 Local handoff Ready" "" wait_until 60 local_ready "${G}" w2
  w2_clear() { w2_health_is clear; }
  check "public restored: w2 health cleared" "" wait_until 60 w2_clear
  check "public restored: pool holds 4 on every gateway" "" wait_until 60 pool_holds 4
  advs_back() { [ "$(rule_advs "${G}")" -eq "${advs0}" ]; }
  check "public restored: ${G} re-advertised" "${advs0} -v4/-v6 advertisements" wait_until 60 advs_back
  pin "${G}"
  flows "${G}" tcp 6 "${VIP6[w2]}" 4
  ok_tcp=${F_OK}
  flows "${G}" udp 4 "${VIP4[w2]}" 4
  ok_udp=${F_OK}
  check "public restored: w2 Local through ${G}" "tcp/v6 ${ok_tcp}/4 udp/v4 ${ok_udp}/4" \
    eval '[ "${ok_tcp}" -eq 4 ] && [ "${ok_udp}" -eq 4 ]'
  unpin
fi

for gw in "${GATEWAYS[@]}"; do
  lt_dump "${gw}" end
  docker exec "${gw}" tail -200 /var/log/galactic-worker.log >"${OUT}/worker-${gw}.log" 2>&1 || true
done
kc -n galactic-system get networkgateways -o yaml >"${OUT}/networkgateways-end.yaml"
log "done"
