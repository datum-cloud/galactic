#!/bin/bash
# verify-fabric-routing.sh — drive one site's fabric routers from their
# ConfigMaps to the typed API and through every activation path, on the live
# lab:
#
#   1. Shadow: every router's imported revision stages with no change.
#   2. CRD: a release commits every router, with its BGP sessions held.
#   3. A change release commits a new static route on ROUTER.
#   4. A failing release (a peer pointed at the wrong AS) fails on ROUTER,
#      which restores its previous revision by itself.
#   5. A release rolls forward once the peer is fixed.
#   6. ROUTER's pod restarts with the API unreachable and restores its
#      checkpoint.
#
# Operator actions run through fabric-router-controller's own commands.
# The site's routers stay on the CRD source afterwards; `fabric-router-
# controller source DEPLOYMENT ConfigMap` hands each back. Needs
# deploy:fabric-routing first.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

SITE=${SITE:-dfw}
ROUTER=${ROUTER:-dfw-worker3}
DOMAIN="lab-${SITE}"
NS=galactic-system
CP=$(control_plane "${SITE}")
CHANGE_ROUTE=verify-fabric-routing
CHANGE_PREFIX=2001:db8:fff0::/64
# The agent fails an activation whose required peers stay down this long.
STABILIZATION=60
# Lift the offline test's API block after this long whatever happens.
OFFLINE_LIMIT=300

k() { docker exec -i "${CP}" kubectl -n "${NS}" "$@"; }

# Whatever the script changes on the lab, it puts back on any exit: the
# peer step 4 breaks, and the API block step 6 installs.
RESTORE_PEER=""
UNBLOCK="for t in iptables ip6tables; do while \$t -S OUTPUT | grep -q verify-fabric-routing; do
  \$t -S OUTPUT | grep verify-fabric-routing | head -1 | sed 's/^-A/-D/' | xargs \$t; done; done"
REMOVE_ROUTE=""
cleanup() {
  if [[ -n "${REMOVE_ROUTE}" ]]; then
    k delete bgpstaticroute "${CHANGE_ROUTE}" --ignore-not-found >/dev/null || true
  fi
  if [[ -n "${RESTORE_PEER}" ]]; then
    k patch bgppeer "${RESTORE_PEER% *}" --type=merge -p "{\"spec\":{\"peerASN\":${RESTORE_PEER#* }}}" >/dev/null || true
  fi
  docker exec "${ROUTER}" sh -c "${UNBLOCK}" || true
  rm -f "${KUBECONFIG_FILE}"
}
KUBECONFIG_FILE=$(mktemp)
trap cleanup EXIT
kind get kubeconfig --internal --name "${SITE}" >"${KUBECONFIG_FILE}"

# frc runs fabric-router-controller's operator commands against the site.
frc() {
  docker run --rm --network kind --user "$(id -u)" -v "${KUBECONFIG_FILE}:/kubeconfig:ro" \
    -e KUBECONFIG=/kubeconfig fabric-router-controller:latest "$@"
}

fail() {
  echo "FAIL $*" >&2
  frc status >&2 || true
  exit 1
}

# wait_for SECONDS DESCRIPTION COMMAND... retries COMMAND until it succeeds.
wait_for() {
  local limit=$1 what=$2
  shift 2
  for _ in $(seq 1 $((limit / 3))); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  fail "${what} within ${limit}s"
}

dep() { k get fabricrouterdeployment "$1" -o jsonpath="$2"; }

# staged_matches DEPLOYMENT CLASS: the deployment's current candidate is
# staged, with change class CLASS.
staged_matches() {
  local cand
  cand=$(dep "$1" '{.spec.candidateRevisionRef.name}')
  [[ -n "${cand}" && "$(dep "$1" '{.status.staged.revision}')" == "${cand}" &&
    "$(dep "$1" '{.status.staged.class}')" == "$2" ]]
}

release_phase() { k get fabricreleaseauthorization "$1" -o jsonpath='{.status.phase}'; }
release_done() { [[ "$(release_phase "$1")" =~ ^(Completed|Failed|Cancelled)$ ]]; }

# release NAME [DEPLOYMENT...] creates a release at the domain's next fleet
# sequence, waits for it to finish and sets PHASE to how it ended. It runs
# in this shell, so a failure stops the script with its own reason.
release() {
  local name=$1 seq
  shift
  seq=$(k get fabricreleaseauthorizations -o jsonpath="{range .items[?(@.spec.routingDomain==\"${DOMAIN}\")]}{.spec.fleetSequence}{\"\n\"}{end}" |
    sort -n | tail -1)
  frc release create "${name}" --domain "${DOMAIN}" --sequence $((${seq:-0} + 1)) "$@"
  wait_for 600 "release ${name} to finish" release_done "${name}"
  frc release status "${name}"
  PHASE=$(release_phase "${name}")
}

frr_pod() {
  k get pods -l app.kubernetes.io/name=fabric-router --field-selector "spec.nodeName=$1" -o name
}

vtysh() {
  local node=$1
  shift
  k exec "$(frr_pod "${node}")" -c frr -- vtysh -c "$*"
}

# established NODE counts NODE's Established BGP sessions.
established() {
  vtysh "$1" "show bgp summary json" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for af in d.values() for p in af.get("peers",{}).values() if p.get("state")=="Established"))'
}

all_established() {
  local node
  for node in "${NODES[@]}"; do
    [[ "$(established "${node}")" -eq "${SESSIONS[${node}]}" ]] || return 1
  done
}

stamp=$(date +%s)
mapfile -t NODES < <(k get fabricrouterdeployments -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[[ ${#NODES[@]} -gt 0 ]] || fail "${SITE} has no FabricRouterDeployments; run deploy:fabric-routing"
[[ " ${NODES[*]} " == *" ${ROUTER} "* ]] || fail "${ROUTER} has no FabricRouterDeployment"
declare -A SESSIONS
for node in "${NODES[@]}"; do
  SESSIONS[${node}]=$(established "${node}")
  echo "${node}: ${SESSIONS[${node}]} sessions Established"
done

echo "--- 1. Shadow: the typed API reproduces every router"
for node in "${NODES[@]}"; do
  if [[ "$(dep "${node}" '{.status.effectiveSource}')" != CRD ]]; then
    frc source "${node}" Shadow
  fi
done
for node in "${NODES[@]}"; do
  if [[ "$(dep "${node}" '{.status.effectiveSource}')" == CRD ]]; then
    echo "ok   ${node} is already on CRD"
    continue
  fi
  wait_for 120 "${node} to stage its candidate with no change" staged_matches "${node}" NoChange
  echo "ok   ${node} stages $(dep "${node}" '{.spec.candidateRevisionRef.name}') with no change"
done

echo "--- 2. CRD: a release commits every router with its sessions held"
for node in "${NODES[@]}"; do
  frc source "${node}" CRD
done
release "verify-${stamp}-enroll" "${NODES[@]}"
[[ "${PHASE}" == Completed ]] || fail "the enrollment release ended ${PHASE}"
for node in "${NODES[@]}"; do
  [[ "$(dep "${node}" '{.status.appliedEpoch}')" == "$(dep "${node}" '{.spec.activationEpoch}')" ]] ||
    fail "${node} did not commit its epoch"
done
wait_for 120 "every session to be Established again" all_established
echo "ok   every router committed, every session Established"

echo "--- 3. A change release commits a new static route on ${ROUTER}"
before=$(dep "${ROUTER}" '{.spec.candidateRevisionRef.name}')
vtysh "${ROUTER}" "show ipv6 route ${CHANGE_PREFIX}" | grep -q static &&
  fail "${ROUTER} already routes ${CHANGE_PREFIX}, so adding it would change nothing"
REMOVE_ROUTE=1
k apply -f - <<EOF
apiVersion: galactic.datumapis.com/v1alpha1
kind: BGPStaticRoute
metadata:
  name: ${CHANGE_ROUTE}
  namespace: ${NS}
spec:
  action: Discard
  addressFamily: ipv6
  destination: ${CHANGE_PREFIX}
  routerRef:
    name: ${ROUTER}
EOF
candidate_moved() { [[ "$(dep "${ROUTER}" '{.spec.candidateRevisionRef.name}')" != "$1" ]]; }
wait_for 120 "a new candidate for ${ROUTER}" candidate_moved "${before}"
wait_for 120 "${ROUTER} to stage the change as non-disruptive" staged_matches "${ROUTER}" NonDisruptive
changed=$(dep "${ROUTER}" '{.spec.candidateRevisionRef.name}')
release "verify-${stamp}-change" "${ROUTER}"
[[ "${PHASE}" == Completed ]] || fail "the change release ended ${PHASE}"
vtysh "${ROUTER}" "show ipv6 route ${CHANGE_PREFIX}" | grep -q static || fail "${CHANGE_PREFIX} is not installed"
echo "ok   ${ROUTER} committed ${changed} and installed ${CHANGE_PREFIX}"

echo "--- 4. A failing release fails on ${ROUTER}, which recovers by itself"
peer=$(k get bgppeers -o jsonpath="{range .items[?(@.spec.routerRef.name==\"${ROUTER}\")]}{.metadata.name} {.spec.peerASN}{\"\n\"}{end}" |
  grep -v '^$' | sort | head -1)
peer_name=${peer% *}
# A generated peer is rewritten by its topology, so the broken AS would not
# last; this step needs a hand-authored or imported one.
[[ -z "$(k get bgppeer "${peer_name}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}')" ]] ||
  fail "${ROUTER}'s peers come from a FabricTopology; pick a ROUTER on a site deploy:fabric-topology has not converted"
peer_asn=${peer#* }
RESTORE_PEER="${peer_name} ${peer_asn}"
k patch bgppeer "${peer_name}" --type=merge -p "{\"spec\":{\"peerASN\":$((peer_asn + 99))}}"
wait_for 120 "a new candidate for ${ROUTER}" candidate_moved "${changed}"
wait_for 120 "${ROUTER} to stage the bad peer" staged_matches "${ROUTER}" SessionReset
release "verify-${stamp}-fail" "${ROUTER}"
k patch bgppeer "${peer_name}" --type=merge -p "{\"spec\":{\"peerASN\":${peer_asn}}}"
RESTORE_PEER=""
[[ "${PHASE}" == Failed ]] || fail "a release with a dead required peer ended ${PHASE}"
[[ "$(dep "${ROUTER}" '{.status.appliedRevision}')" == "${changed}" ]] ||
  fail "${ROUTER} did not restore ${changed}"
[[ "$(k get fabricreleaseauthorization "verify-${stamp}-fail" -o jsonpath='{.status.recoveryVerified}')" == true ]] ||
  fail "the failed release did not see ${ROUTER} recover"
wait_for 120 "${ROUTER}'s sessions to be Established again" all_established
echo "ok   the release failed, ${ROUTER} restored ${changed} after ${STABILIZATION}s, sessions Established"

echo "--- 5. A release rolls forward once the peer is fixed"
back_to() { [[ "$(dep "${ROUTER}" '{.spec.candidateRevisionRef.name}')" == "$1" ]]; }
wait_for 120 "${ROUTER}'s candidate to return to ${changed}" back_to "${changed}"
wait_for 120 "${ROUTER} to stage ${changed} with no change" staged_matches "${ROUTER}" NoChange
release "verify-${stamp}-forward" "${ROUTER}"
[[ "${PHASE}" == Completed ]] || fail "the roll-forward ended ${PHASE}"
echo "ok   ${ROUTER} committed ${changed} again"

echo "--- 6. ${ROUTER} restarts without the API and restores its checkpoint"
api4=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${CP}")
api6=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "${CP}")
svc=$(k exec "$(frr_pod "${ROUTER}")" -c config-agent -- printenv KUBERNETES_SERVICE_HOST | tr -d '\r')
# The timer lifts the block even if this script is killed; the EXIT trap
# lifts it on any other exit. Both are in place before the first rule.
docker exec -d "${ROUTER}" sh -c "sleep ${OFFLINE_LIMIT}; ${UNBLOCK}"
block() { docker exec "${ROUTER}" "$1" -I OUTPUT -d "$2" -p tcp --dport "$3" -m comment --comment verify-fabric-routing -j DROP; }
[[ -n "${api4}" ]] && block iptables "${api4}" 6443
[[ -n "${api6}" ]] && block ip6tables "${api6}" 6443
case "${svc}" in *:*) block ip6tables "${svc}" 443 ;; ?*) block iptables "${svc}" 443 ;; esac
sandbox=$(docker exec "${ROUTER}" crictl pods --name fabric-router --state ready -q | head -1)
started=$(date +%s)
docker exec "${ROUTER}" crictl stopp "${sandbox}" >/dev/null
frr_running() {
  local pod
  pod=$(docker exec "${ROUTER}" crictl pods --name fabric-router --state ready -q | head -1)
  [[ -n "${pod}" && "${pod}" != "${sandbox}" ]] &&
    docker exec "${ROUTER}" crictl ps --pod "${pod}" --name '^frr$' --state running -q | grep -q .
}
wait_for $((OFFLINE_LIMIT - 30)) "FRR to start on ${ROUTER} without the API" frr_running
pod=$(docker exec "${ROUTER}" crictl pods --name fabric-router --state ready -q | head -1)
init=$(docker exec "${ROUTER}" crictl ps -a --pod "${pod}" --name frr-init -q | head -1)
docker exec "${ROUTER}" crictl logs "${init}" 2>&1 | grep -q "restoring committed ${changed}" ||
  fail "${ROUTER} did not restore its checkpoint: $(docker exec "${ROUTER}" crictl logs "${init}" 2>&1 | tail -3)"
echo "ok   FRR started from the checkpoint $(($(date +%s) - started))s after the restart"
frr=$(docker exec "${ROUTER}" crictl ps --pod "${pod}" --name '^frr$' -q | head -1)
offline_established() {
  [[ "$(docker exec "${ROUTER}" crictl exec "${frr}" vtysh -c 'show bgp summary json' |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for af in d.values() for p in af.get("peers",{}).values() if p.get("state")=="Established"))')" \
    -eq "${SESSIONS[${ROUTER}]}" ]]
}
wait_for 120 "${ROUTER}'s sessions to come up without the API" offline_established
docker exec "${ROUTER}" crictl exec "${frr}" vtysh -c "show ipv6 route ${CHANGE_PREFIX}" | grep -q static ||
  fail "${CHANGE_PREFIX} is missing after the offline restart"
echo "ok   ${ROUTER} runs ${changed} without the API, every session Established"
docker exec "${ROUTER}" sh -c "${UNBLOCK}"
agent_reports() {
  local hb
  hb=$(dep "${ROUTER}" '{.status.heartbeatTime}')
  [[ -n "${hb}" && $(date -d "${hb}" +%s) -gt ${started} ]]
}
wait_for 180 "${ROUTER}'s agent to report once the API is back" agent_reports
echo "ok   ${ROUTER}'s agent reports again once the API is back"

echo "--- Cleanup: remove the change"
k delete bgpstaticroute "${CHANGE_ROUTE}"
REMOVE_ROUTE=""
wait_for 120 "a new candidate for ${ROUTER}" candidate_moved "${changed}"
wait_for 120 "${ROUTER} to stage the removal" staged_matches "${ROUTER}" NonDisruptive
release "verify-${stamp}-cleanup" "${ROUTER}"
[[ "${PHASE}" == Completed ]] || fail "the cleanup release ended ${PHASE}"
echo "PASS fabric routing on ${SITE}: Shadow, CRD, change, failure and recovery, offline restart"
