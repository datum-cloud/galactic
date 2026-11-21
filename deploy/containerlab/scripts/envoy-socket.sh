#!/bin/bash
# envoy-socket.sh: prove a real Envoy reaches ns80's guests through the
# galactic-vrf sidecar's Worker socket claims (docs/envoy-socket.md, #1439).
#
# Usage: envoy-socket.sh [up|down|probe] OUTDIR
#
# With no mode it sets up, runs every window and cleans up. probe sets up,
# sends one request per VPC and backend, and cleans up. up only sets up
# and leaves the fixture, Worker and the backends running (task
# deploy:ns80-envoy); down only cleans up (task delete:ns80-envoy).
#
# Envoy (resources/envoy-socket) runs on dfw-worker with the
# galactic-vrf sidecar, which holds one Worker socket claim per ns80 VPC.
# Its upstream sockets bind to each VPC's VRF in the pod and send from the
# gateway fd20:80:ff04::1, which both VPCs' proxy attachments hold. Each VPC
# has a local backend (ns80's guest on dfw-worker) and a remote one:
#
#   REMOTE=dfw-worker4  ns80's guests on dfw's second compute worker (#1460),
#                       which dfw's cluster already knows
#   REMOTE=sjc          ns80's guests on sjc-worker, mirrored into dfw's
#                       cluster as an EndpointSlice and a VPCAttachment per
#                       VPC, standing in for a single control plane
#
# REMOTE defaults to dfw-worker4 when dfw-worker4 runs ns80's guests, and to
# sjc otherwise.
#
# Windows, each recorded in results.json:
#
#   fresh    5 requests per VPC and backend, one upstream connection each
#   reused   5 requests per VPC and backend over one pooled connection
#   sockets  the pooled upstream sockets: gateway source, bound to the VRF
#   captures where each request and reply crossed, during fresh and reused
#   state    routes in the pod and host VRFs, Worker's advertisements, the
#            remote node's route back, the sidecar's metrics
#   move     VPC 80's local guest goes and comes back
#   replace  a rollout replaces the Envoy pod
#   cleanup  the fixture goes; nothing of the claims is left on dfw-worker
#
# When a precondition does not hold it changes nothing, writes the reason to
# OUTDIR/precondition and exits 0. Otherwise it always tries to clean up and
# exits non-zero when any check failed. The cleanup hands Worker's scopes
# back (galactic-worker handback), restarts galactic-router on dfw-worker,
# removes everything the run created or patched, and checks the lab is back
# to its deployed state; task verify:ns80 and task verify then run on the same
# deploy.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

MODE=run
case "${1:-}" in
  up | down | probe)
    MODE=$1
    shift
    ;;
esac
OUT=${1:?usage: envoy-socket.sh [up|down|probe] OUTDIR}
mkdir -p "${OUT}/logs" "${OUT}/configs"
OUT=$(cd "${OUT}" && pwd)
: >"${OUT}/results.tsv"
: >"${OUT}/volatile.tsv"
rm -f "${OUT}/precondition"
# record, volatile and seen, and FAILED.
source "${SCRIPT_DIR}/baseline-lib.sh"
# The rig (rig_start, rig, in_pod), its captures (cap, cap_wait, cap_stop),
# pod_pid, precondition, DEBUG_IMAGE and PHYSICAL_IFS.
source "${SCRIPT_DIR}/handoff-lib.sh"
RIG=envoy-socket-rig

REPO=$(cd "${SCRIPT_DIR}/../../.." && pwd)
NS=ns80-envoy
DFW=$(control_plane dfw)
SJC=$(control_plane sjc)
NODE=dfw-worker
FIXTURE_DIR=/galactic/resources/envoy-socket
GW=fd20:80:ff04::1
LOCAL_ADDR=fd20:80:ff01::1:0:0
ENVOY_IMAGE=envoyproxy/envoy@sha256:127e33c48c60be9a148cf9256d52e734ceda28aa344145023933116c7e524beb
ENVOY_TAG=envoyproxy/envoy:v1.32.3
VRF_IMAGE=galactic-vrf:lab
WORKER_BIN=/opt/galactic-worker/galactic-worker
ADV=bgpadvertisements.galactic.datumapis.com
N=5
REPLACE_TIMEOUT=${REPLACE_TIMEOUT:-120}
PATHS=(80/local 80/remote 81/local 81/remote)
declare -A VRF=([80]=G000000080V [81]=G000000081V)
declare -A OTHER=([80]=81 [81]=80)

kd() { docker exec -i "${DFW}" kubectl "$@"; }
ks() { docker exec -i "${SJC}" kubectl "$@"; }
# kx CP ARGS... runs kubectl in the control plane CP.
kx() {
  local cp="$1"
  shift
  docker exec -i "${cp}" kubectl "$@"
}
running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" = true ]; }

# ready_pod CP NAMESPACE LABEL prints the newest Ready pod matching LABEL
# that is not being deleted.
ready_pod() {
  kx "$1" -n "$2" get pods -l "$3" -o json </dev/null | jq -r '
    [.items[] | select(.metadata.deletionTimestamp == null)
     | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
    | sort_by(.metadata.creationTimestamp) | last | .metadata.name // empty'
}

# pod_pid_of POD prints the sandbox PID of pod POD of NS on NODE.
pod_pid_of() {
  local id
  id=$(docker exec "${NODE}" crictl pods --namespace "${NS}" --name "^$1\$" -q | head -1)
  [ -n "${id}" ] || return 1
  docker exec "${NODE}" crictl inspectp "${id}" | jq -r '.info.pid'
}

# Preconditions ---------------------------------------------------------------

for c in "${NODE}" "${DFW}" "${SJC}" sjc-worker; do
  running "${c}" || precondition "lab container ${c} is not running (task deploy)"
done
command -v jq >/dev/null || precondition "jq is not installed"
if [ "${MODE}" != down ]; then
command -v go >/dev/null || precondition "go is not installed (worker-fabric.sh builds Worker)"
if ! "${SCRIPT_DIR}/verify-ns80.sh" >"${OUT}/logs/verify-ns80-before.log" 2>&1; then
  precondition "ns80 is not ready: $(tail -1 "${OUT}/logs/verify-ns80-before.log") (task deploy:ns80)"
fi
if kd get namespace "${NS}" >/dev/null 2>&1; then
  precondition "${NS} is already deployed; an earlier run did not remove it (task delete:ns80-envoy)"
fi
out=$(docker exec "${NODE}" pgrep -f "^${WORKER_BIN}" || true)
[ -z "${out}" ] || precondition "Worker already runs on ${NODE} (task delete:ns80-envoy stops it and hands its scopes back)"
out=$(kd -n galactic-system get "${ADV}" -l galactic.datumapis.com/worker-vpc -o name 2>/dev/null || true)
[ -z "${out}" ] || precondition "Worker BGPAdvertisements are left over: $(tr '\n' ' ' <<<"${out}")"
out=$(docker exec "${NODE}" ip -j link show | jq -r '.[] | select((.ifalias // "") | startswith("galactic-local:")) | .ifname')
[ -z "${out}" ] || precondition "Local links are left on ${NODE}: $(tr '\n' ' ' <<<"${out}")"
if docker inspect "${RIG}" >/dev/null 2>&1; then
  precondition "a rig container ${RIG} already exists; an earlier run did not clean up"
fi
# The cleanup returns Worker's scopes with galactic-worker handback (#1462).
[ -d "${REPO}/internal/worker/handback" ] ||
  precondition "this checkout has no galactic-worker handback (#1462); merge integration/galactic-worker first"
out=$("${SCRIPT_DIR}/worker-fabric.sh" scopes "${NODE}" 2>/dev/null || true)
if grep -q 'galactic-worker:' <<<"${out}"; then
  precondition "Worker owns VPC scopes on ${NODE} already; hand them back first"
fi
fi

# The remote backends.
dfw_worker4_guests() {
  running dfw-worker4 || return 1
  local n
  n=$(kd -n ns80 get pods -l 'app in (vpc-a2,vpc-b2)' -o json </dev/null | jq '[.items[]
    | select(.spec.nodeName == "dfw-worker4" and .metadata.deletionTimestamp == null)
    | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length')
  [ "${n}" = 2 ]
}
if [ -z "${REMOTE:-}" ]; then
  REMOTE=sjc
  dfw_worker4_guests && REMOTE=dfw-worker4
  # down follows what up deployed: the sjc mirror lives in the fixture.
  if [ "${MODE}" = down ] && kd -n "${NS}" get vpcattachment mirror-sjc-80 >/dev/null 2>&1; then
    REMOTE=sjc
  fi
fi
declare -A BCP BNS BAPP BNODE BADDR BATT
for v in 80 81; do
  app=vpc-a
  [ "${v}" = 81 ] && app=vpc-b
  BCP[${v}/local]=${DFW} BNS[${v}/local]=ns80 BAPP[${v}/local]=${app} BNODE[${v}/local]=${NODE}
  BADDR[${v}/local]=${LOCAL_ADDR} BATT[${v}/local]=${app}
  case "${REMOTE}" in
    dfw-worker4)
      BCP[${v}/remote]=${DFW} BAPP[${v}/remote]=${app}2 BNODE[${v}/remote]=dfw-worker4
      BADDR[${v}/remote]=fd20:80:ff01::2:0:0 BATT[${v}/remote]=${app}2
      ;;
    sjc)
      BCP[${v}/remote]=${SJC} BAPP[${v}/remote]=${app} BNODE[${v}/remote]=sjc-worker
      BADDR[${v}/remote]=fd20:80:ff02::1:0:0 BATT[${v}/remote]=mirror-sjc-${v}
      ;;
    *) precondition "REMOTE=${REMOTE}: want dfw-worker4 or sjc" ;;
  esac
  BNS[${v}/remote]=ns80
done
if [ "${REMOTE}" = dfw-worker4 ] && ! dfw_worker4_guests; then
  precondition "REMOTE=dfw-worker4, but dfw-worker4 runs no ready ns80 guests (vpc-a2, vpc-b2; #1460)"
fi
volatile remote "${REMOTE}"
volatile checkout "$(git -C "${REPO}" rev-parse HEAD)"
volatile kernel "$(docker exec "${NODE}" uname -r)"
"${SCRIPT_DIR}/worker-fabric.sh" scopes "${NODE}" >"${OUT}/logs/scopes-before.txt" 2>&1 || true

# Cleanup ---------------------------------------------------------------------

WORKER_STARTED=0
MOVED=0
BACKENDS_STARTED=0
# The ns80 attachments this run gave addresses carry this annotation, so a
# later down finds them too.
ADDED=envoy-socket.galactic.datumapis.com/added-addresses

stop_backends() {
  local p pod
  for p in "${PATHS[@]}"; do
    pod=$(ready_pod "${BCP[${p}]}" "${BNS[${p}]}" "app=${BAPP[${p}]}" || true)
    [ -n "${pod}" ] || continue
    kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- cat /tmp/envoy-backend.log \
      </dev/null >"${OUT}/logs/backend-${p//\//-}.log" 2>&1 || true
    kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- pkill -f '[e]nvoy-backend[.]py' </dev/null >/dev/null 2>&1 || true
    kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- rm -f /tmp/envoy-backend.py /tmp/envoy-backend.log \
      </dev/null >/dev/null 2>&1 || true
  done
}

# leftovers prints what of the claims is left on NODE, one item per line.
leftovers() {
  local v
  kd -n galactic-system get "${ADV}" -l "galactic.datumapis.com/worker-node=${NODE}" -o name </dev/null 2>/dev/null |
    sed 's/^/advertisement /' || true
  docker exec "${NODE}" ip -j link show | jq -r '.[] | select((.ifalias // "") | startswith("galactic-local:"))
    | "link \(.ifname) \(.ifalias)"' || true
  for v in 80 81; do
    docker exec "${NODE}" ip -6 route show vrf "${VRF[${v}]}" "${GW}/128" 2>/dev/null | sed "s/^/route ${VRF[${v}]} /" || true
  done
}

CLEANED=0
# STAGE is the fixture's staging directory while it exists.
STAGE=""
cleanup() {
  local status=$? i left
  set +e
  [ "${CLEANED}" = 1 ] && return
  CLEANED=1
  [ -n "${STAGE}" ] && rm -rf "${STAGE}"
  echo "=== cleanup ==="
  [ "${status}" -ne 0 ] && record run "the run completed" yes "no (exit ${status})"
  cap_stop
  kd -n "${NS}" logs deploy/envoy -c envoy --tail=-1 >"${OUT}/logs/envoy.log" 2>&1
  kd -n "${NS}" logs deploy/envoy -c galactic-vrf --tail=-1 >"${OUT}/logs/galactic-vrf.log" 2>&1
  [ "${BACKENDS_STARTED}" = 1 ] && stop_backends
  if [ "${MOVED}" = 1 ]; then
    kd -n ns80 scale deployment/guest-a --replicas="${GUEST_A_REPLICAS:-1}"
    kd -n ns80 rollout status deployment/guest-a --timeout=120s
    "${SCRIPT_DIR}/publish-attachments.sh" ns80 dfw >>"${OUT}/logs/publish-attachments.log" 2>&1
  fi
  kd delete namespace "${NS}" --ignore-not-found --wait=true --timeout=240s
  kd delete clusterrolebinding,clusterrole galactic-vrf --ignore-not-found
  docker exec "${DFW}" rm -rf "${FIXTURE_DIR}"
  for i in $(kd -n ns80 get vpcattachments -o json </dev/null |
    jq -r --arg a "${ADDED}" '.items[] | select(.metadata.annotations[$a] == "true") | .metadata.name'); do
    kd -n ns80 patch vpcattachment "${i}" --type=json -p "[{\"op\":\"remove\",\"path\":\"/spec/interface/addresses\"},
      {\"op\":\"remove\",\"path\":\"/metadata/annotations/${ADDED//\//~1}\"}]" >/dev/null
  done
  left=""
  for i in $(seq 1 60); do
    left=$(leftovers)
    [ -z "${left}" ] && break
    sleep 2
  done
  printf '%s\n' "${left}" >"${OUT}/logs/leftovers-after.txt"
  record cleanup "no Worker BGPAdvertisement on ${NODE}" 0 "$(grep -c '^advertisement' <<<"${left}" || true)"
  record cleanup "no Local link on ${NODE}" 0 "$(grep -c '^link' <<<"${left}" || true)"
  record cleanup "no gateway /128 in the host VRFs" 0 "$(grep -c '^route' <<<"${left}" || true)"
  if [ "${WORKER_STARTED}" = 1 ]; then
    docker exec "${NODE}" cat /var/log/galactic-worker.log >"${OUT}/logs/galactic-worker.log" 2>&1
    NODES=${NODE} "${SCRIPT_DIR}/worker-fabric.sh" stop >>"${OUT}/logs/worker.log" 2>&1
    record cleanup "Worker stopped on ${NODE}" yes \
      "$([ -z "$(docker exec "${NODE}" pgrep -f "^${WORKER_BIN}")" ] && echo yes || echo no)"
    restore_worker_scopes
  fi
  rig_stop
  restore_checks
  finish
}

# restore_worker_scopes hands the stopped Worker's scopes back on NODE, which
# also removes Local's links, filters, pins and claims, restarts
# galactic-router there so it writes the tenant routes again, and removes
# the files worker-fabric.sh put on the node.
restore_worker_scopes() {
  local pod ds
  record restore "galactic-worker handback succeeds on ${NODE}" yes \
    "$(docker exec "${NODE}" "${WORKER_BIN}" handback --node-name "${NODE}" \
      >"${OUT}/logs/handback.log" 2>&1 && echo yes || echo no)"
  pod=$(kd -n galactic-system get pods -l app.kubernetes.io/name=galactic-router -o json </dev/null |
    jq -r --arg n "${NODE}" '.items[] | select(.spec.nodeName == $n) | .metadata.name' | head -1)
  ds=$(kd -n galactic-system get pod "${pod}" -o json </dev/null |
    jq -r '.metadata.ownerReferences[]? | select(.kind == "DaemonSet") | .name')
  if [ -n "${pod}" ] && [ -n "${ds}" ]; then
    kd -n galactic-system delete pod "${pod}" --wait=true --timeout=120s >/dev/null 2>&1
    record restore "galactic-router on ${NODE} restarted and Ready" yes \
      "$(kd -n galactic-system rollout status "daemonset/${ds}" --timeout=300s \
        >>"${OUT}/logs/router-restart.log" 2>&1 && echo yes || echo no)"
  else
    record restore "galactic-router on ${NODE} restarted and Ready" yes "no (pod ${pod:-none}, DaemonSet ${ds:-none})"
  fi
  docker exec "${NODE}" rm -rf "$(dirname "${WORKER_BIN}")" /var/log/galactic-worker.log
}

# oneline joins a value's lines, so a list fits one results.tsv cell.
oneline() { tr '\n' ' ' <<<"$1" | sed 's/ *$//'; }

# restore_checks asserts the lab is back to its deployed state.
restore_checks() {
  local img out p pod d
  d=${OUT}/after
  # Images the run imported go again.
  for img in "${VRF_IMAGE}" "${ENVOY_TAG}"; do
    if [ -f "${BASE_DIR}/images-present" ] && ! grep -qxF "${img}" "${BASE_DIR}/images-present"; then
      docker exec "${NODE}" crictl rmi "${img}" >/dev/null 2>&1
      record restore "image ${img} removed from ${NODE}" yes "$(has_image "${img}" && echo no || echo yes)"
    fi
  done
  # The fixture and the sidecar.
  record restore "namespace ${NS} is gone" yes "$(kd get namespace "${NS}" >/dev/null 2>&1 && echo no || echo yes)"
  out=$(kd get clusterrole,clusterrolebinding galactic-vrf -o name 2>/dev/null || true)
  record restore "the sidecar's ClusterRole and binding are gone" 0 "$(grep -c . <<<"${out}" || true)"
  out=$(kd get pods -A -o json </dev/null | jq '[.items[].spec.containers[].name | select(. == "galactic-vrf")] | length')
  record restore "no galactic-vrf sidecar runs in dfw" 0 "${out}"
  record restore "the fixture's copy on ${DFW} is gone" yes \
    "$(docker exec "${DFW}" test -e "${FIXTURE_DIR}" && echo no || echo yes)"
  for p in "${PATHS[@]}"; do
    pod=$(ready_pod "${BCP[${p}]}" "${BNS[${p}]}" "app=${BAPP[${p}]}" || true)
    [ -n "${pod}" ] || continue
    out=$(kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- pgrep -f '[e]nvoy-backend[.]py' </dev/null || true)
    record restore "no backend server left in ${p}'s guest" "" "$(oneline "${out}")"
  done
  record restore "the rig container is gone" yes "$(docker inspect "${RIG}" >/dev/null 2>&1 && echo no || echo yes)"
  # Worker and Local on the node.
  # Anchored to the binary the case starts: the node runs other processes,
  # in every pod, whose command lines can mention galactic-worker.
  record restore "no Worker process on ${NODE}" "" "$(oneline "$(docker exec "${NODE}" pgrep -f "^${WORKER_BIN}" || true)")"
  out=$("${SCRIPT_DIR}/worker-fabric.sh" scopes "${NODE}" 2>/dev/null || true)
  printf '%s\n' "${out}" >"${OUT}/logs/scopes-after.txt"
  record restore "no Worker-owned fence record on ${NODE}" 0 "$(grep -c 'galactic-worker:' <<<"${out}" || true)"
  record restore "no Worker socket on ${NODE}" yes \
    "$(docker exec "${NODE}" test -e /run/galactic-worker/worker.sock && echo no || echo yes)"
  record restore "no Worker claims on ${NODE}" 0 \
    "$(docker exec "${NODE}" sh -c 'ls -A /var/lib/galactic-worker/claims 2>/dev/null | wc -l')"
  record restore "no Local pins on ${NODE}" yes \
    "$(docker exec "${NODE}" test -e /sys/fs/bpf/galactic-local && echo no || echo yes)"
  out=$(leftovers)
  record restore "no Local link, gateway route or Worker advertisement" 0 "$(grep -c . <<<"${out}" || true)"
  # Everything patched or restarted is back to its deployed spec and ready.
  if [ -d "${BASE_DIR}" ]; then
    deployed_state "${d}"
    for f in ns80-deployments ns80-vpcattachments galactic-system-daemonsets; do
      record restore "${f} match the deployed spec" yes \
        "$(diff -u "${BASE_DIR}/${f}.json" "${d}/${f}.json" >"${OUT}/logs/diff-${f}.txt" && echo yes || echo no)"
    done
  else
    record restore "deployed spec comparison (a down run has no baseline)" - skipped
  fi
  out=$(kd -n ns80 get deployments -o json </dev/null |
    jq -r '.items[] | select((.status.availableReplicas // 0) != .spec.replicas) | .metadata.name')
  record restore "every ns80 Deployment is available" "" "$(oneline "${out}")"
  out=$(kd -n galactic-system get daemonsets -o json </dev/null |
    jq -r '.items[] | select(.status.numberReady != .status.desiredNumberScheduled) | .metadata.name')
  record restore "every galactic-system DaemonSet in dfw is ready" "" "$(oneline "${out}")"
}

finish() {
  jq -R -s 'split("\n") | map(select(length > 0) | split("\t")
    | {scenario: .[0], check: .[1], expected: .[2], observed: .[3], result: .[4]})' \
    "${OUT}/results.tsv" >"${OUT}/results.json"
  echo "=== $(jq length "${OUT}/results.json") checks, $(jq '[.[] | select(.result == "fail")] | length' \
    "${OUT}/results.json") failed (REMOTE=${REMOTE}); results in ${OUT}/results.json ==="
  jq -r '.[] | select(.result == "fail") | "FAIL \(.scenario): \(.check): want \(.expected), got \(.observed)"' \
    "${OUT}/results.json"
  echo "Next, on this deploy: lab-bgp-rebind (#1464), task verify:ns80 and task verify"
  exit "${FAILED}"
}
# Baseline ----------------------------------------------------------------------

# What the cleanup compares the lab with: the specs of everything the case
# patches or restarts, and the images dfw-worker already had.
BASE_DIR=${OUT}/baseline
deployed_state() {
  local d="$1"
  mkdir -p "${d}"
  kd -n ns80 get deployments -o json </dev/null | jq -S '[.items[] | {name: .metadata.name, spec: .spec}]' \
    >"${d}/ns80-deployments.json"
  kd -n ns80 get vpcattachments -o json </dev/null | jq -S '[.items[] | {name: .metadata.name, spec: .spec,
    annotations: (.metadata.annotations // {} | del(.["kubectl.kubernetes.io/last-applied-configuration"]))}]' \
    >"${d}/ns80-vpcattachments.json"
  kd -n galactic-system get daemonsets -o json </dev/null |
    jq -S '[.items[] | {name: .metadata.name, template: .spec.template}]' >"${d}/galactic-system-daemonsets.json"
}
has_image() { docker exec "${NODE}" crictl inspecti "$1" >/dev/null 2>&1; }
if [ "${MODE}" != down ]; then
  deployed_state "${BASE_DIR}"
  : >"${BASE_DIR}/images-present"
  for img in "${VRF_IMAGE}" "${ENVOY_TAG}"; do
    has_image "${img}" && echo "${img}" >>"${BASE_DIR}/images-present"
  done
fi
if [ "${MODE}" = down ]; then
  BACKENDS_STARTED=1
  if [ -n "$(docker exec "${NODE}" pgrep -f "^${WORKER_BIN}" || true)" ]; then
    WORKER_STARTED=1
  fi
  cleanup
fi
trap cleanup EXIT

# Setup -----------------------------------------------------------------------

echo "=== setup (REMOTE=${REMOTE}) ==="
rig_start

echo "--- images ---"
docker build -t "${VRF_IMAGE}" -f "${REPO}/containers/galactic-vrf/Dockerfile" "${REPO}" >"${OUT}/logs/build.log" 2>&1
docker save "${VRF_IMAGE}" | docker exec -i "${NODE}" ctr --namespace k8s.io images import - >/dev/null
docker image inspect "${ENVOY_TAG}" >/dev/null 2>&1 || docker pull "${ENVOY_IMAGE}" >/dev/null
docker save "${ENVOY_TAG}" | docker exec -i "${NODE}" ctr --namespace k8s.io images import - >/dev/null
# The saved index keeps the digest; if the import did not, the kubelet
# pulls the image instead.
if ! docker exec "${NODE}" crictl inspecti "${ENVOY_IMAGE}" >/dev/null 2>&1; then
  volatile envoy-image "not found by digest after import; pulled by the kubelet"
fi

echo "--- Worker on ${NODE} ---"
cat >"${OUT}/configs/allowlist.yaml" <<EOF
serviceAccounts:
  - serviceAccount: galactic-system/galactic-router
    capabilities: [fabric.routes]
  - serviceAccount: ${NS}/galactic-vrf
    capabilities: [local.socket, fabric.srv6]
EOF
WORKER_STARTED=1
NODES=${NODE} WORKER_ALLOWLIST="${OUT}/configs/allowlist.yaml" "${SCRIPT_DIR}/worker-fabric.sh" start \
  >"${OUT}/logs/worker.log" 2>&1

# A routed link's pod end needs SYS_PTRACE and SYS_ADMIN beside NET_ADMIN
# and BPF; a packaged Worker gets them only from the routed-link profile
# Component (config/galactic-worker/profiles/routed-link). Here Worker runs
# as a bare process in the Kind node (worker-fabric.sh), not the packaged
# DaemonSet, so the run records what it actually holds.
volatile worker-placement "bare process in ${NODE} (worker-fabric.sh), not the packaged DaemonSet"
wpid=$(docker exec "${NODE}" pgrep -f "^${WORKER_BIN}" | head -1)
capeff=$(docker exec "${NODE}" awk '/^CapEff:/ {print $2}' "/proc/${wpid}/status" 2>/dev/null || true)
volatile worker-capeff "${capeff:-unknown}"
for c in NET_ADMIN:12 SYS_PTRACE:19 SYS_ADMIN:21 BPF:39; do
  has=no
  if [ -n "${capeff}" ] && (((16#${capeff} >> ${c#*:}) & 1)); then
    has=yes
  fi
  record setup "Worker's effective capabilities include CAP_${c%%:*}" yes "${has}"
done

# Worker takes a destination's addresses only from its VPCAttachment's
# spec.interface.addresses. Fill them in where ns80's attachments have none
# (#1460 adds them); cleanup takes them out again.
ensure_addresses() {
  local att="$1" addr="$2" have
  have=$(kd -n ns80 get vpcattachment "${att}" -o json </dev/null | jq -r '.spec.interface.addresses // [] | length')
  if [ "${have}" = 0 ]; then
    kd -n ns80 patch vpcattachment "${att}" --type=merge \
      -p "{\"spec\":{\"interface\":{\"addresses\":[\"${addr}/96\"]}}}" >/dev/null
    kd -n ns80 annotate vpcattachment "${att}" "${ADDED}=true" --overwrite >/dev/null
    volatile "added-addresses" "ns80/${att} ${addr}/96"
  fi
}
for p in "${PATHS[@]}"; do
  [ "${BCP[${p}]}" = "${DFW}" ] && ensure_addresses "${BATT[${p}]}" "${BADDR[${p}]}"
done

echo "--- TLS ---"
kd create namespace "${NS}" >/dev/null
# A self-signed key made for this run only: it reaches the cluster through
# a pipe and is never written to OUT or the repository.
tls=$(docker run --rm --entrypoint sh "${DEBUG_IMAGE}" -c 'openssl req -x509 -newkey ec \
  -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=envoy-socket \
  -keyout /tmp/k -out /tmp/c 2>/dev/null && base64 -w0 /tmp/c && echo && base64 -w0 /tmp/k && echo')
kd apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: envoy-tls
  namespace: ${NS}
type: kubernetes.io/tls
data:
  tls.crt: $(sed -n 1p <<<"${tls}")
  tls.key: $(sed -n 2p <<<"${tls}")
EOF
unset tls

echo "--- fixture ---"
STAGE=$(mktemp -d)
stage=${STAGE}
cp -r "${RESOURCES_DIR}/envoy-socket" "${stage}/"
cp -r "${CONFIG_DIR}/galactic-vrf" "${stage}/envoy-socket/dfw/galactic-vrf"
if [ "${REMOTE}" = sjc ]; then
  sed -i 's/address: "fd20:80:ff01::2:0:0"/address: "fd20:80:ff02::1:0:0"/' "${stage}/envoy-socket/dfw/envoy-config.yaml"
fi
cp "${stage}/envoy-socket/dfw/envoy-config.yaml" "${OUT}/configs/envoy-config.yaml"
docker exec "${DFW}" rm -rf "${FIXTURE_DIR}"
docker exec "${DFW}" mkdir -p "$(dirname "${FIXTURE_DIR}")"
docker cp "${stage}/envoy-socket" "${DFW}:${FIXTURE_DIR}"
rm -rf "${stage}"
STAGE=""
apply_k "${DFW}" "${FIXTURE_DIR}/dfw/" >"${OUT}/logs/apply.log"
for v in 80 81; do
  kd -n "${NS}" patch vpcattachment "proxy-${v}" --subresource=status --type=merge \
    -p "{\"status\":{\"vpc\":\"${v}\",\"vpcAttachment\":\"e${v}\",\"node\":\"${NODE}\"}}" >/dev/null
done

# The sjc mirror stands in for a single control plane: dfw's cluster gets
# sjc's per-pod EndpointSlice of each VPC's guest, SID annotation and all,
# and a VPCAttachment recording it on sjc-worker. Its tenant identifier,
# <vpc>-s<vpc>, matches only the mirror attachment. Worker on dfw-worker
# knows nothing of sjc-worker, so it reports these destinations unresolved
# or Fabric; either way the sidecar must not route them over the link.
if [ "${REMOTE}" = sjc ]; then
  echo "--- sjc mirror ---"
  for v in 80 81; do
    slice=$(ks -n ns80 get endpointslices -l "galactic.datum.net/tenant-id=${v}-${v}" -o json </dev/null | jq '.items[0] // empty')
    if [ -z "${slice}" ] || [ "$(jq -r '.metadata.annotations["galactic.datum.net/srv6-sid"] // ""' <<<"${slice}")" = "" ]; then
      record setup "sjc's VPC ${v} guest has an EndpointSlice with a SID" yes no
      exit 1
    fi
    jq --arg ns "${NS}" --arg name "mirror-sjc-${v}" --arg tenant "${v}-s${v}" '{
        apiVersion: "discovery.k8s.io/v1", kind: "EndpointSlice",
        metadata: {name: $name, namespace: $ns,
          labels: ((.metadata.labels // {}) + {"galactic.datum.net/tenant-id": $tenant}),
          annotations: ((.metadata.annotations // {}) | del(.["galactic.datum.net/sandbox-id"])
            + {"galactic.datum.net/tenant-id": $tenant})},
        addressType: .addressType,
        endpoints: [.endpoints[] | del(.targetRef)]}
      + (if .ports then {ports: .ports} else {} end)' <<<"${slice}" | tee "${OUT}/configs/mirror-slice-${v}.json" |
      kd apply -f - >/dev/null
    kd apply -f - >/dev/null <<EOF
apiVersion: galactic.datumapis.com/v1alpha1
kind: VPCAttachment
metadata:
  name: mirror-sjc-${v}
  namespace: ${NS}
spec:
  vpc:
    name: "${v}"
  interface:
    name: eth0
    mode: Netns
    addresses:
      - ${BADDR[${v}/remote]}/96
EOF
    kd -n "${NS}" patch vpcattachment "mirror-sjc-${v}" --subresource=status --type=merge \
      -p "{\"status\":{\"vpc\":\"${v}\",\"vpcAttachment\":\"s${v}\",\"node\":\"sjc-worker\"}}" >/dev/null
  done
fi

echo "--- backends ---"
# start_backend PATH copies envoy-backend.py into PATH's guest and starts it.
start_backend() {
  local p="$1" pod i out
  pod=$(ready_pod "${BCP[${p}]}" "${BNS[${p}]}" "app=${BAPP[${p}]}")
  [ -n "${pod}" ] || return 1
  kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec -i "${pod}" -- sh -c 'cat >/tmp/envoy-backend.py' \
    <"${SCRIPT_DIR}/envoy-backend.py"
  # pkill runs on its own, with no shell: a shell's command line would hold
  # the server's path and match the pattern, and pkill would end the shell
  # before it starts the server.
  kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- pkill -f '[e]nvoy-backend[.]py' </dev/null || true
  kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- sh -c "setsid nohup python3 /tmp/envoy-backend.py \
    ${p#*/} ${p%%/*} ${BNODE[${p}]} 8080 >/tmp/envoy-backend.log 2>&1 </dev/null & exit 0" </dev/null
  for i in $(seq 1 25); do
    out=$(kx "${BCP[${p}]}" -n "${BNS[${p}]}" exec "${pod}" -- ss -Hltn 'sport = :8080' </dev/null || true)
    [ -n "${out}" ] && return 0
    sleep 0.2
  done
  return 1
}
BACKENDS_STARTED=1
for p in "${PATHS[@]}"; do
  start_backend "${p}" || {
    record setup "${p} backend listens" yes no
    exit 1
  }
done

echo "--- Envoy ---"
if ! kd -n "${NS}" rollout status deployment/envoy --timeout=300s >"${OUT}/logs/rollout.log" 2>&1; then
  record setup "the Envoy pod becomes Ready" yes no
  kd -n "${NS}" describe pods >"${OUT}/logs/envoy-describe.txt" 2>&1 || true
  exit 1
fi
record setup "the Envoy pod becomes Ready" yes yes
POD=$(ready_pod "${DFW}" "${NS}" app=envoy)
POD_UID=$(kd -n "${NS}" get pod "${POD}" -o jsonpath='{.metadata.uid}')
volatile envoy-pod "${POD} ${POD_UID}"

# Helpers over the Envoy pod ---------------------------------------------------

# client ARGS... runs ARGS in the Envoy pod's client container.
client() { kd -n "${NS}" exec "${POD}" -c client -- "$@" </dev/null; }

stats() { client curl -s -g 'http://[::1]:9901/stats?filter=^cluster\.vpc'; }
# envoy_stat FILE CLUSTER NAME reads one counter from a stats snapshot.
envoy_stat() { awk -F': ' -v k="cluster.$2.$3" '$1 == k { v = $2 } END { print v + 0 }' "$1"; }
metrics() { client curl -s -g 'http://[::1]:9182/metrics'; }
# metric FILE NAME [LABEL] sums NAME's samples whose labels contain LABEL.
metric() {
  awk -v n="galactic_ingress_sidecar_$2" -v l="${3:-}" '
    index($1, n "{") == 1 || $1 == n { if (l == "" || index($1, l) > 0) s += $2 } END { print s + 0 }' "$1"
}

# links discovers the routed links: POD_END, IVS, IVP in the pod and
# HOST_END on the node, per VPC.
declare -A POD_END IVS IVP HOST_END
links() {
  local pid v j h
  pid=$(pod_pid_of "${POD}")
  PPID_POD=${pid}
  j=$(in_pod "${pid}" ip -j -d link show)
  h=$(docker exec "${NODE}" ip -j link show)
  for v in 80 81; do
    POD_END[${v}]=$(jq -r --arg m "${VRF[${v}]}" '[.[] | select(.master == $m and .linkinfo.info_kind == "veth"
      and (.ifname | startswith("ivs") | not)) | .ifname] | first // empty' <<<"${j}")
    IVS[${v}]=$(jq -r --arg m "${VRF[${v}]}" '[.[] | select(.master == $m and (.ifname | startswith("ivs")))
      | .ifname] | first // empty' <<<"${j}")
    IVP[${v}]=${IVS[${v}]/ivs/ivp}
    HOST_END[${v}]=$(jq -r --arg a "galactic-local:${v}/" '[.[] | select((.ifalias // "") | startswith($a))
      | .ifname] | first // empty' <<<"${h}")
    volatile "links-${v}" "pod=${POD_END[${v}]} ivs=${IVS[${v}]} ivp=${IVP[${v}]} host=${HOST_END[${v}]}"
  done
}

# Requests ---------------------------------------------------------------------

# Every nonce has the same length, so no nonce is part of another.
RUN=es$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')
volatile run "${RUN}"
SEQ=0
nonce() {
  SEQ=$((SEQ + 1))
  printf '%s%05d' "${RUN}" "${SEQ}"
}

# curl_args NONCE PATH prints one request's curl options, one per line.
curl_args() {
  printf '%s\n' -sk -g --http1.1 --max-time 10 -H "X-Nonce: $1" -w '\n@@%{http_code}\n' "https://[::1]:8443/$2"
}

# answers W PATH POOL FILE checks the answers in FILE (one curl output per
# request: a JSON line and @@<code>) against PATH and records them.
answers() {
  local w="$1" p="$2" pool="$3" f="$4" v=${2%%/*} site=${2#*/} ok peer
  ok=$(jq -R -s --arg v "${v}" --arg s "${site}" '[split("\n")[] | fromjson? | objects
    | select(.vpc == $v and .site == $s and .nonce != "")] | length' "${f}")
  peer=$(jq -R -s --arg gw "${GW}" '[split("\n")[] | fromjson? | objects | select(.peer.address == $gw)] | length' "${f}")
  record "${w}" "${p}/${pool}: answers from VPC ${v}'s ${site} backend" "${N}" "${ok}"
  record "${w}" "${p}/${pool}: the backend saw the gateway as the source" "${N}" "${peer}"
}

# fresh W PATH sends N requests, one curl each, and checks them and the
# fresh cluster's new upstream connections.
fresh() {
  local w="$1" p="$2" c="vpc${2%%/*}-${2#*/}-fresh" f i n before after
  f="${OUT}/logs/${w}/${p//\//-}-fresh.txt"
  : >"${f}"
  stats >"${f}.before"
  for i in $(seq 1 "${N}"); do
    n=$(nonce)
    printf '%s\t%s\n' "${n}" "${p}" >>"${OUT}/logs/${w}/nonces.tsv"
    mapfile -t a < <(curl_args "${n}" "${p}/fresh")
    client curl "${a[@]}" >>"${f}" 2>&1 || true
  done
  stats >"${f}.after"
  before=$(envoy_stat "${f}.before" "${c}" upstream_cx_total)
  after=$(envoy_stat "${f}.after" "${c}" upstream_cx_total)
  answers "${w}" "${p}" fresh "${f}"
  record "${w}" "${p}/fresh: new upstream connections (${c})" "${N}" "$((after - before))"
}

# reused W PATH [FIRST] sends N requests in one curl invocation and checks
# that the pooled cluster served them over one upstream connection. FIRST=1
# expects exactly one new connection; later windows may reuse an open one.
reused() {
  local w="$1" p="$2" first="${3:-0}" c="vpc${2%%/*}-${2#*/}-pooled" f i n args=() cx rq ports
  f="${OUT}/logs/${w}/${p//\//-}-reused.txt"
  stats >"${f}.before"
  for i in $(seq 1 "${N}"); do
    n=$(nonce)
    printf '%s\t%s\n' "${n}" "${p}" >>"${OUT}/logs/${w}/nonces.tsv"
    [ "${i}" -gt 1 ] && args+=(--next)
    mapfile -t a < <(curl_args "${n}" "${p}/pooled")
    args+=("${a[@]}")
  done
  client curl "${args[@]}" >"${f}" 2>&1 || true
  stats >"${f}.after"
  cx=$(($(envoy_stat "${f}.after" "${c}" upstream_cx_total) - $(envoy_stat "${f}.before" "${c}" upstream_cx_total)))
  rq=$(($(envoy_stat "${f}.after" "${c}" upstream_rq_total) - $(envoy_stat "${f}.before" "${c}" upstream_rq_total)))
  ports=$(jq -R -s '[split("\n")[] | fromjson? | objects | .peer.port] | unique | length' "${f}")
  answers "${w}" "${p}" pooled "${f}"
  if [ "${first}" = 1 ]; then
    record "${w}" "${p}/pooled: new upstream connections (${c})" 1 "${cx}"
  else
    record "${w}" "${p}/pooled: new upstream connections (${c})" "at most 1" \
      "$([ "${cx}" -le 1 ] && echo "at most 1" || echo "${cx}")"
  fi
  record "${w}" "${p}/pooled: upstream requests (${c})" "${N}" "${rq}"
  record "${w}" "${p}/pooled: source ports the backend saw" 1 "${ports}"
  volatile "${w}-${p}-pooled-port" "$(jq -R -s -c '[split("\n")[] | fromjson? | objects | .peer.port] | unique' "${f}")"
}

window() {
  mkdir -p "${OUT}/logs/$1"
  touch "${OUT}/logs/$1/nonces.tsv"
  echo "=== $1 ==="
}

# Captures ---------------------------------------------------------------------

# capture W starts the window's captures: the routed links' ends, the
# sidecar's encapsulation pair and eth0 in the pod, the host ends, the local
# guests' eth0, and dfw-worker's physical bond members.
capture() {
  local w="$1" v gpid
  for v in 80 81; do
    cap "${w}" "pod${v}" "pid:${PPID_POD}" "${POD_END[${v}]}"
    cap "${w}" "encap${v}" "pid:${PPID_POD}" "${IVS[${v}]}" "${IVP[${v}]}"
    cap "${w}" "host${v}" node "${HOST_END[${v}]}"
    gpid=$(pod_pid ns80 "${BAPP[${v}/local]}")
    cap "${w}" "guest${v}" "pid:${gpid}" eth0
  done
  cap "${w}" podeth0 "pid:${PPID_POD}" eth0
  cap "${w}" physical node "${PHYSICAL_IFS[@]}"
  cap_wait
}

# counts W POINT prints POINT's request and reply counts per path as JSON.
counts() {
  python3 -I "${SCRIPT_DIR}/envoy-pcap.py" --gateway "${GW}" --nonces "${OUT}/logs/$1/nonces.tsv" \
    "${OUT}/pcap/$1/$2".*.pcap
}

# where W checks where each path's requests and replies crossed.
where() {
  local w="$1" pt p v o site j
  declare -A C
  for pt in pod80 pod81 encap80 encap81 host80 host81 guest80 guest81 podeth0 physical; do
    C[${pt}]=$(counts "${w}" "${pt}")
    printf '%s\t%s\n' "${pt}" "${C[${pt}]}" >>"${OUT}/logs/${w}/counts.tsv"
  done
  g() { jq -r --arg p "$2" --arg k "$3" '.[$p][$k] // 0' <<<"${C[$1]}"; }
  for p in "${PATHS[@]}"; do
    v=${p%%/*} o=${OTHER[${p%%/*}]} site=${p#*/}
    if [ "${site}" = local ]; then
      record "${w}" "${p}: requests cross VPC ${v}'s routed link" yes "$(seen "$(g "pod${v}" "${p}" req)")"
      record "${w}" "${p}: replies cross VPC ${v}'s routed link" yes "$(seen "$(g "pod${v}" "${p}" rep)")"
      record "${w}" "${p}: requests leave the host end" yes "$(seen "$(g "host${v}" "${p}" req)")"
      record "${w}" "${p}: replies enter the host end" yes "$(seen "$(g "host${v}" "${p}" rep)")"
      record "${w}" "${p}: the guest receives the requests" yes "$(seen "$(g "guest${v}" "${p}" req)")"
      record "${w}" "${p}: the guest sends the replies" yes "$(seen "$(g "guest${v}" "${p}" rep)")"
      record "${w}" "${p}: nothing through the encapsulation pair" 0 \
        "$(($(g "encap${v}" "${p}" req) + $(g "encap${v}" "${p}" rep)))"
      record "${w}" "${p}: nothing on the physical members" 0 \
        "$(($(g physical "${p}" req) + $(g physical "${p}" rep)))"
    else
      record "${w}" "${p}: requests leave through the encapsulation pair" yes "$(seen "$(g "encap${v}" "${p}" req)")"
      record "${w}" "${p}: no request on the routed link" 0 "$(($(g "pod${v}" "${p}" req) + $(g "host${v}" "${p}" req)))"
      record "${w}" "${p}: replies return over the routed link" yes "$(seen "$(g "pod${v}" "${p}" rep)")"
      record "${w}" "${p}: replies enter the host end" yes "$(seen "$(g "host${v}" "${p}" rep)")"
      record "${w}" "${p}: requests leave the node in SRv6" yes "$(seen "$(g physical "${p}" req_srv6)")"
      record "${w}" "${p}: replies reach the node in SRv6" yes "$(seen "$(g physical "${p}" rep_srv6)")"
      record "${w}" "${p}: nothing at the local guest" 0 "$(($(g "guest${v}" "${p}" req) + $(g "guest${v}" "${p}" rep)))"
    fi
    record "${w}" "${p}: nothing on VPC ${o}'s link, pair or guest" 0 "$(($(g "pod${o}" "${p}" req) + $(g "pod${o}" "${p}" rep) +
      $(g "host${o}" "${p}" req) + $(g "host${o}" "${p}" rep) + $(g "encap${o}" "${p}" req) +
      $(g "encap${o}" "${p}" rep) + $(g "guest${o}" "${p}" req) + $(g "guest${o}" "${p}" rep)))"
    volatile "${w}-${p}-podeth0" "$(jq -c --arg p "${p}" '.[$p]' <<<"${C[podeth0]}")"
  done
}

# State --------------------------------------------------------------------------

# local_routes V prints the destinations of the sidecar's routes (protocol
# 0x47) in VPC V's VRF in the pod.
local_routes() {
  { in_pod "${PPID_POD}" ip -6 -j route show vrf "${VRF[$1]}" proto 71 2>/dev/null || echo '[]'; } |
    jq -r '[.[].dst] | sort | join(",")' 2>/dev/null || true
}

# wait_local_routes V WANT waits up to 90s for local_routes V to be WANT.
wait_local_routes() {
  local i got=""
  for i in $(seq 1 45); do
    got=$(local_routes "$1")
    [ "${got}" = "$2" ] && break
    sleep 2
  done
  echo "${got:-none}"
}

host_gateway_dev() {
  { docker exec "${NODE}" ip -6 -j route show vrf "${VRF[$1]}" "${GW}/128" 2>/dev/null || echo '[]'; } |
    jq -r '.[0].dev // "none"' 2>/dev/null || echo none
}

# advertisement V FIELD prints FIELD of NODE's Worker advertisements for V.
advertisements() {
  kd -n galactic-system get "${ADV}" -l "galactic.datumapis.com/worker-node=${NODE},galactic.datumapis.com/worker-vpc=$1" \
    -o json
}

state() {
  local w=state v j ll route a f
  window "${w}"
  for v in 80 81; do
    in_pod "${PPID_POD}" ip -6 route show vrf "${VRF[${v}]}" >"${OUT}/logs/${w}/pod-vrf-${v}.txt" 2>&1 || true
    docker exec "${NODE}" ip -6 route show vrf "${VRF[${v}]}" >"${OUT}/logs/${w}/host-vrf-${v}.txt" 2>&1 || true
    j=$(in_pod "${PPID_POD}" ip -6 -j route show vrf "${VRF[${v}]}" proto 71 2>/dev/null || echo '[]')
    ll=$({ docker exec "${NODE}" ip -6 -j addr show dev "${HOST_END[${v}]}" scope link 2>/dev/null || echo '[]'; } |
      jq -r '.[0].addr_info[0].local // empty')
    record "${w}" "VPC ${v}: the pod VRF's routed-link routes are the local backend only" "${LOCAL_ADDR}" \
      "$(jq -r '[.[].dst] | sort | join(",")' <<<"${j}")"
    route=$(jq -r --arg ll "${ll}" --arg dev "${POD_END[${v}]}" \
      '[.[] | select(.gateway == $ll and .dev == $dev)] | length' <<<"${j}")
    record "${w}" "VPC ${v}: the local route goes through the pod end to the host end's link-local" 1 "${route}"
    record "${w}" "VPC ${v}: the host VRF routes the gateway to the host end" yes \
      "$([ "$(host_gateway_dev "${v}")" = "${HOST_END[${v}]}" ] && echo yes || echo no)"
    a=$(advertisements "${v}" 2>/dev/null || echo '{"items":[]}')
    printf '%s\n' "${a}" >"${OUT}/logs/${w}/advertisements-${v}.json"
    record "${w}" "VPC ${v}: Worker advertisements" 1 "$(jq '.items | length' <<<"${a}")"
    record "${w}" "VPC ${v}: the advertisement's prefixes" "${GW}/128" "$(jq -r '[.items[].spec.prefixes[]] | join(",")' <<<"${a}")"
    record "${w}" "VPC ${v}: the advertisement names the Envoy pod" yes \
      "$(jq -r --arg uid "${POD_UID}" 'if [.items[] | select(.metadata.annotations["galactic.datumapis.com/worker-pod"] == $uid)]
        | length == 1 then "yes" else "no" end' <<<"${a}")"
    remote_route "${v}"
  done
  f="${OUT}/logs/${w}/metrics.txt"
  metrics >"${f}" 2>&1 || true
  record "${w}" "sidecar: connected to Worker" 1 "$(metric "${f}" worker_connected)"
  # RoutedLinkUnavailable here means Worker lacks the routed-link
  # capabilities (above).
  for cap in local.socket fabric.srv6; do
    record "${w}" "sidecar: Worker reports ${cap} available" 1 \
      "$(metric "${f}" worker_capability "capability=\"${cap}\",reason=\"\",state=\"available\"")"
  done
  record "${w}" "sidecar: ready claims" 2 "$(metric "${f}" worker_claims 'state="ready"')"
  record "${w}" "sidecar: local destinations" 2 "$(metric "${f}" worker_destinations 'mode="local"')"
  if [ "${REMOTE}" = dfw-worker4 ]; then
    record "${w}" "sidecar: fabric destinations" 2 "$(metric "${f}" worker_destinations 'mode="fabric"')"
  else
    record "${w}" "sidecar: fabric or unresolved destinations (sjc mirror)" 2 \
      "$(($(metric "${f}" worker_destinations 'mode="fabric"') + $(metric "${f}" worker_destinations 'mode="unresolved"')))"
    volatile "sjc-destinations" "fabric=$(metric "${f}" worker_destinations 'mode="fabric"') unresolved=$(metric "${f}" worker_destinations 'mode="unresolved"')"
  fi
}

# remote_route V checks the remote node routes the gateway back in VPC V:
# a kernel route, or an egress_route_table entry when bpftool can be run
# without a password.
remote_route() {
  local v="$1" node=${BNODE[$1/remote]} k e=""
  k=$(docker exec "${node}" ip -6 route show vrf "${VRF[${v}]}" 2>&1 || true)
  printf '%s\n' "${k}" >"${OUT}/logs/state/remote-${node}-vrf-${v}.txt"
  if sudo -n true 2>/dev/null; then
    e=$("${SCRIPT_DIR}/worker-fabric.sh" dump "${node}" "${v}" 2>&1 || true)
    printf '%s\n' "${e}" >"${OUT}/logs/state/remote-${node}-egress-${v}.txt"
  fi
  record state "VPC ${v}: ${node} has a route back to the gateway" yes \
    "$(grep -qF "${GW}" <<<"${k}${e}" && echo yes || echo no)"
}

# Sockets ----------------------------------------------------------------------

# sockets checks the pooled upstream sockets the reused window left open:
# each source port a backend saw is a socket in the pod from the gateway,
# bound to its VPC's VRF, to that backend.
sockets() {
  local w=sockets p v port ss_out line lo pe re='^\[([^]]+)\](%([^:]+))?:([0-9]+)$' ok
  window "${w}"
  in_pod "${PPID_POD}" ss -tnie >"${OUT}/logs/${w}/ss-tnie.txt" 2>&1 || true
  ss_out=$(in_pod "${PPID_POD}" ss -Htn state established '( dport = :8080 )' || true)
  printf '%s\n' "${ss_out}" >"${OUT}/logs/${w}/ss.txt"
  for p in "${PATHS[@]}"; do
    v=${p%%/*}
    port=$(jq -R -s -r '[split("\n")[] | fromjson? | objects | .peer.port] | unique | first // empty' \
      "${OUT}/logs/reused/${p//\//-}-reused.txt")
    line=$(awk -v port=":${port}" 'index($3, port) && substr($3, length($3) - length(port) + 1) == port' <<<"${ss_out}")
    lo=$(awk '{print $3}' <<<"${line}")
    pe=$(awk '{print $4}' <<<"${line}")
    volatile "socket-${p}" "${lo} -> ${pe}"
    ok=no
    [ -n "${line}" ] && ok=yes
    record "${w}" "${p}: the socket the backend saw is open in the pod" yes "${ok}"
    if [[ "${lo}" =~ ${re} ]]; then
      record "${w}" "${p}: its local address" "${GW}" "${BASH_REMATCH[1]}"
      record "${w}" "${p}: its bound device" "${VRF[${v}]}" "${BASH_REMATCH[3]:-none}"
    else
      record "${w}" "${p}: its local address" "${GW}" none
      record "${w}" "${p}: its bound device" "${VRF[${v}]}" none
    fi
    record "${w}" "${p}: its peer" "[${BADDR[${p}]}]:8080" "${pe:-none}"
  done
}

if [ "${MODE}" = up ]; then
  trap - EXIT
  rig_stop
  echo "ns80-envoy is up (REMOTE=${REMOTE}, pod ${POD}); remove it with task delete:ns80-envoy"
  exit 0
fi

# Run ----------------------------------------------------------------------------

# The pod can turn Ready before its first claims are made, while the proxy
# attachments' status is still being written; wait for the sidecar to
# report both claims held and configured.
claims_ready=0
for i in $(seq 1 90); do
  metrics >"${OUT}/logs/setup-metrics.txt" 2>&1 || true
  claims_ready=$(metric "${OUT}/logs/setup-metrics.txt" worker_claims 'state="ready"')
  [ "${claims_ready}" = 2 ] && break
  sleep 2
done
record setup "the sidecar reports both Worker claims ready" 2 "${claims_ready}"
kd -n "${NS}" get vpcattachments -o yaml >"${OUT}/logs/proxy-attachments.yaml" 2>&1 || true
kd -n "${NS}" logs "${POD}" -c galactic-vrf --tail=200 >"${OUT}/logs/galactic-vrf-setup.log" 2>&1 || true

links
for v in 80 81; do
  record setup "VPC ${v}: routed link ends found" yes \
    "$([ -n "${POD_END[${v}]}" ] && [ -n "${HOST_END[${v}]}" ] && [ -n "${IVS[${v}]}" ] && echo yes || echo no)"
done

# probe: one request per VPC and backend over a fresh upstream connection,
# then the usual cleanup and restore checks from the exit trap. A short run
# to show the setup works before the full one.
if [ "${MODE}" = probe ]; then
  window probe
  N=1
  for p in "${PATHS[@]}"; do
    fresh probe "${p}"
  done
  exit 0
fi

# Warm every path's neighbors outside the capture windows.
for p in "${PATHS[@]}"; do
  client curl -sk -g --http1.1 --max-time 10 -o /dev/null "https://[::1]:8443/${p}/fresh" || true
done

window fresh
capture fresh
for p in "${PATHS[@]}"; do fresh fresh "${p}"; done
cap_stop
where fresh

window reused
capture reused
for p in "${PATHS[@]}"; do reused reused "${p}" 1; done
cap_stop
where reused

sockets
state

# move: VPC 80's local guest goes. It is the last tenant interface of VPC 80
# on dfw-worker (ns80 has no TAP guest; a veth is the same state for the
# claim), so only the claim keeps the host VRF.
window move
GUEST_A_REPLICAS=$(kd -n ns80 get deployment guest-a -o jsonpath='{.spec.replicas}' </dev/null)
MOVED=1
kd -n ns80 scale deployment/guest-a --replicas=0 >/dev/null
kd -n ns80 wait --for=delete pod -l app=vpc-a --timeout=120s >/dev/null 2>&1 || true
record move "VPC 80: the pod VRF drops the local route" none "$(wait_local_routes 80 "")"
record move "VPC 80: the host VRF stays" yes "$(docker exec "${NODE}" ip link show "${VRF[80]}" >/dev/null 2>&1 && echo yes || echo no)"
record move "VPC 80: the host VRF still routes the gateway to the host end" yes \
  "$([ "$(host_gateway_dev 80)" = "${HOST_END[80]}" ] && echo yes || echo no)"
for p in 80/remote 81/local 81/remote; do
  fresh move "${p}"
  reused move "${p}"
done
n=$(nonce)
mapfile -t a < <(curl_args "${n}" 80/local/fresh)
out=$(client curl "${a[@]}" 2>&1 || true)
record move "80/local: no backend answers" yes "$(jq -R -s '[split("\n")[] | fromjson? | objects] | length == 0' <<<"${out}" |
  sed 's/true/yes/;s/false/no/')"
kd -n ns80 scale deployment/guest-a --replicas="${GUEST_A_REPLICAS}" >/dev/null
kd -n ns80 rollout status deployment/guest-a --timeout=120s >/dev/null
MOVED=0
"${SCRIPT_DIR}/publish-attachments.sh" ns80 dfw >"${OUT}/logs/publish-attachments.log" 2>&1
record move "80/local: the backend restarts in the new guest" yes "$(start_backend 80/local && echo yes || echo no)"
record move "VPC 80: the pod VRF's local route comes back" "${LOCAL_ADDR}" "$(wait_local_routes 80 "${LOCAL_ADDR}")"
fresh move 80/local
reused move 80/local

# replace: a rollout replaces the Envoy pod. The Component's strategy stops
# the old pod first; the new pod's sidecar is refused with
# ClaimHeldByAnotherPod until the old one has released the claims or is gone.
window replace
OLD=${POD}
declare -A OLD_HOST_IDX
for v in 80 81; do
  OLD_HOST_IDX[${v}]=$(docker exec "${NODE}" ip -j link show dev "${HOST_END[${v}]}" | jq -r '.[0].ifindex')
done
kd -n "${NS}" rollout restart deployment/envoy >/dev/null
first="" new="" ready=no
for i in $(seq 1 "${REPLACE_TIMEOUT}"); do
  new=$(kd -n "${NS}" get pods -l app=envoy -o json </dev/null | jq -r --arg old "${OLD}" '[.items[]
    | select(.metadata.name != $old and .metadata.deletionTimestamp == null)] | first | .metadata.name // empty')
  if [ -n "${new}" ]; then
    m=$(kd -n "${NS}" exec "${new}" -c client -- curl -s -g 'http://[::1]:9182/metrics' </dev/null 2>/dev/null || true)
    printf '%s\n' "${m}" >"${OUT}/logs/replace/metrics-${i}.txt"
    if [ -z "${first}" ]; then
      if grep -q 'worker_claims{.*ClaimHeldByAnotherPod.*state="refused"} [1-9]' <<<"${m}"; then
        first="refused ClaimHeldByAnotherPod"
      elif grep -q 'worker_claims{.*state="ready"} 2' <<<"${m}"; then
        first=ready
      fi
    fi
    if [ "$(ready_pod "${DFW}" "${NS}" app=envoy)" = "${new}" ]; then
      ready=yes
      break
    fi
  fi
  sleep 1
done
# Either is correct: refused while the old pod still held the claims, or
# ready at once when it had already released them.
record replace "the new pod's first claim state" - "${first:-none seen}"
record replace "the new pod becomes Ready" yes "${ready}"
[ "${ready}" = yes ] || exit 1
kd -n "${NS}" rollout status deployment/envoy --timeout=120s >>"${OUT}/logs/rollout.log" 2>&1 || true
kd -n "${NS}" wait --for=delete "pod/${OLD}" --timeout=120s >/dev/null 2>&1 || true
record replace "the old pod is gone" yes "$(kd -n "${NS}" get pod "${OLD}" >/dev/null 2>&1 && echo no || echo yes)"
POD=$(ready_pod "${DFW}" "${NS}" app=envoy)
POD_UID=$(kd -n "${NS}" get pod "${POD}" -o jsonpath='{.metadata.uid}')
volatile envoy-pod-replaced "${POD} ${POD_UID}"
# Worker moves the link to the new pod; give it a moment to report.
sleep 5
links
for v in 80 81; do
  pidx=$(in_pod "${PPID_POD}" ip -j link show dev "${POD_END[${v}]}" 2>/dev/null | jq -r '.[0].link_index // empty')
  hidx=$(docker exec "${NODE}" ip -j link show dev "${HOST_END[${v}]}" 2>/dev/null | jq -r '.[0].ifindex // empty')
  volatile "replace-${v}-host-ifindex" "before=${OLD_HOST_IDX[${v}]} after=${hidx}"
  record replace "VPC ${v}: the routed link's pod end is in the new pod, peered with the host end" yes \
    "$([ -n "${pidx}" ] && [ "${pidx}" = "${hidx}" ] && echo yes || echo no)"
  record replace "VPC ${v}: host ends on ${NODE}" 1 "$(docker exec "${NODE}" ip -j link show |
    jq --arg a "galactic-local:${v}/" '[.[] | select((.ifalias // "") | startswith($a))] | length')"
  record replace "VPC ${v}: the advertisement names the new pod" yes \
    "$(advertisements "${v}" | jq -r --arg uid "${POD_UID}" 'if [.items[]
      | select(.metadata.annotations["galactic.datumapis.com/worker-pod"] == $uid)] | length == 1 then "yes" else "no" end')"
done
for p in "${PATHS[@]}"; do
  fresh replace "${p}"
  reused replace "${p}" 1
done
record replace "verify-ns80 passes" yes \
  "$("${SCRIPT_DIR}/verify-ns80.sh" >"${OUT}/logs/verify-ns80-after.log" 2>&1 && echo yes || echo no)"

# cleanup runs from the EXIT trap and finishes the run.
