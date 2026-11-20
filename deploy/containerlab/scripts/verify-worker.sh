#!/bin/bash
# verify-worker.sh: install galactic-worker on dfw from this checkout's
# manifests in one placement profile, check its diagnostics against injected
# failures, and remove it with the handback, checking that host state Worker
# does not own is unchanged throughout (docs/worker/operations.md).
#
# Usage: verify-worker.sh dedicated|combined [OUTDIR]
#   OUTDIR defaults to bin/worker-lab/<UTC timestamp>-<profile> at the
#   repository root.
#
# Needs ns80 with dfw's second compute worker, dfw-worker4, the
# galactic-worker and worker-claim images on dfw's nodes (task
# worker:images), and bpftool through passwordless sudo on the host. The combined profile also deploys ns80-tap pinned to
# dfw-worker2, an edge node, and removes it at the end.
#
# Claims, all in VPC 80 and held by the lab claim client:
#   dedicated  on dfw-worker:  ns80/vpc-a -> ns80/vpc-a2 (dfw-worker4, Fabric)
#   combined   on dfw-worker2: ns80-tap/vpc-a-tap -> itself (Local) and
#              ns80/vpc-a2 (Fabric); and a routed_link claim on
#              ns80-tap/vpc-b-tap, whose pod end goes into the client's pod.
#
# Failures injected one at a time, each restored before the next:
#   route       an unreachable route shadows the underlay route toward
#               dfw-worker4's locator on the claim node
#   attachment  the Fabric destination's guest (guest-a2) is scaled to zero,
#               or, for combined, the Local destination's TAP guest
#   hook        (combined) Local's galactic_local_rx filter is removed from
#               the receiving device
#
# Stages compared with the state before install, excluding the claimed
# VPCs' VRF tables and egress_route_table rows, the links, routes and
# filters Worker's Local module owns, and volatile fields: claims reconciled, a second resync, a Worker restart, a drain of
# dfw-worker3, and the uninstall with handback.
#
# When a precondition does not hold it changes nothing, says which, and
# exits 0. Every check that fails is listed in OUTDIR/failures, and the
# script exits 1.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"
LAB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPO=$(cd "${LAB_DIR}/../.." && pwd)

PROFILE=${1:?usage: verify-worker.sh dedicated|combined [OUTDIR]}
case "${PROFILE}" in dedicated | combined) ;; *)
  echo "profile must be dedicated or combined" >&2
  exit 2
  ;;
esac
OUT=${2:-${REPO}/bin/worker-lab/$(date -u +%Y%m%dT%H%M%SZ)-${PROFILE}}
mkdir -p "${OUT}"
OUT=$(cd "${OUT}" && pwd)
SITE=dfw
CP=$(control_plane "${SITE}")
NS=galactic-system
LAB="${SCRIPT_DIR}/worker-lab.sh"
DRAIN_NODE=dfw-worker3
REMOTE_NODE=dfw-worker4
VPC=80
: >"${OUT}/failures"

kc() { docker exec -i "${CP}" kubectl "$@"; }
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "${OUT}/steps.log"; }
fail() {
  echo "$*" | tee -a "${OUT}/failures" >&2
}
precondition() {
  echo "PRECONDITION: $*" | tee "${OUT}/precondition"
  exit 0
}

# ---- preconditions -------------------------------------------------------

if ! kc get nodes >/dev/null 2>&1; then
  precondition "the dfw cluster does not answer"
fi
if ! kc get node "${REMOTE_NODE}" >/dev/null 2>&1; then
  precondition "${REMOTE_NODE} is not in the dfw cluster (#1459's topology)"
fi
if ! kc -n ns80 get vpcattachment vpc-a vpc-a2 >/dev/null 2>&1; then
  precondition "ns80 with vpc-a and vpc-a2 is not deployed (task deploy:ns80)"
fi
if kc -n "${NS}" get ds galactic-worker >/dev/null 2>&1; then
  precondition "a galactic-worker DaemonSet already runs on dfw; an earlier run did not remove it"
fi
if kc get namespace ns80-tap >/dev/null 2>&1; then
  precondition "ns80-tap is deployed; an earlier run did not remove it (task delete:ns80-tap)"
fi
NODES=()
if node_list=$("${LAB}" nodes "${SITE}"); then
  mapfile -t NODES <<<"${node_list}"
fi
if [ "${#NODES[@]}" -eq 0 ] || [ -z "${NODES[0]}" ]; then
  precondition "no dfw node matches Worker's affinity"
fi
if ! sudo -n bpftool version >/dev/null 2>&1; then
  precondition "bpftool through passwordless sudo is needed to read egress_route_table"
fi
for node in "${NODES[@]}"; do
  if docker exec "${node}" pgrep -f '^/opt/galactic-worker/galactic-worker' >/dev/null; then
    precondition "worker-fabric.sh's Worker runs on ${node} (worker-fabric.sh stop)"
  fi
  owners=$(docker exec "${node}" sh -c 'cat /var/lib/galactic-edge/ownership/*.json 2>/dev/null || true' |
    jq -r '.owner' 2>/dev/null || true)
  if grep -q '^galactic-worker:' <<<"${owners}"; then
    precondition "${node} has VPC scopes a galactic-worker owns; hand them back first (worker-lab.sh uninstall dfw)"
  fi
done
for node in "${NODES[@]}"; do
  images=$(docker exec "${node}" ctr --namespace k8s.io images ls -q)
  for image in galactic-worker:latest worker-claim:latest; do
    if ! grep -qx "docker.io/library/${image}" <<<"${images}"; then
      precondition "${image} is not loaded on ${node} (task worker:images)"
    fi
  done
done

# ---- helpers --------------------------------------------------------------

# table_of NODE VPC prints VPC's VRF table ID on NODE, or nothing.
table_of() {
  docker exec "$1" ip -j -d link show dev "G$(printf '%09s' "$2" | tr ' ' 0)V" 2>/dev/null |
    jq -r '.[0].linkinfo.info_data.table // empty' || true
}

# snapshot NODE prints NODE's host state that Worker does not own and that
# is outside the claimed VPCs' VRF tables, one sorted line per item.
snapshot() {
  local -
  local node="$1" tables="" pid t vpc
  set +e +o pipefail
  for vpc in ${RELATED_VPCS}; do
    t=$(table_of "${node}" "${vpc}")
    [ -n "${t}" ] && tables="${tables}${tables:+|}${t}"
  done
  {
    for fam in -4 -6; do
      # Left out as not Worker's and not stable: routes of Local links and
      # of Cilium's pod interfaces (lxc*, such as the claim client's), the
      # kernel's link-local routes, which a pod replaced by the drain
      # changes, and which of the two bonds an underlay route uses.
      docker exec "${node}" ip "${fam}" route show table all |
        grep -v -E " table local|proto ra| cache|dev G[A-Za-z0-9]{12}[NTRP]( |$)|dev lxc|fe80::" |
        grep -v -E " table (${tables:-none})( |$)" |
        sed -E 's/ expires [0-9]+sec//; s/ via (inet6 )?[^ ]+ dev bond[0-9]+/ via underlay/; s/ +$//' |
        sed "s/^/route${fam} /"
    done
    docker exec "${node}" ip -j -d link show |
      jq -r '.[] | select(.ifname | test("^G[A-Za-z0-9]{12}[NTRP]$|^lxc") | not)
        | "link \(.ifname) master=\(.master // "-") xdp=\(.xdp.prog.id // "-")"'
    for dev in $(docker exec "${node}" ip -j link show | jq -r '.[].ifname | select(test("^(eth|bond)[0-9]+$"))'); do
      for dir in ingress egress; do
        # JSON, so a filter's program name is on the same entry as its
        # priority and Local's own filters (galactic_local_*) can be left out.
        docker exec "${node}" tc -j filter show dev "${dev}" "${dir}" 2>/dev/null |
          jq -r --arg d "${dev} ${dir}" '.[] | select(.options != null)
            | select((.options.bpf_name // "") | startswith("galactic_local") | not)
            | "tc \($d) pref \(.pref) \(.kind) \(.options.bpf_name // .options.handle // "-")"' 
      done
    done
    # A row of a table no VRF holds is garbage galactic-router's GC sweeps
    # within one interval; it is kept apart as stale_egress_row, which the
    # comparison leaves out and the leak check counts.
    vrfs=$(docker exec "${node}" ip -j -d link show type vrf | jq -r '[.[].linkinfo.info_data.table] | join("|")')
    pid=$(docker inspect -f '{{.State.Pid}}' "${node}")
    sudo -n bpftool -j map dump pinned "/proc/${pid}/root/sys/fs/bpf/galactic/egress_route_table" |
      python3 -I "${SCRIPT_DIR}/worker-rows.py" "${tables}" "${vrfs:-none}"
  } | sort
}

# no_stale_rows waits up to one GC interval and a minute for every node to
# have no egress_route_table row of a table no VRF holds, and fails naming
# the nodes that still do: rows a run's VPCs left behind would be a leak.
no_stale_rows() {
  local left="" node
  for _ in $(seq 36); do
    left=""
    for node in "${NODES[@]}"; do
      if snapshot "${node}" | grep -q '^stale_egress_row '; then
        left="${left} ${node}"
      fi
    done
    [ -z "${left}" ] && return 0
    sleep 10
  done
  fail "$1: egress_route_table rows of a table no VRF holds remain on${left} after 6 minutes"
}

# snap_all LABEL writes every Worker node's snapshot under OUT/LABEL.
snap_all() {
  local label="$1" node
  mkdir -p "${OUT}/${label}"
  for node in "${NODES[@]}"; do
    snapshot "${node}" >"${OUT}/${label}/${node}.txt"
  done
}

# compare LABEL checks LABEL's snapshots against the baseline.
compare() {
  local label="$1" node
  for node in "${NODES[@]}"; do
    if ! diff -u <(grep -v '^stale_egress_row ' "${OUT}/baseline/${node}.txt") \
      <(grep -v '^stale_egress_row ' "${OUT}/${label}/${node}.txt") >"${OUT}/${label}/${node}.diff"; then
      fail "${label}: ${node}'s unrelated host state changed (${label}/${node}.diff)"
    else
      rm -f "${OUT}/${label}/${node}.diff"
    fi
  done
}

uid_of() { kc -n "$1" get vpcattachment "$2" -o jsonpath='{.metadata.uid}'; }

# claim NODE ATT HANDOFF DESTS [GEN] requests a claim through NODE's client
# and saves its status.
claim() {
  local node="$1" att="$2" handoff="$3" dests="$4" gen="${5:-1}"
  kc -n "${NS}" exec "worker-lab-client-${node}" -- /worker-claim -node "${node}" -vpc "${VPC}" \
    -attachment "${att}" -handoff "${handoff}" -dest "${dests}" -generation "${gen}" -wait 120s |
    tee -a "${OUT}/claims.jsonl"
}

release() {
  local node="$1" att="$2" handoff="$3" dests="$4"
  kc -n "${NS}" exec "worker-lab-client-${node}" -- /worker-claim -node "${node}" -vpc "${VPC}" \
    -attachment "${att}" -handoff "${handoff}" -dest "${dests}" -release -wait 120s | tee -a "${OUT}/claims.jsonl"
}

# dest NODE ATT DEST prints one destination of the claim on ATT from
# inspect: locality programmed forwardReady returnReady reason.
dest() {
  "${LAB}" inspect "${SITE}" "$1" -o json 2>/dev/null |
    jq -r --arg k "$1/${VPC}/$2" --arg d "attachment/$3" '.scopes[]?.claims[]? | select(.key == $k)
      | .destinations[] | select(.id == $d)
      | "\(.locality // "-") \(.programmed) \(.forwardReady) \(.returnReady) \(.reason // "AsExpected")"'
}

# wait_dest NODE ATT DEST REGEX WHAT waits up to 150s for dest to match.
wait_dest() {
  local got=""
  for _ in $(seq 75); do
    got=$(dest "$1" "$2" "$3")
    if [[ "${got}" =~ $4 ]]; then
      log "ok: $5 ($3: ${got})"
      return 0
    fi
    sleep 2
  done
  fail "$5: destination $3 reports '${got}', want /$4/"
}

metric() {
  docker exec "$1" curl -s "http://127.0.0.1:9104/metrics" | grep -E "^$2" || true
}

save_diagnostics() {
  local label="$1" node
  mkdir -p "${OUT}/${label}"
  for node in "${CLAIM_NODE}" "${REMOTE_NODE}"; do
    "${LAB}" inspect "${SITE}" "${node}" >"${OUT}/${label}/inspect-${node}.txt" 2>&1 || true
    metric "${node}" galactic_worker_ >"${OUT}/${label}/metrics-${node}.txt"
  done
}

# ---- run ------------------------------------------------------------------

if [ "${PROFILE}" = dedicated ]; then
  CLAIM_NODE=dfw-worker
  CLAIM_NS=ns80
  CLAIM_ATT=vpc-a
  # The routed link refusal claims in VPC 81, ns80's other VPC.
  RELATED_VPCS="80 81"
else
  CLAIM_NODE=dfw-worker2
  CLAIM_NS=ns80-tap
  # The claim's own handoff attachment, a gateway's in production, is not
  # its Local destination: removing the destination's guest must leave the
  # claim standing.
  CLAIM_ATT=vpc-a-svc
  # The routed link probe claims in VPC 81.
  RELATED_VPCS="80 81"
fi

cleanup() {
  status=$?
  set +e
  log "cleanup"
  kc -n "${NS}" logs -l app.kubernetes.io/name=galactic-worker --all-containers --prefix --tail=-1 \
    >"${OUT}/worker-logs.txt" 2>&1
  "${LAB}" client-down "${SITE}" >>"${OUT}/steps.log" 2>&1
  kc uncordon "${DRAIN_NODE}" >/dev/null 2>&1
  kc -n ns80 scale deployment guest-a2 --replicas=1 >/dev/null 2>&1
  for node in "${NODES[@]}"; do
    docker exec "${node}" ip -6 route del unreachable "${REMOTE_LOCATOR:-::1/128}" 2>/dev/null
  done
  if kc -n "${NS}" get ds galactic-worker >/dev/null 2>&1; then
    "${LAB}" uninstall "${SITE}" >>"${OUT}/steps.log" 2>&1 || fail "cleanup: uninstall failed"
  fi
  if [ "${PROFILE}" = combined ]; then
    "${SCRIPT_DIR}/handoff-fixture.sh" down >>"${OUT}/steps.log" 2>&1 || fail "cleanup: ns80-tap removal failed"
  fi
  if [ "${status}" -eq 0 ] && [ "${#NODES[@]}" -gt 0 ]; then
    log "leak check: rows of tables no VRF holds"
    no_stale_rows "cleanup"
  fi
  if [ -s "${OUT}/failures" ]; then
    echo "FAILED: $(wc -l <"${OUT}/failures") checks; see ${OUT}/failures"
    exit 1
  fi
  [ "${status}" -eq 0 ] && echo "PASSED: ${PROFILE}; evidence in ${OUT}"
  exit "${status}"
}
trap cleanup EXIT

if [ "${PROFILE}" = combined ]; then
  log "deploy ns80-tap on dfw-worker2"
  "${SCRIPT_DIR}/deploy-tenant-policy.sh" ns80-tap dfw >>"${OUT}/steps.log"
  copy_to "${CP}" tenants/base
  copy_to "${CP}" tenants/ns80-tap
  copy_to "${CP}" galactic-worker
  apply_k "${CP}" /galactic/resources/galactic-worker/ns80-tap-combined/ >>"${OUT}/steps.log"
  "${SCRIPT_DIR}/publish-attachments.sh" ns80-tap dfw >>"${OUT}/steps.log"
  # vpc-a-svc has no pod or NAD, so publish-attachments leaves it; its status
  # places it on the combined node, as an attachment controller would.
  kc -n ns80-tap patch vpcattachment vpc-a-svc --subresource=status --type=merge \
    -p '{"status":{"vpc":"80","node":"dfw-worker2"}}' >>"${OUT}/steps.log"
  kc -n ns80-tap wait --for=condition=Ready pod -l 'app in (vpc-a-tap,vpc-b-tap)' --timeout=240s >>"${OUT}/steps.log"
fi

# The remote node's locator: its /48 uSID block and 16-bit node ID, from the
# BGPRouter that carries them, as internal/nodelocator reads it. Other
# BGPRouters may target the node without a locator.
routers=$(kc -n "${NS}" get bgprouters -o json)
read -r block nodeid < <(jq -r --arg n "${REMOTE_NODE}" '[.items[]
  | select(.spec.targetRef.name == $n and (.spec.srv6Locator // "") != "" and (.spec.nodeID // 0) > 0)]
  | if length == 1 then "\(.[0].spec.srv6Locator) \(.[0].spec.nodeID)" else "" end' <<<"${routers}")
if [ -z "${nodeid:-}" ]; then
  jq -r '.items[] | "\(.metadata.name) target=\(.spec.targetRef.name) locator=\(.spec.srv6Locator) nodeID=\(.spec.nodeID)"' \
    <<<"${routers}" >"${OUT}/bgprouters.txt"
  fail "no single BGPRouter carries ${REMOTE_NODE}'s locator (bgprouters.txt)"
  exit 1
fi
REMOTE_LOCATOR="${block%::/48}:$(printf '%x' "${nodeid}")::/64"
log "remote node ${REMOTE_NODE}, locator ${REMOTE_LOCATOR}"

# all_rows NODE counts every egress_route_table row on NODE, in every table.
all_rows() {
  local pid
  pid=$(docker inspect -f '{{.State.Pid}}' "$1")
  sudo -n bpftool -j map dump pinned "/proc/${pid}/root/sys/fs/bpf/galactic/egress_route_table" 2>/dev/null |
    jq 'length' 2>/dev/null || echo 0
}

# The previous run's uninstall restarts galactic-router on every node, so
# wait until every node has rows before taking the baseline, counted in every
# table: a node may hold only the claimed VPCs' guests, which the snapshot
# leaves out.
log "waiting for every node's egress_route_table rows"
for _ in $(seq 30); do
  empty=""
  for node in "${NODES[@]}"; do
    [ "$(all_rows "${node}")" -gt 0 ] || empty="${empty} ${node}"
  done
  [ -z "${empty}" ] && break
  sleep 10
done
[ -z "${empty}" ] || fail "baseline: no egress_route_table rows on${empty} after 5 minutes"
log "baseline snapshot"
snap_all baseline
for node in "${NODES[@]}"; do
  if ! grep -q '^route-6 ' "${OUT}/baseline/${node}.txt"; then
    fail "baseline: ${node}'s snapshot has no routes; the comparison would prove nothing"
    exit 1
  fi
done
if ! cat "${OUT}"/baseline/*.txt | grep -q '^egress_route_table '; then
  fail "baseline: no node has egress_route_table rows outside the claimed VPCs; the comparison would prove nothing"
  exit 1
fi

log "install ${PROFILE}"
"${LAB}" install "${SITE}" "${PROFILE}" 2>&1 | tee -a "${OUT}/steps.log"
kc -n "${NS}" get pods -l app.kubernetes.io/name=galactic-worker -o wide >"${OUT}/worker-pods.txt"

# Least privilege, from the running pods: the capabilities in effect and
# what the ServiceAccount may and may not do.
for node in "${NODES[@]}"; do
  # Anchored and with -o, so neither a shell holding the pattern nor a
  # pipe closing early decides the result.
  pid=$(docker exec "${node}" pgrep -o -f '^/galactic-worker' || true)
  if [ -z "${pid}" ]; then
    fail "privileges: no galactic-worker process on ${node}"
    continue
  fi
  docker exec "${node}" grep -E '^Cap(Prm|Eff|Bnd)' "/proc/${pid}/status" | sed "s/^/${node} /" >>"${OUT}/capabilities.txt"
done
caps=$(awk '/CapEff/ {print $3}' "${OUT}/capabilities.txt" | sort -u)
# Each profile's set, as its manifest grants it: NET_ADMIN is bit 12, BPF 39,
# and the routed-link Component the combined run composes adds SYS_PTRACE 19
# and SYS_ADMIN 21.
if [ "${PROFILE}" = combined ]; then
  want_caps=0000008000281000 want_names="NET_ADMIN, BPF, SYS_PTRACE and SYS_ADMIN"
else
  want_caps=0000008000001000 want_names="NET_ADMIN and BPF"
fi
if [ "${caps}" != "${want_caps}" ]; then
  fail "privileges: Worker's effective capabilities are ${caps}, want ${want_names} only (${want_caps})"
fi
SA=system:serviceaccount:${NS}:galactic-worker
while read -r want verb resource ns; do
  # </dev/null: kc runs docker exec -i, which would read the rest of this list.
  got=$(kc auth can-i --as="${SA}" "${verb}" "${resource}" ${ns:+-n "${ns}"} </dev/null 2>/dev/null || true)
  echo "${verb} ${resource} ${ns:-cluster}: ${got}" >>"${OUT}/rbac.txt"
  [ "${got}" = "${want}" ] || fail "privileges: ${SA} can-i ${verb} ${resource} ${ns}: ${got}, want ${want}"
done <<'EOF'
yes create tokenreviews.authentication.k8s.io
yes watch vpcattachments.galactic.datumapis.com
yes create bgpvrfinstances.galactic.datumapis.com galactic-system
no create bgpvrfinstances.galactic.datumapis.com ns80
no update vpcattachments.galactic.datumapis.com ns80
no delete bgprouters.galactic.datumapis.com galactic-system
no create pods
no get secrets galactic-system
no create bgpadvertisements.galactic.datumapis.com galactic-system
EOF

log "claims"
if ! "${LAB}" client-up "${SITE}" "${CLAIM_NODE}" >>"${OUT}/steps.log" 2>&1; then
  kc -n "${NS}" describe pod "worker-lab-client-${CLAIM_NODE}" >"${OUT}/client-describe.txt" 2>&1
  kc -n "${NS}" logs "worker-lab-client-${CLAIM_NODE}" --all-containers >"${OUT}/client-logs.txt" 2>&1
  fail "claims: the claim client on ${CLAIM_NODE} did not become ready (client-describe.txt, client-logs.txt)"
  exit 1
fi
ATT_UID=$(uid_of "${CLAIM_NS}" "${CLAIM_ATT}")
REMOTE_UID=$(uid_of ns80 vpc-a2)
if [ "${PROFILE}" = dedicated ]; then
  DESTS=${REMOTE_UID}
else
  LOCAL_UID=$(uid_of ns80-tap vpc-a-tap)
  DESTS=${LOCAL_UID},${REMOTE_UID}
fi
claim "${CLAIM_NODE}" "${ATT_UID}" tap "${DESTS}" >/dev/null
wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" '^fabric true true true AsExpected$' "Fabric destination ready"
if [ "${PROFILE}" = dedicated ]; then
  # Without the routed-link Component, Worker reports a routed link
  # unavailable instead of failing on the pod's namespace.
  REFUSED_UID=$(uid_of ns80 vpc-b)
  VPC=81 claim "${CLAIM_NODE}" "${REFUSED_UID}" routed_link "${REFUSED_UID}" >"${OUT}/routed-link-refused.json" || true
  VPC=81 wait_dest "${CLAIM_NODE}" "${REFUSED_UID}" "${REFUSED_UID}" ' RoutedLinkUnavailable$' \
    "routed link reported unavailable without the routed-link Component"
  VPC=81 release "${CLAIM_NODE}" "${REFUSED_UID}" routed_link "${REFUSED_UID}" >/dev/null || fail "routed release failed"
fi
if [ "${PROFILE}" = combined ]; then
  wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${LOCAL_UID}" '^local true true true AsExpected$' "Local destination ready"
  # A routed link's pod end goes into the client pod's network namespace.
  ROUTED_UID=$(uid_of ns80-tap vpc-b-tap)
  VPC=81 claim "${CLAIM_NODE}" "${ROUTED_UID}" routed_link "${ROUTED_UID}" >"${OUT}/routed-link.json" || true
  VPC=81 wait_dest "${CLAIM_NODE}" "${ROUTED_UID}" "${ROUTED_UID}" '^local true ' "routed link created in the client's pod"
fi
save_diagnostics reconciled
snap_all reconciled
compare reconciled

log "fault: route"
docker exec "${CLAIM_NODE}" ip -6 route add unreachable "${REMOTE_LOCATOR}"
wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" ' UnderlayUnreachable$' "route fault identified"
save_diagnostics fault-route
docker exec "${CLAIM_NODE}" ip -6 route del unreachable "${REMOTE_LOCATOR}"
wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" '^fabric true true true AsExpected$' "route fault recovered"

log "fault: attachment"
if [ "${PROFILE}" = dedicated ]; then
  # Scaled to zero, not deleted: the Deployment would replace the pod before
  # Worker reads the change.
  kc -n ns80 scale deployment guest-a2 --replicas=0 >>"${OUT}/steps.log"
  kc -n ns80 wait --for=delete pod -l app=vpc-a2 --timeout=120s >>"${OUT}/steps.log"
  wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" \
    ' (ForwardRouteMissing|RouteWithdrawn|NeighborUnresolved|LocatorUnknown|DestinationNotFound)$' \
    "attachment fault identified"
  save_diagnostics fault-attachment
  kc -n ns80 scale deployment guest-a2 --replicas=1 >>"${OUT}/steps.log"
  kc -n ns80 wait --for=condition=Ready pod -l app=vpc-a2 --timeout=240s >>"${OUT}/steps.log"
  "${SCRIPT_DIR}/publish-attachments.sh" ns80 dfw >>"${OUT}/steps.log"
  wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" '^fabric true true true AsExpected$' "attachment fault recovered"
else
  kc -n ns80-tap scale deployment tap-guest-a --replicas=0 >>"${OUT}/steps.log"
  kc -n ns80-tap wait --for=delete pod -l app=vpc-a-tap --timeout=120s >>"${OUT}/steps.log"
  # The guest's TAP goes with it (HandoffInterfaceMissing), or its
  # attachment's node with its pod (LocatorUnknown), whichever Worker reads
  # first.
  wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${LOCAL_UID}" ' (HandoffInterfaceMissing|LocatorUnknown)$' \
    "attachment fault identified"
  save_diagnostics fault-attachment
  kc -n ns80-tap scale deployment tap-guest-a --replicas=1 >>"${OUT}/steps.log"
  kc -n ns80-tap wait --for=condition=Ready pod -l app=vpc-a-tap --timeout=240s >>"${OUT}/steps.log"
  "${SCRIPT_DIR}/publish-attachments.sh" ns80-tap dfw >>"${OUT}/steps.log"
  wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${LOCAL_UID}" '^local true true true AsExpected$' "attachment fault recovered"

  log "fault: hook"
  before=$(metric "${CLAIM_NODE}" 'galactic_worker_drift_repairs_total\{module="local"\}' | awk '{print $2}')
  # No pipe into head: under pipefail its early exit would end the script.
  rxs=$(docker exec "${CLAIM_NODE}" sh -c 'for d in $(ls /sys/class/net); do
    tc filter show dev "$d" ingress 2>/dev/null | grep -q galactic_local_rx && echo "$d"; done' || true)
  rx=${rxs%%$'\n'*}
  if [ -z "${rx}" ]; then
    fail "hook fault: no device carries galactic_local_rx on ${CLAIM_NODE}"
  else
    log "removing galactic_local_rx from ${rx}"
    docker exec "${CLAIM_NODE}" tc filter del dev "${rx}" ingress pref \
      "$(docker exec "${CLAIM_NODE}" tc filter show dev "${rx}" ingress | awk '/galactic_local_rx/ {for (i=1;i<=NF;i++) if ($i=="pref") print $(i+1); exit}')"
    for _ in $(seq 40); do
      after=$(metric "${CLAIM_NODE}" 'galactic_worker_drift_repairs_total\{module="local"\}' | awk '{print $2}')
      [ "${after:-0}" != "${before:-0}" ] && break
      sleep 2
    done
    # inspect reads Worker's status snapshot, written within 5 seconds of
    # the repair the counter already shows.
    for _ in $(seq 15); do
      save_diagnostics fault-hook
      grep -q "repaired drift .*galactic_local_rx.*${rx}" "${OUT}/fault-hook/inspect-${CLAIM_NODE}.txt" && break
      sleep 2
    done
    if [ "${after:-0}" = "${before:-0}" ]; then
      fail "hook fault: galactic_worker_drift_repairs_total{module=\"local\"} stayed ${before}"
    elif ! grep -q "repaired drift .*galactic_local_rx.*${rx}" "${OUT}/fault-hook/inspect-${CLAIM_NODE}.txt"; then
      fail "hook fault: inspect does not name galactic_local_rx on ${rx}"
    else
      log "ok: hook fault identified and repaired"
    fi
    filters=$(docker exec "${CLAIM_NODE}" tc filter show dev "${rx}" ingress)
    if ! grep -q galactic_local_rx <<<"${filters}"; then
      fail "hook fault: galactic_local_rx is not back on ${rx}"
    fi
  fi
fi

log "second reconcile"
sleep 35
save_diagnostics resynced
snap_all resynced
compare resynced

log "restart"
kc -n "${NS}" delete pod -l app.kubernetes.io/name=galactic-worker --wait=true >>"${OUT}/steps.log"
kc -n "${NS}" rollout status ds/galactic-worker --timeout=300s >>"${OUT}/steps.log"
wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" '^fabric true true true AsExpected$' "ready after restart"
snap_all restarted
compare restarted

log "drain ${DRAIN_NODE}"
kc drain "${DRAIN_NODE}" --ignore-daemonsets --delete-emptydir-data --timeout=180s >>"${OUT}/steps.log" 2>&1 ||
  fail "drain of ${DRAIN_NODE} failed"
kc uncordon "${DRAIN_NODE}" >>"${OUT}/steps.log"
wait_dest "${CLAIM_NODE}" "${ATT_UID}" "${REMOTE_UID}" '^fabric true true true AsExpected$' "ready after drain"
# The drain evicts the node's tenant pods, which come back once it is
# uncordoned; compare once the state settles, within 3 minutes.
for _ in $(seq 36); do
  snap_all drained
  same=1
  for node in "${NODES[@]}"; do
    cmp -s "${OUT}/baseline/${node}.txt" "${OUT}/drained/${node}.txt" || same=0
  done
  [ "${same}" = 1 ] && break
  sleep 5
done
compare drained

log "release and uninstall"
release "${CLAIM_NODE}" "${ATT_UID}" tap "${DESTS}" >/dev/null || fail "release failed"
if [ "${PROFILE}" = combined ]; then
  VPC=81 release "${CLAIM_NODE}" "${ROUTED_UID}" routed_link "${ROUTED_UID}" >/dev/null || fail "routed release failed"
fi
"${LAB}" client-down "${SITE}" >>"${OUT}/steps.log"
kc -n "${NS}" logs -l app.kubernetes.io/name=galactic-worker --all-containers --prefix --tail=-1 \
  >"${OUT}/worker-logs.txt" 2>&1
ROUTER_RESTARTS="${OUT}/router-restarts.txt" "${LAB}" uninstall "${SITE}" 2>&1 | tee "${OUT}/uninstall.log"
for node in "${NODES[@]}"; do
  docker exec "${node}" sh -c 'cat /var/lib/galactic-edge/ownership/*.json 2>/dev/null || true' >"${OUT}/fence-${node}.json"
  if grep -q '"galactic-worker:' "${OUT}/fence-${node}.json"; then
    fail "uninstall: ${node} still has Worker-owned scopes"
  fi
  links=$(docker exec "${node}" ip -o link show | awk '{print $2}')
  if grep -qE '^G[A-Za-z0-9]{12}[NTRP](@|:)' <<<"${links}"; then
    fail "uninstall: Local links remain on ${node}"
  fi
  if docker exec "${node}" test -e /sys/fs/bpf/galactic-local; then
    fail "uninstall: Local pins remain on ${node}"
  fi
done
# galactic-router restarted on every node in the uninstall and writes its
# tenant routes again. Each node's state is compared once it matches the
# baseline, within 5 minutes, and the time from that node's router restart
# until then is its route gap, which the qualification report (#1442) takes
# from route-gap.txt.
declare -A gap=()
mkdir -p "${OUT}/uninstalled"
for _ in $(seq 60); do
  pending=0
  for node in "${NODES[@]}"; do
    [ -n "${gap[${node}]:-}" ] && continue
    snapshot "${node}" >"${OUT}/uninstalled/${node}.txt"
    if cmp -s "${OUT}/baseline/${node}.txt" "${OUT}/uninstalled/${node}.txt"; then
      restarted=$(awk -v n="${node}" '$1 == n {print $2}' "${OUT}/router-restarts.txt" 2>/dev/null | tail -1)
      gap[${node}]=$(($(date +%s) - ${restarted:-$(date +%s)}))
    else
      pending=1
    fi
  done
  [ "${pending}" = 0 ] && break
  sleep 5
done
for node in "${NODES[@]}"; do
  echo "${node} ${gap[${node}]:-unsettled}" | tee -a "${OUT}/route-gap.txt"
done
log "tenant route gap after the router restart, seconds per node: $(tr '\n' ' ' <"${OUT}/route-gap.txt")"
compare uninstalled
log "done"
