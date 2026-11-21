#!/bin/bash
# verify-nat-local-clean.sh: prove verify:nat-local-shard left dfw-worker2 as
# it found it, so later checks can run on the same deployment.
#
#   verify-nat-local-clean.sh snapshot DIR   record the deployed values first
#   verify-nat-local-clean.sh assert DIR     check against them afterwards
#
# assert fails on the first of these that does not hold:
#   - no ns80 object of the nat-local fixture (named *-edge) remains;
#   - no galactic-worker process or socket remains on dfw-worker2;
#   - galactic-nat carries no GALACTIC_NAT_WORKER_SOCKET, its pod template is
#     the one recorded, and every pod is updated and Ready;
#   - galactic-cni's egress settings are the ones recorded, and it is rolled
#     out;
#   - remote-host has no UDP socket on port 7;
#   - dfw-worker2 holds no Local link, Local tc filter, Local pin directory,
#     egress_local_shard row, PassThroughLocalNAT route, galactic-nat local
#     link pin or galactic-nat pair row.
#   - no VPC scope on dfw-worker2 is owned by a galactic-worker incarnation:
#     the case's clean-up hands them back.
set -euo pipefail

CP=dfw-control-plane
EDGE=dfw-worker2
REMOTE=clab-gvpc-remote-host
mode=${1:?snapshot or assert}
dir=${2:?directory}

kc() { docker exec "${CP}" kubectl "$@"; }
die() {
  echo "FAIL: $*" >&2
  exit 1
}

nat_template() {
  kc -n galactic-system get ds galactic-nat -o json |
    python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["spec"]["template"], sort_keys=True))'
}
cni_env() {
  kc -n galactic-system get ds galactic-cni -o json | python3 -c 'import json,sys
d = json.load(sys.stdin)
for c in d["spec"]["template"]["spec"]["containers"]:
    if c["name"] == "credential-refresh":
        print(json.dumps(sorted(c.get("env", []), key=lambda e: e["name"]), sort_keys=True))'
}

case "${mode}" in
  snapshot)
    mkdir -p "${dir}"
    nat_template >"${dir}/galactic-nat-template.json"
    cni_env >"${dir}/galactic-cni-env.json"
    echo "recorded galactic-nat's pod template and galactic-cni's egress settings in ${dir}"
    exit 0
    ;;
  assert) ;;
  *) die "unknown mode ${mode}" ;;
esac
[ -s "${dir}/galactic-nat-template.json" ] && [ -s "${dir}/galactic-cni-env.json" ] ||
  die "no snapshot in ${dir}"

left=$(kc -n ns80 get deploy,pods,network-attachment-definitions,vpcattachments,trafficpolicybindings -o name |
  grep -- '-edge' || true)
[ -z "${left}" ] || die "nat-local fixture objects remain in ns80: ${left}"
echo "ok   no nat-local fixture object remains in ns80"

if docker exec "${EDGE}" pgrep -f '^/opt/galactic-worker/galactic-worker' >/dev/null 2>&1; then
  die "galactic-worker still runs on ${EDGE}"
fi
if docker exec "${EDGE}" test -e /run/galactic-worker/worker.sock; then
  die "galactic-worker's socket remains on ${EDGE}"
fi
echo "ok   no galactic-worker process or socket on ${EDGE}"

env_names=$(kc -n galactic-system get ds galactic-nat \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="galactic-nat")].env[*].name}')
case " ${env_names} " in
  *" GALACTIC_NAT_WORKER_SOCKET "*) die "galactic-nat still carries GALACTIC_NAT_WORKER_SOCKET" ;;
esac
[ "$(nat_template)" = "$(cat "${dir}/galactic-nat-template.json")" ] ||
  die "galactic-nat's pod template differs from the deployed one"
kc -n galactic-system rollout status daemonset/galactic-nat --timeout=300s >/dev/null ||
  die "galactic-nat is not rolled out"
# jsonpath ends without a newline, which read reports as a failure, so the
# counts are captured first and read from a here-string.
counts=$(kc -n galactic-system get ds galactic-nat \
  -o jsonpath='{.status.desiredNumberScheduled} {.status.numberReady} {.status.updatedNumberScheduled}') ||
  die "cannot read galactic-nat's rollout counts"
read -r desired ready updated <<<"${counts}"
[ "${ready}" = "${desired}" ] && [ "${updated}" = "${desired}" ] ||
  die "galactic-nat has ${ready}/${desired} Ready and ${updated}/${desired} updated"
echo "ok   galactic-nat runs its deployed template, ${ready}/${desired} Ready"

[ "$(cni_env)" = "$(cat "${dir}/galactic-cni-env.json")" ] ||
  die "galactic-cni's egress settings differ from the deployed ones"
kc -n galactic-system rollout status daemonset/galactic-cni --timeout=600s >/dev/null ||
  die "galactic-cni is not rolled out"
echo "ok   galactic-cni runs its deployed egress settings"

[ -z "$(docker exec "${REMOTE}" ss -Hlun 'sport = :7')" ] || die "remote-host still has a UDP socket on port 7"
echo "ok   no echo server on remote-host port 7"

[ -z "$(docker exec "${EDGE}" ip -o link show | grep 'alias galactic-local:' || true)" ] ||
  die "Local links remain on ${EDGE}"
filters=""
for l in $(docker exec "${EDGE}" ip -o link show | awk -F': ' '{sub(/@.*/, "", $2); print $2}'); do
  if docker exec "${EDGE}" tc filter show dev "${l}" ingress 2>/dev/null | grep -E 'local_(link_rx|rx|pair_rx|link_gu)' >/dev/null; then
    filters="${filters} ${l}"
  fi
done
[ -z "${filters}" ] || die "Local tc filters remain on${filters}"
if docker exec "${EDGE}" test -e /sys/fs/bpf/galactic-local; then
  die "Local's pin directory /sys/fs/bpf/galactic-local remains on ${EDGE}"
fi
pins=$(docker exec "${EDGE}" sh -c 'ls /sys/fs/bpf/galactic-nat/links 2>/dev/null | grep "^local-" || true')
[ -z "${pins}" ] || die "galactic-nat local link pins remain: ${pins}"
echo "ok   no Local link, tc filter or pin directory, and no galactic-nat local link pin, on ${EDGE}"

pid=$(docker inspect -f '{{.State.Pid}}' "${EDGE}")
count() { # PINNED-PATH
  sudo -n bpftool -j map dump pinned "/proc/${pid}/root$1" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'
}
for m in /sys/fs/bpf/galactic/egress_local_shard /sys/fs/bpf/galactic-nat/nat_local_pair \
  /sys/fs/bpf/galactic-nat/nat_local_return /sys/fs/bpf/galactic-nat/nat_vlan_egress; do
  n=$(count "${m}") || die "cannot read ${m} on ${EDGE}"
  [ "${n}" = 0 ] || die "${m} on ${EDGE} still holds ${n} rows"
done
echo "ok   egress_local_shard and galactic-nat's pair maps are empty on ${EDGE}"

# The egress sweep restores a class route from PassThroughLocalNAT within a
# poll of its row going.
local_routes() {
  sudo -n bpftool -j map dump pinned "/proc/${pid}/root/sys/fs/bpf/galactic/egress_route_table" |
    python3 -c 'import json,sys
n = 0
for e in json.load(sys.stdin):
    f = e.get("formatted")
    if f:
        sid0, link = f["value"]["sid"][0], f["value"]["link_ifindex"]
    else:
        v = [int(b, 16) for b in e["value"]]
        sid0, link = v[0], int.from_bytes(bytes(v[16:20]), "little")
    if link == 0 and sid0 == 3:
        n += 1
print(n)'
}
deadline=$((SECONDS + 30))
until [ "$(local_routes)" = 0 ]; do
  [ ${SECONDS} -lt ${deadline} ] || die "PassThroughLocalNAT routes remain on ${EDGE} after 30s"
  sleep 2
done
echo "ok   no PassThroughLocalNAT route on ${EDGE}"

owned=$(docker exec "${EDGE}" sh -c 'for f in /var/lib/galactic-edge/ownership/vpc-*.json; do
    [ -e "$f" ] || continue; printf "%s " "$(basename "$f" .json)"; cat "$f"; echo; done' |
  python3 -c 'import json,sys
for line in sys.stdin:
    name, _, rec = line.strip().partition(" ")
    if rec and json.loads(rec).get("owner", "").startswith("galactic-worker:"):
        print(name)') || die "cannot read ${EDGE}'s ownership fence"
[ -z "${owned}" ] || die "a galactic-worker incarnation still owns these scopes on ${EDGE}: $(tr '\n' ' ' <<<"${owned}")"
echo "ok   no VPC scope on ${EDGE} is owned by a galactic-worker incarnation"
echo "PASS: ${EDGE} is clean of verify:nat-local-shard"
