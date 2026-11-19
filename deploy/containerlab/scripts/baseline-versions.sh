#!/bin/bash
# baseline-versions.sh: check the pinned versions in baseline/pins.yaml
# against the host tools, the lab's Dockerfiles, the ns80 fixture and the
# running lab, and record every version the baseline depends on.
#
# Usage: baseline-versions.sh OUTFILE
#
# OUTFILE gets a YAML record: each pin with its expected and observed value,
# then the unpinned values (kernel, Docker, Galactic revision, image IDs and
# digests). Exits non-zero if any pin disagrees.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

LAB=${LAB:-gvpc}
OUTFILE=${1:?usage: baseline-versions.sh OUTFILE}
LAB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPO=$(cd "${LAB_DIR}/../.." && pwd)
PINS="${LAB_DIR}/baseline/pins.yaml"

pin() { awk -v k="$1" -F': ' '$1 == k {print $2; exit}' "${PINS}"; }
dockerfile_arg() { sed -nE "s/^ARG $2=(.*)/\1/p" "$1" | head -1; }

mkdir -p "$(dirname "${OUTFILE}")"
rc=0
{
  echo "# Recorded by scripts/baseline-versions.sh"
  echo "pins:"
} >"${OUTFILE}"

# check KEY SOURCE OBSERVED
check() {
  local want
  want=$(pin "$1")
  local ok=match
  if [ "${want}" != "$3" ]; then
    ok=MISMATCH
    rc=1
  fi
  printf '  - {pin: %s, source: "%s", want: "%s", got: "%s", result: %s}\n' "$1" "$2" "${want}" "$3" "${ok}" >>"${OUTFILE}"
  printf '%-9s %-17s %-40s want %s got %s\n' "${ok}" "$1" "$2" "${want}" "$3"
}

check containerlab "containerlab version" "$(containerlab version 2>/dev/null | sed -nE 's/^ *version: *//p' | head -1)"
check kind "kind version" "$(kind version | awk '{print $2}')"
check task "task --version" "$(task --version | sed -E 's/^Task version: //; s/ .*//')"
check kindest_node "kindest-node-galactic Dockerfile" \
  "$(dockerfile_arg "${LAB_DIR}/containers/kindest-node-galactic/Dockerfile" KINDEST_VER)"
check kindest_node "dfw API server" \
  "$(docker exec "$(control_plane dfw)" kubectl version -o json | jq -r .serverVersion.gitVersion)"
check frr "fabric-router Dockerfile" "$(dockerfile_arg "${REPO}/containers/fabric-router/Dockerfile" FRR_VERSION)"
check frr "tr1 vtysh" \
  "$(docker exec "clab-${LAB}-tr1" vtysh -c 'show version' | sed -nE 's/^FRRouting ([0-9.]+).*/\1/p' | head -1)"
check remote_host_base "remote-host Dockerfile" "$(sed -nE 's/^FROM (.*)/\1/p' "${REPO}/containers/remote-host/Dockerfile" | head -1)"
for f in base/guests.yaml; do
  for img in $(sed -nE 's/^ *image: *//p' "${LAB_DIR}/resources/tenants/ns80/${f}" | sort -u); do
    check guest_image "ns80/${f}" "${img}"
  done
done
# What the running guests were actually started from.
for site in dfw sjc; do
  got=$(docker exec "$(control_plane "${site}")" kubectl get pods -n ns80 -o json |
    jq -r '[.items[].status.containerStatuses[]?.imageID] | unique | join(",")')
  check guest_image "ns80 pods in ${site}" "ghcr.io/datum-cloud/galactic-debug@${got##*@}"
done

{
  echo "recorded:"
  echo "  host_kernel: \"$(uname -r)\""
  echo "  docker: \"$(docker version -f '{{.Server.Version}}')\""
  echo "  kubectl_client: \"$(kubectl version --client -o json | jq -r .clientVersion.gitVersion)\""
  echo "  node_kernel: \"$(docker exec dfw-worker uname -r)\""
  echo "  galactic_revision: \"$(git -C "${REPO}" rev-parse HEAD)\""
  echo "  galactic_tree: \"$(git -C "${REPO}" diff --quiet HEAD && echo clean || echo dirty)\""
  echo "  local_images:"
  docker images --no-trunc --format '{{.Repository}}:{{.Tag}} {{.ID}}' |
    grep -E '^(kindest/node:galactic|fabric-router:|remote-host:|galactic-[a-z-]+:|fabric-[a-z-]+:|masque-[a-z-]+:)' |
    sort | awk '{printf "    - {image: \"%s\", id: \"%s\"}\n", $1, $2}'
  echo "  dfw_worker_images:"
  docker exec dfw-worker crictl images -o json |
    jq -r '.images[] | select(any(.repoTags[]?; test("galactic|fabric|masque"))) | "\(.repoTags[0]) \(.id)"' |
    sort | awk '{printf "    - {image: \"%s\", id: \"%s\"}\n", $1, $2}'
} >>"${OUTFILE}"

echo "versions recorded in ${OUTFILE}"
exit "${rc}"
