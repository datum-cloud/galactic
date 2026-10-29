#!/bin/bash
# restart-node.sh NODE: restart one Kind node container with `docker
# restart` and put back the lab plumbing that lived in its network
# namespace, which the restart replaces:
#
#   1. every gvpc.clab.yaml link with an end on NODE (containerlab tools veth
#      create; the peer's end went with the old namespace too);
#   2. NODE's net.* sysctls and exec commands from gvpc.clab.yaml (blackhole
#      route, bonds, install.sh);
#   3. each peer's bond membership, from the peer's own exec commands or a
#      transit router's startup.sh;
#   4. the pass-through XDP programs on the transit and compute ports
#      (deploy:lab-xdp-passthrough and deploy:lab-xdp-passthrough-compute);
#   5. NODE's addresses (resources/node-addresses/NODE.addrs).
#
# The Kind node shares the host's kernel, so its boot ID does not change;
# the script prints it before and after. Kubernetes restarts the node's pods
# in place. Needs passwordless sudo for containerlab. Used by
# TestMASQUEService's node-restart row.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"
LAB_DIR="${SCRIPT_DIR}/.."
TOPO="${LAB_DIR}/gvpc.clab.yaml"
LAB=$(awk '/^name:/ {print $2; exit}' "${TOPO}")

node="${1:?usage: restart-node.sh NODE}"

# container NAME prints the Docker container of a topology node: a Kind node
# keeps its own name, a containerlab node is prefixed with the lab's.
container() {
  if docker inspect "$1" >/dev/null 2>&1; then
    echo "$1"
  else
    echo "clab-${LAB}-$1"
  fi
}

# block NAME prints the YAML lines of topology node NAME.
block() {
  awk -v n="    $1:" '
    $0 == n { on = 1; next }
    on && /^    [^ ]/ { exit }
    on && /^  [^ ]/ { exit }
    on { print }
  ' "${TOPO}"
}

# execs NAME prints topology node NAME's exec commands.
execs() {
  block "$1" | awk '
    /^      exec:/ { on = 1; next }
    on && /^        - / { sub(/^        - /, ""); print; next }
    on { exit }
  '
}

# links prints "A IFA B IFB MTU" for every link with an end on NODE. MTU is
# "-" for a link with no mtu line, which keeps containerlab's default.
links() {
  awk -v n="${node}" '
    function emit() {
      if (a != "" && (index(a, n ":") == 1 || index(b, n ":") == 1)) {
        split(a, x, ":"); split(b, y, ":")
        print x[1], x[2], y[1], y[2], mtu
      }
      a = ""
    }
    /endpoints:/ {
      emit()
      line = $0
      gsub(/[\[\]",]/, " ", line)
      split(line, f, " ")
      a = f[3]; b = f[4]; mtu = "-"
      next
    }
    a != "" && /^ *mtu:/ { mtu = $2; next }
    { emit() }
    END { emit() }
  ' "${TOPO}"
}

boot_id() { docker exec "$(container "${node}")" cat /proc/sys/kernel/random/boot_id; }

echo "boot ID before: $(boot_id)"
docker restart "$(container "${node}")" >/dev/null
until [ "$(docker inspect -f '{{.State.Running}}' "$(container "${node}")")" = true ]; do sleep 1; done
echo "boot ID after: $(boot_id)"

peers=()
while read -r a ia b ib mtu; do
  echo "link ${a}:${ia} <-> ${b}:${ib} (mtu ${mtu})"
  mtu_flag=()
  if [ "${mtu}" != - ]; then mtu_flag=(-m "${mtu}"); fi
  sudo -n containerlab tools veth create -a "$(container "${a}"):${ia}" -b "$(container "${b}"):${ib}" \
    "${mtu_flag[@]}" >/dev/null
  if [ "${a}" = "${node}" ]; then peers+=("${b}:${ib}"); else peers+=("${a}:${ia}"); fi
done < <(links)

c=$(container "${node}")
block "${node}" | awk '
  /^      sysctls:/ { on = 1; next }
  on && /^        [a-z]/ { gsub(/[":]/, " "); print $1, $2; next }
  on { exit }
' | while read -r key value; do
  case "${key}" in net.*) docker exec "${c}" sysctl -qw "${key}=${value}" ;; esac
done
while read -r cmd; do
  echo "${node}: ${cmd}"
  # The blackhole route may already exist if the node kept it.
  docker exec "${c}" sh -c "${cmd}" || case "${cmd}" in "ip -6 route add blackhole"*) ;; *) exit 1 ;; esac
done < <(execs "${node}")

for p in "${peers[@]}"; do
  peer=${p%%:*} iface=${p##*:}
  pc=$(container "${peer}")
  if [ -f "${LAB_DIR}/node_files/${peer}/startup.sh" ]; then
    cmd=$(grep -E "mkbond\.sh [a-z0-9]+ .*\b${iface}\b" "${LAB_DIR}/node_files/${peer}/startup.sh" | sed 's/#.*//')
  else
    cmd=$(execs "${peer}" | grep -E "mkbond\.sh [a-z0-9]+ .*\b${iface}\b" || true)
  fi
  if [ -n "${cmd}" ]; then
    echo "${peer}: ${cmd}"
    docker exec "${pc}" sh -c "${cmd}"
  fi
done

(cd "${LAB_DIR}" && task deploy:lab-xdp-passthrough deploy:lab-xdp-passthrough-compute) >/dev/null

file="${RESOURCES_DIR}/node-addresses/${node}.addrs"
if [ -f "${file}" ]; then
  while read -r iface key rest; do
    case "${iface}" in '' | '#'*) continue ;; esac
    if [ "${key}" = alias ]; then
      docker exec "${c}" ip link set dev "${iface}" alias "${rest}"
    else
      docker exec "${c}" ip addr replace "${key}" dev "${iface}"
    fi
  done <"${file}"
fi
echo "${node}: restarted and replumbed"
