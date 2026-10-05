#!/bin/bash
# xdp-dispatch-release.sh — Detach the galactic XDP dispatcher from a node's
# interfaces (internal/plumbing/ebpf/xdpdispatch).
#
# The dispatcher's links are pinned, so they stay attached after galactic-nat
# and galactic-gateway are gone. Run this:
#   - after removing both DaemonSets from a node for good, and
#   - before rolling either binary back to an image that predates the
#     dispatcher: such an image attaches its own XDP program and fails with
#     EBUSY while the dispatcher holds the interface.
#
# Removing a link pin detaches the root from that interface, which on most
# drivers resets it once. Every datapath on it stops seeing traffic at once.
#
# Usage:
#   xdp-dispatch-release.sh                 run on this host, as root
#   xdp-dispatch-release.sh --node NAME     run on NAME through kubectl debug
#   add --all to also remove the pinned maps, root and role rows
#
# kubectl debug leaves its pod behind. Delete it by the name it prints,
# node-debugger-NAME-xxxxx. --node pulls busybox, so a node that cannot reach
# a registry needs the script run locally instead.
set -euo pipefail

PIN_DIR=/sys/fs/bpf/galactic-xdp
node=""
all=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node)
      node="${2:?--node needs a node name}"
      shift 2
      ;;
    --all)
      all=true
      shift
      ;;
    -h | --help)
      sed -n '/^# xdp-dispatch-release.sh/,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

# release runs on the node itself. $1 is the bpffs root as seen by the caller.
release_script() {
  cat <<EOF
set -eu
dir="\$1${PIN_DIR}"
if [ ! -d "\$dir" ]; then
  echo "no dispatcher state at \$dir"
  exit 0
fi
for pin in "\$dir"/links/*; do
  [ -e "\$pin" ] || continue
  echo "detaching dispatcher from ifindex \$(basename "\$pin")"
  rm -f "\$pin"
done
if [ "${all}" = true ]; then
  echo "removing \$dir"
  rm -rf "\$dir"
fi
EOF
}

if [[ -z "${node}" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "run as root, or pass --node" >&2
    exit 1
  fi
  sh -c "$(release_script)" sh ""
  exit 0
fi

# kubectl debug mounts the node's root filesystem at /host; the host's bpffs
# is a submount of it.
kubectl debug "node/${node}" --profile=sysadmin --image=busybox:1.37 --attach --quiet -- \
  sh -c "$(release_script)" sh /host
