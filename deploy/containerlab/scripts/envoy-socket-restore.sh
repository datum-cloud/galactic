#!/bin/bash
# envoy-socket-restore.sh: restore the lab after envoy-socket.sh
# (docs/envoy-socket.md). Worker takes over every VPC scope on dfw-worker and
# never hands one back, so after it stops galactic-router leaves those VPCs'
# tenant routes to a Worker that is gone (worker-fabric.sh). A fresh deploy
# is the restore: destroy the lab, deploy it, and verify ns80 and everything
# else. Stops at the first step that fails.
#
# Usage: envoy-socket-restore.sh
set -euo pipefail

LAB_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "${LAB_DIR}"

for step in destroy deploy verify:ns80 verify; do
  echo "##### task ${step} #####"
  if ! task "${step}"; then
    echo "envoy-socket-restore: task ${step} failed" >&2
    exit 1
  fi
done
echo "envoy-socket-restore: the lab is redeployed and verified"
