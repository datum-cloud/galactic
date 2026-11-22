#!/bin/bash
# Finish cluster deletion even if image-cache cleanup fails; preserve its failure.
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
status=0
"${SCRIPT_DIR}/lab-node-cache.py" release || status=1
for site in dfw sjc iad; do
  kind delete cluster --name "${site}" || status=1
done
exit "${status}"
