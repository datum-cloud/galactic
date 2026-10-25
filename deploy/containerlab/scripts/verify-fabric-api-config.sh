#!/bin/bash
# verify-fabric-api-config.sh — Check, without a running lab, that each site's
# fabric-router overlay renders the fabric-api ConfigMap with the site as its
# site and cell. The fabric-api node sidecar reads both once, at start, so the
# ConfigMap has to arrive in the same apply as the DaemonSet (deploy:fabric);
# a sidecar that starts without it serves nothing until its pod is recreated.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# deploy:fabric copies config/fabric-router/ to base/fabric on each node
# before applying; build from the same layout.
tmp=$(mktemp -d)
trap 'rm -rf "${tmp}"' EXIT
cp -r "${RESOURCES_DIR}/fabric-router" "${tmp}/"
rm -rf "${tmp}/fabric-router/base/fabric"
cp -r "${CONFIG_DIR}/fabric-router" "${tmp}/fabric-router/base/fabric"

fail=0
for site in dfw iad sjc; do
  # kustomize prints each object's keys sorted, at fixed indents: data's keys
  # and metadata's name and namespace two spaces in.
  got=$(kubectl kustomize "${tmp}/fabric-router/${site}" | awk '
    function emit() { if (kind == "ConfigMap" && name == "fabric-api") print ns, s, c }
    /^---$/ { emit(); kind = name = ns = s = c = ""; sec = ""; next }
    /^[a-z]/ { sec = $1 }
    /^kind: / { kind = $2 }
    sec == "metadata:" && /^  name: / { name = $2 }
    sec == "metadata:" && /^  namespace: / { ns = $2 }
    sec == "data:" && /^  site: / { s = $2 }
    sec == "data:" && /^  cell: / { c = $2 }
    END { emit() }')
  if [[ "${got}" == "galactic-system ${site} ${site}" ]]; then
    echo "ok   ${site}: fabric-router overlay renders fabric-api with site and cell ${site}"
  else
    echo "FAIL ${site}: fabric-router overlay's fabric-api ConfigMap (namespace site cell) is '${got:-missing}'"
    fail=1
  fi
done
exit "${fail}"
