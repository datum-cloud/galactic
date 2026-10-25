#!/bin/bash
# deploy-tenant-policy.sh — apply a tenant's traffic policies and bindings
# (resources/tenants/<namespace>/policy/) to the given sites. A site with
# its own policy/<site>/ overlay, for attachments only that site has, gets
# that overlay instead.
#
# The lab enforces traffic policy, so a tenant's interfaces deny everything
# until these are bound and galactic-router publishes them. Runs before the
# tenant's pods, so a pod's interface is granted as soon as its attachment is
# published (scripts/publish-attachments.sh).
#
# Usage: deploy-tenant-policy.sh <namespace> <site> [site...]
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $(basename "$0") <namespace> <site> [site...]" >&2
  exit 1
fi

NS="$1"
shift

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

for site in "$@"; do
  node=$(control_plane "${site}")
  echo "Applying ${NS}'s traffic policy to ${site}..."
  ensure_namespace "${node}" "${NS}"
  # The policy sets each tenant's policy/ kustomization pulls in.
  copy_to "${node}" tenants/policies
  copy_to "${node}" "tenants/${NS}/policy"
  dir="tenants/${NS}/policy"
  [ -d "${SCRIPT_DIR}/../resources/${dir}/${site}" ] && dir="${dir}/${site}"
  apply_k "${node}" "/galactic/resources/${dir}/"
done

echo "Done."
