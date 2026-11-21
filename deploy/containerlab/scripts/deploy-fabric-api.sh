#!/bin/bash
# deploy-fabric-api.sh — Install the fabric-api looking glass's cell side in
# every cluster: the FabricQuery CRD, the gateway's and janitor's RBAC, the
# lab PKI (a stand-in for the per-cell issuer infra owns in production), and
# the gateway and janitor. The node sidecars come with deploy:fabric, through
# config/fabric-router/components/fabric-api, and so does the fabric-api
# ConfigMap both read, which therefore has to exist before this runs.
#
# Each lab site is one cell; its cell, site and Karmada member cluster name
# are all the site name. Runs host-side through a fresh kubeconfig per site,
# since kustomize can then reach config/ directly.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

# The cell's CA is a plain Secret this script creates once, not a
# cert-manager Certificate. cert-manager can issue a self-signed CA
# Certificate twice within a second of creating it, and every certificate
# the fabric-api Issuer signed in between then chains to a CA the gateway no
# longer trusts (#1477). A Secret nothing manages has one key for its whole
# life.
#
# CA_SCRIPT runs in the site's control-plane container. The key exists only
# in shell variables and the kubectl pipe there: nothing is written to the
# container's or the host's disk.
# shellcheck disable=SC2016 # expanded in the container, not here
CA_SCRIPT='set -eu
pem=$(openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
  -keyout /dev/stdout -out /dev/stdout -days 365 -subj "/CN=fabric-api $1" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" 2>/dev/null)
crt=$(printf "%s\n" "$pem" | sed -n "/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p" | base64 -w0)
key=$(printf "%s\n" "$pem" | sed -n "/-BEGIN PRIVATE KEY-/,/-END PRIVATE KEY-/p" | base64 -w0)
[ -n "$crt" ] && [ -n "$key" ]
printf "%s\n" \
  "apiVersion: v1" \
  "kind: Secret" \
  "type: kubernetes.io/tls" \
  "metadata:" \
  "  name: fabric-api-ca" \
  "  namespace: galactic-system" \
  "data:" \
  "  tls.crt: $crt" \
  "  tls.key: $key" \
  "  ca.crt: $crt" | kubectl create -f -'

# ensure_ca SITE creates SITE's fabric-api-ca Secret unless one exists. A
# lab deployed before #1477 has a cert-manager-managed Secret: its
# Certificate and self-signed Issuer are deleted and the Secret, with its
# current key, is kept, so a rerun never changes the CA under running pods.
# To change a cell's CA, delete the Secret, rerun this, then restart the
# fabric-api-certs and fabric-router DaemonSets and the fabric-api-gateway
# Deployment in galactic-system, and delete the fabric-api-operator Secret.
ensure_ca() {
  local site=$1
  # Without this, deleting the Certificate would garbage-collect the Secret
  # when cert-manager runs with --enable-certificate-owner-ref.
  if [[ -n "$(k -n galactic-system get secret fabric-api-ca --ignore-not-found -o jsonpath='{.metadata.ownerReferences}')" ]]; then
    k -n galactic-system patch secret fabric-api-ca --type json -p '[{"op":"remove","path":"/metadata/ownerReferences"}]'
  fi
  k -n galactic-system delete certificate/fabric-api-ca issuer/fabric-api-selfsigned --ignore-not-found
  if k -n galactic-system get secret fabric-api-ca >/dev/null 2>&1; then
    echo "${site}: keeping the existing fabric-api-ca Secret"
    return
  fi
  docker exec -i "$(control_plane "${site}")" sh -c "${CA_SCRIPT}" sh "${site}"
}

# flat PEM prints PEM with its line breaks removed, so certificates compare
# by content whatever line endings their writer used.
flat() { tr -d '\r\n' <<<"$1"; }

# check_chain SITE fails unless every credential the fabric-api Issuer
# issued in SITE names the current fabric-api-ca as its CA: the operator
# Secret, every CertificateRequest it signed (the gateway's and the nodes'
# csi-driver requests among them) and each fabric node's synced ca.crt.
check_chain() {
  local site=$1 ca bad=0 name got node nodes
  ca=$(flat "$(k -n galactic-system get secret fabric-api-ca -o jsonpath='{.data.tls\.crt}' | base64 -d)")
  got=$(flat "$(k -n galactic-system get secret fabric-api-operator -o jsonpath='{.data.ca\.crt}' | base64 -d)")
  if [[ "${got}" != "${ca}" ]]; then
    echo "${site}: secret/fabric-api-operator chains to a different CA than fabric-api-ca" >&2
    bad=1
  fi
  # A request still pending has no CA yet and signed nothing.
  while read -r name got; do
    [[ -n "${name}" && -n "${got}" ]] || continue
    if [[ "$(flat "$(base64 -d <<<"${got}")")" != "${ca}" ]]; then
      echo "${site}: certificaterequest/${name} was signed by a different CA than fabric-api-ca" >&2
      bad=1
    fi
  done < <(k -n galactic-system get certificaterequests -o jsonpath='{range .items[?(@.spec.issuerRef.name=="fabric-api")]}{.metadata.name}{" "}{.status.ca}{"\n"}{end}')
  # The certs pods were pending until the Issuer existed; give certsync,
  # which copies every 10s, time to write each node's files.
  k -n galactic-system rollout status daemonset/fabric-api-certs --timeout=180s
  nodes=$(k -n galactic-system get pods -l app.kubernetes.io/name=fabric-api-certs -o jsonpath='{.items[*].spec.nodeName}')
  for node in ${nodes}; do
    got=""
    for _ in $(seq 1 30); do
      got=$(flat "$(docker exec "${node}" cat /run/fabric-api/tls/ca.crt 2>/dev/null || true)")
      [[ "${got}" == "${ca}" ]] && break
      sleep 2
    done
    if [[ "${got}" != "${ca}" ]]; then
      echo "${site}: ${node}'s /run/fabric-api/tls/ca.crt is missing or names a different CA than fabric-api-ca" >&2
      bad=1
    fi
  done
  if (( bad )); then
    echo "${site}: fabric-api credentials do not all chain to the current fabric-api-ca; see #1477" >&2
    return 1
  fi
  echo "${site}: every fabric-api credential chains to the current fabric-api-ca"
}

kc=""
trap 'rm -f "${kc}"' EXIT
for site in dfw iad sjc; do
  kc=$(site_kubeconfig "${site}")
  k() { kubectl --kubeconfig "${kc}" "$@"; }
  echo "Installing fabric-api on ${site}..."
  if ! k -n galactic-system get configmap fabric-api >/dev/null; then
    echo "${site}: no fabric-api ConfigMap in galactic-system; run deploy:fabric first" >&2
    exit 1
  fi
  # The CRD is the lab's copy until the kind ships in the network
  # repository; infra owns it in production.
  k apply --server-side -f "${CONFIG_DIR}/fabric-api/crd/"
  k wait --for condition=established --timeout=60s crd/fabricqueries.galactic.datumapis.com
  k apply -k "${CONFIG_DIR}/fabric-api/"
  ensure_ca "${site}"
  sed "s/CELL_NAME/${site}/g" "${RESOURCES_DIR}/fabric-api/pki/pki.yaml" | k apply -f -
  k -n galactic-system wait --for condition=Ready --timeout=120s certificate/fabric-api-operator
  k apply -k "${RESOURCES_DIR}/fabric-api/gateway/${site}/"
  k -n galactic-system rollout status deployment/fabric-api-gateway --timeout=180s
  check_chain "${site}"
  rm -f "${kc}"
done
echo "Done."
