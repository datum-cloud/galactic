#!/bin/bash
# verify-fabric-api-bootstrap.sh — prove that fabric-api diagnostics never
# gate routing bootstrap.
#
# With the cell's fabric-api Issuer broken, so no certificate can be issued,
# it clears the node's synced credentials and recreates both the node's
# fabric-api-certs pod and its fabric-router pod. The certs pod must wait in
# ContainerCreating (its csi-driver volume blocks until issuance), while the
# fabric-router pod starts, every container including FRR runs, and the
# node's underlay sessions come back Established, with the sidecar reporting
# no credentials and diagnostics unavailable. It then repairs the Issuer and
# checks that the certs pod gets its certificate and the sidecar picks it up
# and answers, without a restart.
#
# Finally it kills bgpd, which watchfrr restarts, and checks that the
# sidecar rides it out: the underlay reconverges and diagnostics become
# available again without restarting the sidecar.
#
# Disruptive: it restarts FRR on NODE (default dfw-worker). Run it on a lab
# you can afford to reconverge.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NODE=${NODE:-dfw-worker}
site=${NODE%%-*}
kc=$(site_kubeconfig "${site}")
k() { kubectl --kubeconfig "${kc}" "$@"; }
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

restore() {
  k -n galactic-system patch issuer fabric-api --type merge -p '{"spec":{"ca":{"secretName":"fabric-api-ca"}}}' >/dev/null
}
trap 'restore; rm -f "${kc}"' EXIT

# metric NAME prints the sidecar's value for an unlabelled metric.
metric() {
  docker exec "${NODE}" sh -c "curl -sf \"http://[\$(ip -6 -o addr show eth0 scope global | awk '{print \$4}' | cut -d/ -f1 | head -n1)]:9345/metrics\"" |
    awk -v m="$1" '$1 == m {print $2}'
}

echo "Breaking the ${site} fabric-api Issuer..."
k -n galactic-system patch issuer fabric-api --type merge -p '{"spec":{"ca":{"secretName":"fabric-api-ca-missing"}}}' >/dev/null

echo "Clearing ${NODE}'s synced credentials and recreating its fabric-api-certs pod..."
k -n galactic-system delete pod -l app.kubernetes.io/name=fabric-api-certs --field-selector "spec.nodeName=${NODE}" --wait=true >/dev/null
docker exec "${NODE}" sh -c 'rm -f /run/fabric-api/tls/*'
old=$(k -n galactic-system get pods -l app.kubernetes.io/name=fabric-router --field-selector "spec.nodeName=${NODE}" -o name)
echo "Recreating ${old} on ${NODE}..."
k -n galactic-system delete "${old}" --wait=true >/dev/null
new=""
for _ in $(seq 1 60); do
  new=$(k -n galactic-system get pods -l app.kubernetes.io/name=fabric-router --field-selector "spec.nodeName=${NODE}" -o name 2>/dev/null || true)
  [[ -n "${new}" && "${new}" != "${old}" ]] && break
  sleep 2
done
if k -n galactic-system wait --for=condition=Ready --timeout=240s "${new}" >/dev/null 2>&1; then
  ok "${new} is Ready with no fabric-api certificate"
else
  bad "${new} did not become Ready: $(k -n galactic-system get "${new}" -o jsonpath='{.status.containerStatuses[*].state}')"
fi
running=$(k -n galactic-system get "${new}" -o jsonpath='{range .status.containerStatuses[*]}{.name}={.started} {end}')
if [[ "${running}" == *"frr=true"* && "${running}" == *"fabric-api=true"* ]]; then
  ok "containers started: ${running}"
else
  bad "containers: ${running}"
fi

# The underlay converges with diagnostics down.
established=0
for _ in $(seq 1 60); do
  states=$(docker exec "${NODE}" curl -sf localhost:9342/metrics | awk '/^frr_bgp_peer_state/ {print $NF}' || true)
  if [[ -n "${states}" ]] && ! grep -qv '^1$' <<<"${states}"; then
    established=1
    break
  fi
  sleep 5
done
if [[ "${established}" -eq 1 ]]; then
  ok "${NODE}: every underlay session Established"
else
  bad "${NODE}: underlay did not converge: ${states:-no metrics}"
fi

for _ in $(seq 1 30); do
  [[ -n $(metric fabric_api_node_diagnostics_available) ]] && break
  sleep 5
done
creds=$(metric fabric_api_credentials_loaded)
avail=$(metric fabric_api_node_diagnostics_available)
if [[ "${creds}" == 0 && "${avail}" == 0 ]]; then
  ok "sidecar reports no credentials and diagnostics unavailable"
else
  bad "sidecar credentials_loaded=${creds:-?} diagnostics_available=${avail:-?}"
fi

certs=$(k -n galactic-system get pods -l app.kubernetes.io/name=fabric-api-certs --field-selector "spec.nodeName=${NODE}" \
  -o jsonpath='{.items[0].status.phase}')
if [[ "${certs}" != Running ]]; then
  ok "fabric-api-certs pod waits for its certificate (${certs}) without holding FRR"
else
  bad "fabric-api-certs pod is Running with no issuable certificate"
fi

echo "Repairing the Issuer..."
restore
recovered=0
for _ in $(seq 1 72); do
  if [[ $(metric fabric_api_credentials_loaded) == 1 && $(metric fabric_api_node_diagnostics_available) == 1 ]]; then
    recovered=1
    break
  fi
  sleep 5
done
restarts=$(k -n galactic-system get "${new}" -o jsonpath='{.status.containerStatuses[?(@.name=="fabric-api")].restartCount}')
if [[ "${recovered}" -eq 1 && "${restarts}" == 0 ]]; then
  ok "sidecar loaded its certificate and became available without a restart"
else
  bad "sidecar recovered=${recovered} restarts=${restarts}"
fi

echo "Killing bgpd on ${NODE}..."
k -n galactic-system exec "${new}" -c frr -- sh -c 'kill "$(cat /run/frr/bgpd.pid)"'
back=0
for _ in $(seq 1 60); do
  sleep 5
  states=$(docker exec "${NODE}" curl -sf localhost:9342/metrics | awk '/^frr_bgp_peer_state/ {print $NF}' || true)
  if [[ -n "${states}" ]] && ! grep -qv '^1$' <<<"${states}" && [[ $(metric fabric_api_node_diagnostics_available) == 1 ]]; then
    back=1
    break
  fi
done
restarts=$(k -n galactic-system get "${new}" -o jsonpath='{.status.containerStatuses[?(@.name=="fabric-api")].restartCount}')
if [[ "${back}" -eq 1 && "${restarts}" == 0 ]]; then
  ok "after a bgpd restart the underlay reconverged and diagnostics are available, sidecar not restarted"
else
  bad "after a bgpd restart: recovered=${back} sidecar restarts=${restarts}"
fi
exit "${fail}"
