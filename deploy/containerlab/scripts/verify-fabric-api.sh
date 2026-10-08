#!/bin/bash
# verify-fabric-api.sh — verify the fabric-api looking glass in every cell.
#
# For every fabric-router pod, directly against its sidecar with the lab's
# operator certificate:
#   - Info: diagnostics available, FRR 10.7, router ID and ASN read;
#   - BGPSummary for both families: every underlay session Established;
#   - an exact lookup of another site's loopback /32 and a longest-match
#     lookup of the same address, each with the router's selected BGP path
#     and zebra's installation evidence for it;
#   - a longest-match lookup of the site's gateway VIP, which the fabric
#     carries as a covering /64;
#   - an exact lookup of a prefix nobody announces: a successful empty answer;
#   - an AS-path and a community search, answered from the sidecar's
#     BMP-fed search index with its freshness, and equal to the prefixes
#     whose best path FRR's own search matches;
#   - operator ping and traceroute to another site's loopback, both
#     families: the cross-site reachability the operator exception allows.
# For every fabric-router pod spec: no automounted API token, a projected
# token in frr-init and config-agent only, none in the fabric-api sidecar.
# Through each cell's gateway debug service:
#   - the same ping is refused (DestinationNotAllowed): public policy never
#     carries the lab exceptions.
# Through the API, as NSO would on the hub:
#   - a FabricQuery for the cell's site and cluster completes Succeeded with
#     one observation per fabric node;
#   - a FabricQuery pinned to another cluster is left untouched.
#
# It deliberately claims nothing about tenant EVPN tables or kernel tables
# other than zebra's: those are not in FRR.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

WORK=$(mktemp -d)
cleanup() {
  [[ -n "${PF_PID:-}" ]] && kill "${PF_PID}" 2>/dev/null || true
  rm -rf "${WORK}"
}
trap cleanup EXIT

echo "Building the fabric-api client..."
(cd "${SCRIPT_DIR}/../../.." && CGO_ENABLED=0 go build -o "${WORK}/fabric-api" ./cmd/fabric-api)
FA="${WORK}/fabric-api"

fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }

# The cross-site probe and lookup targets: each site's first fabric node's
# loopbacks, read from its sidecar's own probe sources.
declare -A LOOP4 LOOP6
other_site() { case "$1" in dfw) echo iad ;; iad) echo sjc ;; sjc) echo dfw ;; esac; }

# setup_site SITE sets kc and creds for SITE, writing the operator
# certificate out of its Secret.
setup_site() {
  site=$1
  kc="${WORK}/${site}.kubeconfig"
  [[ -f "${kc}" ]] || kind get kubeconfig --name "${site}" > "${kc}"
  creds="${WORK}/${site}"
  if [[ ! -d "${creds}" ]]; then
    mkdir -p "${creds}"
    for f in tls.crt tls.key ca.crt; do
      k -n galactic-system get secret fabric-api-operator -o jsonpath="{.data.${f//./\\.}}" | base64 -d > "${creds}/${f}"
    done
  fi
}
k() { kubectl --kubeconfig "${kc}" "$@"; }

# node_targets prints "node certs-pod hostIP fabric-router-pod" for each
# fabric-router pod.
# A sidecar presents the identity of the fabric-api-certs pod on its node,
# which holds its certificate, so that is the identity to dial.
node_targets() {
  local certs
  certs=$(k -n galactic-system get pods -l app.kubernetes.io/name=fabric-api-certs \
    -o jsonpath='{range .items[*]}{.spec.nodeName} {.metadata.name}{"\n"}{end}')
  k -n galactic-system get pods -l app.kubernetes.io/name=fabric-router \
    -o jsonpath='{range .items[*]}{.spec.nodeName} {.status.hostIP} {.metadata.name}{"\n"}{end}' |
    while read -r node hostip frpod; do
      echo "${node} $(awk -v n="${node}" '$1 == n {print $2}' <<<"${certs}") ${hostip} ${frpod}"
    done
}
q() { "${FA}" --log-format text --log-level warn query --cell "${site}" --operator lab-verify \
  --tls-cert "${creds}/tls.crt" --tls-key "${creds}/tls.key" --tls-ca "${creds}/ca.crt" "$@"; }

# wait_info prints a node's Info, retrying for up to 90s: right after a
# rollout a sidecar can still present a replaced certs pod's certificate
# until certsync and its next credential reload catch up.
wait_info() {
  local out
  for _ in $(seq 1 30); do
    if out=$(q --node "[$3]:9344" --node-name "$1" --node-pod "$2" --info 2>&1); then
      echo "${out}"
      return 0
    fi
    sleep 3
  done
  echo "${out}"
  return 1
}

for site in dfw iad sjc; do
  setup_site "${site}"
  read -r node pod hostip _ < <(node_targets | sort | head -n1)
  info=$(wait_info "${node}" "${pod}" "${hostip}")
  LOOP4[${site}]=$(jq -r '.probeSources[] | select(contains(":") | not)' <<<"${info}" | head -n1)
  LOOP6[${site}]=$(jq -r '.probeSources[] | select(contains(":"))' <<<"${info}" | head -n1)
  echo "${site} targets: ${node} ${LOOP4[${site}]} ${LOOP6[${site}]}"
done

for site in dfw iad sjc; do
  setup_site "${site}"
  echo "=== ${site}"

  far=$(other_site "${site}")
  vip=$(grep -h -m1 -o 'vipAddress: [0-9a-f:]*' "${RESOURCES_DIR}/galactic-gateway/${site}"/*.yaml 2>/dev/null |
    awk '{print $2}' | head -n1 || true)

  pods=$(node_targets)
  nodes=0
  while read -r node pod hostip frpod; do
    [[ -z "${node}" ]] && continue
    nodes=$((nodes + 1))
    n() { q --node "[${hostip}]:9344" --node-name "${node}" --node-pod "${pod}" "$@"; }

    if ! info=$(wait_info "${node}" "${pod}" "${hostip}"); then
      bad "${node}: Info: ${info}"
      continue
    fi
    if [[ $(jq -r '.diagnosticsAvailable // false' <<<"${info}") != true ]] ||
      [[ $(jq -r '.frrVersion' <<<"${info}") != 10.7* ]] ||
      [[ -z $(jq -r '.routerId // empty' <<<"${info}") ]]; then
      bad "${node}: Info ${info}"
    else
      ok "${node}: FRR $(jq -r .frrVersion <<<"${info}"), router ID $(jq -r .routerId <<<"${info}"), AS $(jq -r .asn <<<"${info}")"
    fi

    for fam in IPv4 IPv6; do
      if ! sum=$(n BGPSummary --family "${fam}" 2>&1); then
        bad "${node}: ${fam} summary: ${sum}"
        continue
      fi
      total=$(jq -r '.observation.summary.totalPeers // 0' <<<"${sum}")
      est=$(jq -r '.observation.summary.establishedPeers // 0' <<<"${sum}")
      if [[ "${total}" -eq 0 || "${est}" -ne "${total}" ]]; then
        bad "${node}: ${fam} sessions ${est}/${total} Established"
      else
        ok "${node}: ${fam} sessions ${est}/${total} Established"
      fi
    done

    for target in "${LOOP4[${far}]}/32" "${LOOP6[${far}]}/128"; do
      if ! r=$(n RouteLookup "${target}" 2>&1); then
        bad "${node}: lookup ${target}: ${r}"
        continue
      fi
      kind=$(jq -r '.observation.routes.lookupKind' <<<"${r}")
      matched=$(jq -r '.observation.matched // 0' <<<"${r}")
      best=$(jq -r '[.observation.routes.prefixes[0].paths[]? | select(.best)] | length' <<<"${r}")
      installed=$(jq -r '[.observation.routes.prefixes[0].installation.routes[]? | select(.selected and .installed)] | .[0].protocol // "none"' <<<"${r}")
      if [[ "${kind}" != LOOKUP_KIND_EXACT || "${matched}" -ne 1 || "${best}" -ne 1 || "${installed}" == none ]]; then
        bad "${node}: exact ${target}: kind=${kind} matched=${matched} best=${best} installed=${installed}"
      else
        ok "${node}: exact ${target}: best path selected, zebra installed via ${installed}"
      fi
      addr=${target%/*}
      if ! r=$(n RouteLookup "${addr}" 2>&1); then
        bad "${node}: lookup ${addr}: ${r}"
        continue
      fi
      got=$(jq -r '.observation.routes.prefixes[0].prefix // "none"' <<<"${r}")
      kind=$(jq -r '.observation.routes.lookupKind' <<<"${r}")
      if [[ "${kind}" != LOOKUP_KIND_LONGEST_MATCH || "${got}" != "${target}" ]]; then
        bad "${node}: longest match ${addr}: kind=${kind} prefix=${got}"
      else
        ok "${node}: longest match ${addr} -> ${got}"
      fi
    done

    if [[ -n "${vip}" ]]; then
      if r=$(n RouteLookup "${vip}" 2>&1) && [[ $(jq -r '.observation.matched // 0' <<<"${r}") -eq 1 ]]; then
        ok "${node}: VIP ${vip} -> $(jq -r '.observation.routes.prefixes[0].prefix' <<<"${r}")"
      else
        bad "${node}: VIP ${vip} has no covering route: ${r}"
      fi
    fi

    if r=$(n RouteLookup 192.0.2.0/24 2>&1) && [[ $(jq -r '.observation.matchedIsExact' <<<"${r}") == true ]] &&
      [[ $(jq -r '.observation.matched // 0' <<<"${r}") -eq 0 ]]; then
      ok "${node}: absent prefix is an exact empty answer"
    else
      bad "${node}: absent prefix: ${r}"
    fi

    # type|target|FRR's own search command for the same query
    for spec in "ASPath|_65100_|regexp _65100_" "Community|no-export|community no-export"; do
      IFS='|' read -r typ target frrcmd <<<"${spec}"
      for fam in IPv4 IPv6; do
        afi=ipv4
        [[ "${fam}" == IPv6 ]] && afi=ipv6
        if ! r=$(n "${typ}" "${target}" --family "${fam}" 2>&1); then
          bad "${node}: ${fam} ${typ} ${target}: ${r}"
          continue
        fi
        got=$(jq -r '.observation.matched // 0' <<<"${r}")
        ver=$(jq -r '.observation.routes.index.version // empty' <<<"${r}")
        # The index holds each prefix's selected path, so compare with the
        # prefixes whose matching paths, as FRR lists them, include the
        # best path.
        want=$(k -n galactic-system exec "${frpod}" -c frr -- vtysh -c "show bgp ${afi} unicast ${frrcmd} json" 2>/dev/null |
          jq '[.routes[] | select(any(.[]; .bestpath == true))] | length')
        if [[ -n "${ver}" && "${got}" == "${want}" ]]; then
          ok "${node}: ${fam} ${typ} ${target} from the index (version ${ver}): ${got} prefixes, as FRR's best paths"
        else
          bad "${node}: ${fam} ${typ} ${target}: index ${got} (version ${ver:-none}), FRR ${want}"
        fi
      done
    done

    for dst in "${LOOP4[${far}]}" "${LOOP6[${far}]}"; do
      if r=$(n Ping "${dst}" 2>&1) && [[ $(jq -r '.observation.ping.received // 0' <<<"${r}") -gt 0 ]]; then
        ok "${node}: ping ${dst} from $(jq -r .observation.ping.source <<<"${r}"): $(jq -r .observation.ping.received <<<"${r}")/3"
      else
        bad "${node}: ping ${dst}: ${r}"
      fi
      if r=$(n Traceroute "${dst}" 2>&1) && [[ $(jq -r '.observation.traceroute.reached // false' <<<"${r}") == true ]]; then
        ok "${node}: traceroute ${dst}: $(jq -r '.observation.traceroute.hops | length' <<<"${r}") hops"
      else
        bad "${node}: traceroute ${dst}: ${r}"
      fi
    done
  done <<<"${pods}"

  # API credentials reach only the containers that call the API.
  while read -r pod; do
    spec=$(k -n galactic-system get "${pod}" -o json)
    auto=$(jq -r '.spec.automountServiceAccountToken' <<<"${spec}")
    tokens=$(jq -r '[(.spec.initContainers + .spec.containers)[] | select(any(.volumeMounts[]?;
      .mountPath == "/var/run/secrets/kubernetes.io/serviceaccount")) | .name] | sort | join(",")' <<<"${spec}")
    if [[ "${auto}" == false && "${tokens}" == "config-agent,frr-init" ]]; then
      ok "${pod#pod/}: API token only in ${tokens}"
    else
      bad "${pod#pod/}: automount=${auto}, token in ${tokens}"
    fi
  done < <(k -n galactic-system get pods -l app.kubernetes.io/name=fabric-router -o name)

  # Gateway debug service, through a port-forward to its Service.
  port=$((19346 + RANDOM % 1000))
  k -n galactic-system port-forward svc/fabric-api-gateway "${port}:9346" >/dev/null 2>&1 &
  PF_PID=$!
  for _ in $(seq 1 50); do
    (echo >/dev/tcp/127.0.0.1/${port}) 2>/dev/null && break
    sleep 0.2
  done
  if r=$(q --gateway "127.0.0.1:${port}" BGPSummary 2>&1) &&
    [[ $(jq -r '[.results[] | select(.observation)] | length' <<<"${r}") -eq "${nodes}" ]]; then
    ok "${site} gateway: debug BGPSummary answered by ${nodes} nodes"
  else
    bad "${site} gateway: debug BGPSummary: ${r}"
  fi
  if r=$(q --gateway "127.0.0.1:${port}" Ping "${LOOP4[${far}]}" 2>&1) &&
    [[ $(jq -r '[.results[] | select(.errorCode == "DestinationNotAllowed")] | length' <<<"${r}") -eq "${nodes}" ]]; then
    ok "${site} gateway: public policy refuses the loopback probe on every node"
  else
    bad "${site} gateway: public probe of a loopback: ${r}"
  fi
  kill "${PF_PID}" 2>/dev/null || true
  PF_PID=

  # FabricQuery end to end, written as NSO would write it on the hub.
  k create namespace fabric-api-verify --dry-run=client -o yaml | k apply -f - >/dev/null
  name="verify-$(date +%s)"
  expires=$(date -u -d '+90 seconds' +%Y-%m-%dT%H:%M:%SZ)
  for spec in "${name}:${site}" "${name}-elsewhere:not-${site}"; do
    obj=${spec%%:*} cluster=${spec##*:}
    k apply -f - >/dev/null <<EOF
apiVersion: network.datumapis.com/v1alpha1
kind: FabricQuery
metadata:
  name: ${obj}
  namespace: fabric-api-verify
spec:
  requestID: ${obj}
  source: {uid: verify, cluster: lab, namespace: default, name: ${obj}}
  query: {type: BGPSummary, addressFamily: IPv6}
  site: ${site}
  clusterName: ${cluster}
  expiresAt: "${expires}"
EOF
  done
  if k -n fabric-api-verify wait --for=condition=Complete --timeout=90s "fabricquery/${name}" >/dev/null 2>&1; then
    fq=$(k -n fabric-api-verify get fabricquery "${name}" -o json)
    reason=$(jq -r '.status.conditions[] | select(.type=="Complete") | .reason' <<<"${fq}")
    obs=$(jq -r '[.status.observations[] | select(.summary)] | length' <<<"${fq}")
    if [[ "${reason}" == Succeeded && "${obs}" -eq "${nodes}" ]]; then
      ok "${site}: FabricQuery ${name} Succeeded with ${obs}/${nodes} observations"
    else
      bad "${site}: FabricQuery ${name} ${reason}, ${obs}/${nodes} observations: $(jq -c .status.coverage <<<"${fq}")"
    fi
  else
    bad "${site}: FabricQuery ${name} did not complete"
  fi
  if [[ -z $(k -n fabric-api-verify get fabricquery "${name}-elsewhere" -o jsonpath='{.status.conditions}') ]]; then
    ok "${site}: FabricQuery for another cluster left untouched"
  else
    bad "${site}: FabricQuery for another cluster was executed"
  fi
  k -n fabric-api-verify delete fabricquery "${name}" "${name}-elsewhere" --wait=false >/dev/null
done

exit "${fail}"
