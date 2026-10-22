#!/bin/bash
# verify-traffic-policy.sh — prove the lab's interface traffic policy is
# installed, forwards what each tenant's bindings grant and drops what they do
# not, on every forwarding path, and counts each decision where it was made.
#
#   1. Every TrafficPolicyBinding reports both directions Applied on its node.
#   2. Private: an ns20 TCP connection from dfw to sjc reaches a listener on
#      8080, and never reaches the same listener on 9, which sjc's ingress
#      policy denies (rule deny-discard) and counts.
#   3. PublicNAT: ns10 on dfw reaches remote-host through a NAT shard; ns60's
#      backend-a on dfw, whose egress grants only PublicService, does not, and
#      dfw counts the no_match denial on its egress.
#   4. PublicService: with a temporary deny-udp rule ahead of ns60's
#      allow-service on dfw, the dfw VIP's UDP check fails and the rule counts
#      it; with the fixture restored, it passes again.
#   5. Built-in default: unbinding ns30's private-b ingress makes it deny
#      everything as default-deny-all, counted under the built-in identity;
#      rebinding restores it.
#
# Steps 4 and 5 change live policy; an exit trap restores the fixtures.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

METRICS_PORT=9179
REMOTE_HOST="2001:db8:1:40::2"
BUILTIN_UID="builtin:default-deny-all:v1"
DFW=$(control_plane dfw)
SJC=$(control_plane sjc)
rc=0

fail() {
  echo "FAIL $*" >&2
  rc=1
}

# metric_sum WORKER NAME LABEL=VALUE... — the sum of every NAME sample on
# WORKER's galactic-router whose labels include each LABEL="VALUE".
metric_sum() {
  local worker="$1" name="$2"
  shift 2
  local lines
  lines=$(docker exec "${worker}" curl -fsS "http://localhost:${METRICS_PORT}/metrics" | grep "^${name}{" || true)
  for kv in "$@"; do
    lines=$(grep -F "${kv%%=*}=\"${kv#*=}\"" <<<"${lines}" || true)
  done
  awk '{s += $NF} END {printf "%d\n", s}' <<<"${lines}"
}

# wait_applied SITE NS BINDING — until BINDING's status shows both
# directions Applied on some node, at the binding's current generation.
wait_applied() {
  local cp
  cp=$(control_plane "$1")
  for _ in $(seq 1 60); do
    if docker exec "${cp}" kubectl get trafficpolicybinding -n "$2" "$3" -o json | jq -e '
        .metadata.generation as $g
        | [.status.nodes[]?
           | select(.ingress.state == "Applied" and .egress.state == "Applied"
                    and .ingress.observedGeneration == $g)] | length > 0' >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# wait_policy_applied SITE NS POLICY — until every binding naming POLICY
# reports its current generation installed for that direction.
wait_policy_applied() {
  local cp gen
  cp=$(control_plane "$1")
  gen=$(docker exec "${cp}" kubectl get trafficpolicy -n "$2" "$3" -o jsonpath='{.metadata.generation}')
  for _ in $(seq 1 60); do
    if docker exec "${cp}" kubectl get trafficpolicybindings -n "$2" -o json | jq -e \
      --arg p "$3" --argjson g "${gen}" '
        [.items[].status.nodes[]? | (.ingress, .egress)
         | select(.policy.name == $p)]
        | length > 0 and all(.state == "Applied" and .policy.generation == $g)' >/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

# tcp_reaches CP NS POD ADDRESS PORT — whether POD's TCP connection to
# [ADDRESS]:PORT is accepted within 5 seconds.
tcp_reaches() {
  docker exec "$1" kubectl exec -n "$2" "$3" -- \
    timeout 6 sh -c "echo probe | socat -T 5 -u - TCP6:[$4]:$5,connect-timeout=5" >/dev/null 2>&1
}

# listen CP NS POD PORT — a one-shot TCP listener on PORT in POD, for 20s.
listen() {
  docker exec "$1" kubectl exec -n "$2" "$3" -- \
    timeout 20 socat -u "TCP6-LISTEN:$4,reuseaddr" OPEN:/dev/null >/dev/null 2>&1 &
  sleep 1
}

out=$(mktemp)
# restore re-applies the two fixtures steps 4 and 5 change and waits for the
# router to install them, so a check run after this one sees the lab as
# deployed.
restore() {
  set +e
  apply_k "${DFW}" /galactic/resources/tenants/ns60/policy/ >/dev/null
  apply_k "${DFW}" /galactic/resources/tenants/ns30/policy/ >/dev/null
  wait_policy_applied dfw ns60 lab-ingress || echo "warning: ns60's lab-ingress not reinstalled on dfw" >&2
  wait_applied dfw ns30 private-b || echo "warning: ns30/private-b not rebound on dfw" >&2
  rm -f "${out}"
}
trap restore EXIT

echo "--- 1. every binding is installed on its node"
for site in dfw sjc iad; do
  cp=$(control_plane "${site}")
  while read -r ns name; do
    [ -z "${ns}" ] && continue
    if wait_applied "${site}" "${ns}" "${name}"; then
      echo "ok   ${site}: ${ns}/${name} applied in both directions"
    else
      fail "${site}: ${ns}/${name} is not applied in both directions:"
      docker exec "${cp}" kubectl get trafficpolicybinding -n "${ns}" "${name}" -o jsonpath='{.status}' >&2
      echo >&2
    fi
  done < <(docker exec "${cp}" kubectl get trafficpolicybindings -A \
    -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name}{"\n"}{end}')
done

echo "--- 2. Private: a granted port connects, a denied one does not"
src=$(pod_name "${DFW}" ns20)
dst=$(pod_name "${SJC}" ns20)
dst_ip=$(pod_ip6 "${SJC}" ns20 "${dst}")
listen "${SJC}" ns20 "${dst}" 8080
if tcp_reaches "${DFW}" ns20 "${src}" "${dst_ip}" 8080; then
  echo "ok   ns20 dfw -> sjc TCP 8080 connects"
else
  fail "ns20 dfw -> sjc TCP 8080 did not connect"
fi
before=$(metric_sum sjc-worker galactic_cni_traffic_policy_rule_hits_total \
  namespace=ns20 direction=ingress rule=deny-discard)
listen "${SJC}" ns20 "${dst}" 9
if tcp_reaches "${DFW}" ns20 "${src}" "${dst_ip}" 9; then
  fail "ns20 dfw -> sjc TCP 9 connected through a deny rule"
else
  echo "ok   ns20 dfw -> sjc TCP 9 is dropped"
fi
after=$(metric_sum sjc-worker galactic_cni_traffic_policy_rule_hits_total \
  namespace=ns20 direction=ingress rule=deny-discard)
if [ "${after}" -gt "${before}" ]; then
  echo "ok   sjc counted the denial on ns20's ingress: deny-discard ${before} -> ${after}"
else
  fail "sjc's deny-discard counter for ns20 did not move (${before} -> ${after})"
fi

echo "--- 3. PublicNAT: granted egress reaches remote-host, ungranted does not"
ns10=$(pod_name "${DFW}" ns10)
if tcp_reaches "${DFW}" ns10 "${ns10}" "${REMOTE_HOST}" 80; then
  echo "ok   ns10 dfw -> remote-host TCP 80 connects through a NAT shard"
else
  fail "ns10 dfw -> remote-host TCP 80 did not connect"
fi
backend=$(pod_name "${DFW}" ns60 app=backend,instance=a)
before=$(metric_sum dfw-worker galactic_cni_traffic_policy_fallback_packets_total \
  namespace=ns60 attachment=backend-a direction=egress reason=no_match)
if tcp_reaches "${DFW}" ns60 "${backend}" "${REMOTE_HOST}" 80; then
  fail "ns60 backend-a -> remote-host connected though its egress grants only PublicService"
else
  echo "ok   ns60 backend-a -> remote-host is dropped"
fi
after=$(metric_sum dfw-worker galactic_cni_traffic_policy_fallback_packets_total \
  namespace=ns60 attachment=backend-a direction=egress reason=no_match)
if [ "${after}" -gt "${before}" ]; then
  echo "ok   dfw counted backend-a's egress as no_match: ${before} -> ${after}"
else
  fail "dfw's no_match counter for backend-a's egress did not move (${before} -> ${after})"
fi

echo "--- 4. PublicService: a deny rule stops the VIP's UDP, and lifting it restores it"
docker exec -i "${DFW}" kubectl apply -f - >/dev/null <<'EOF'
apiVersion: galactic.datumapis.com/v1alpha1
kind: TrafficPolicy
metadata:
  name: lab-ingress
  namespace: ns60
spec:
  rules:
    - name: deny-udp
      action: Deny
      match:
        path: PublicService
        protocol: UDP
    - name: allow-service
      action: Allow
      match:
        path: PublicService
    - name: allow-health-probe
      action: Allow
      match:
        path: Private
        protocol: TCP
        sourceCIDRs: ["fe80::/10"]
        destinationPorts: [{start: 80, end: 80}]
EOF
if ! wait_policy_applied dfw ns60 lab-ingress; then
  fail "dfw did not install ns60's edited lab-ingress"
fi
before=$(metric_sum dfw-worker galactic_cni_traffic_policy_rule_hits_total \
  namespace=ns60 direction=ingress rule=deny-udp)
if "${SCRIPT_DIR}/verify-gateway-ingress.sh" --node dfw-worker2 >"${out}" 2>&1; then
  fail "dfw's VIP passed its TCP and UDP check with UDP denied to its backends"
elif grep -q 'udp from port .*: no reply' "${out}" && ! grep -q 'tcp from port' "${out}"; then
  echo "ok   dfw's VIP still serves TCP, and its UDP draws no reply while denied"
else
  fail "dfw's VIP check failed, but not only on UDP:"
  sed 's/^/    /' "${out}" >&2
fi
after=$(metric_sum dfw-worker galactic_cni_traffic_policy_rule_hits_total \
  namespace=ns60 direction=ingress rule=deny-udp)
if [ "${after}" -gt "${before}" ]; then
  echo "ok   dfw counted the VIP's UDP under deny-udp: ${before} -> ${after}"
else
  fail "dfw's deny-udp counter for ns60 did not move (${before} -> ${after})"
fi
apply_k "${DFW}" /galactic/resources/tenants/ns60/policy/ >/dev/null
if ! wait_policy_applied dfw ns60 lab-ingress; then
  fail "dfw did not reinstall ns60's lab-ingress"
fi
if "${SCRIPT_DIR}/verify-gateway-ingress.sh" --node dfw-worker2 >"${out}" 2>&1; then
  echo "ok   dfw's VIP serves TCP and UDP again"
else
  fail "dfw's VIP still fails with the fixture restored:"
  sed 's/^/    /' "${out}" >&2
fi

echo "--- 5. Built-in default: an unbound direction denies, rebinding restores it"
a=$(pod_name "${DFW}" ns30)
b=$(pod_name "${DFW}" ns30 app=private-b)
b_ip=$(pod_ip6 "${DFW}" ns30 "${b}")
docker exec "${DFW}" kubectl patch trafficpolicybinding -n ns30 private-b --type=json \
  -p '[{"op":"remove","path":"/spec/ingressPolicyRef"}]' >/dev/null
for _ in $(seq 1 60); do
  got=$(docker exec "${DFW}" kubectl get trafficpolicybinding -n ns30 private-b \
    -o jsonpath='{.status.nodes[0].ingress.policy.uid}')
  [ "${got}" = "${BUILTIN_UID}" ] && break
  sleep 2
done
if [ "${got}" != "${BUILTIN_UID}" ]; then
  fail "ns30/private-b's ingress did not fall back to the built-in default (uid ${got:-none})"
fi
before=$(metric_sum dfw-worker galactic_cni_traffic_policy_rule_hits_total \
  namespace=ns30 attachment=private-b direction=ingress policy_uid="${BUILTIN_UID}")
if docker exec "${DFW}" kubectl exec -n ns30 "${a}" -- ping -6 -c 3 -W 2 "${b_ip}" >/dev/null 2>&1; then
  fail "ns30 private -> private-b answered with private-b on the built-in default"
else
  echo "ok   ns30 private -> private-b is dropped on the built-in default"
fi
after=$(metric_sum dfw-worker galactic_cni_traffic_policy_rule_hits_total \
  namespace=ns30 attachment=private-b direction=ingress policy_uid="${BUILTIN_UID}")
if [ "${after}" -gt "${before}" ]; then
  echo "ok   dfw counted the default deny-all as a rule hit: ${before} -> ${after}"
else
  fail "dfw's default deny-all counter for ns30/private-b did not move (${before} -> ${after})"
fi
apply_k "${DFW}" /galactic/resources/tenants/ns30/policy/ >/dev/null
if wait_applied dfw ns30 private-b &&
  docker exec "${DFW}" kubectl exec -n ns30 "${a}" -- ping -6 -c 3 -W 2 "${b_ip}" >/dev/null 2>&1; then
  echo "ok   ns30 private -> private-b answers again once rebound"
else
  fail "ns30 private -> private-b does not answer after rebinding"
fi

if [ "${rc}" -ne 0 ]; then
  echo "traffic policy: FAILED" >&2
  exit 1
fi
echo "traffic policy: every path forwards what it grants and drops, and counts, what it does not"
