#!/bin/bash
# verify-ns80.sh: check the dedicated-placement fixture (resources/tenants/ns80)
# is in place and forwarding. Each VPC's guests sit on dfw's and sjc's compute
# workers, both VPCs' guests hold the same address at each site, and each VPC
# reaches its own guest across sites in both directions. dfw has a second
# guest per VPC on its second compute worker, dfw-worker4, at a second shared
# address, and each VPC reaches between its two dfw guests in both directions. The full
# observations, with captures and the isolation control, are
# task baseline:observe.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns80
DFW=$(control_plane dfw)
SJC=$(control_plane sjc)
declare -A WANT=([dfw]=fd20:80:ff01::1:0:0 [sjc]=fd20:80:ff02::1:0:0)

declare -A POD
for site in dfw sjc; do
  cp=$(control_plane "${site}")
  for app in vpc-a vpc-b; do
    pod=$(pod_name "${cp}" "${NS}" "app=${app}")
    if [ -z "${pod}" ]; then
      echo "ns80 ${app} pod not found in ${site}" >&2
      exit 1
    fi
    node=$(pod_scheduling_node "${cp}" "${NS}" "${pod}")
    if [ "${node}" != "${site}-worker" ]; then
      echo "ns80 ${app} in ${site} runs on ${node}, want ${site}-worker" >&2
      exit 1
    fi
    addr=$(pod_ip6 "${cp}" "${NS}" "${pod}")
    if [ "${addr}" != "${WANT[${site}]}" ]; then
      echo "ns80 ${app} in ${site} has address '${addr}', want ${WANT[${site}]}" >&2
      exit 1
    fi
    POD[${site}-${app}]=${pod}
    echo "${site} ${app}: ${pod} on ${node}, ${addr}"
  done
done

# dfw's second guests, one per VPC on dfw-worker4.
WANT2=fd20:80:ff01::2:0:0
for app in vpc-a vpc-b; do
  pod=$(pod_name "${DFW}" "${NS}" "app=${app}2")
  if [ -z "${pod}" ]; then
    echo "ns80 ${app}2 pod not found in dfw" >&2
    exit 1
  fi
  node=$(pod_scheduling_node "${DFW}" "${NS}" "${pod}")
  if [ "${node}" != "dfw-worker4" ]; then
    echo "ns80 ${app}2 in dfw runs on ${node}, want dfw-worker4" >&2
    exit 1
  fi
  addr=$(pod_ip6 "${DFW}" "${NS}" "${pod}")
  if [ "${addr}" != "${WANT2}" ]; then
    echo "ns80 ${app}2 in dfw has address '${addr}', want ${WANT2}" >&2
    exit 1
  fi
  POD[dfw-${app}2]=${pod}
  echo "dfw ${app}2: ${pod} on ${node}, ${addr}"
done

for app in vpc-a vpc-b; do
  echo "--- ${app}: dfw -> sjc ---"
  ping_pod "${DFW}" "${NS}" "${POD[dfw-${app}]}" -6 "${WANT[sjc]}"
  echo "--- ${app}: sjc -> dfw ---"
  ping_pod "${SJC}" "${NS}" "${POD[sjc-${app}]}" -6 "${WANT[dfw]}"
done

for app in vpc-a vpc-b; do
  echo "--- ${app}: dfw-worker -> dfw-worker4 ---"
  ping_pod "${DFW}" "${NS}" "${POD[dfw-${app}]}" -6 "${WANT2}"
  echo "--- ${app}: dfw-worker4 -> dfw-worker ---"
  ping_pod "${DFW}" "${NS}" "${POD[dfw-${app}2]}" -6 "${WANT[dfw]}"
  echo "--- ${app}: sjc -> dfw-worker4 ---"
  ping_pod "${SJC}" "${NS}" "${POD[sjc-${app}]}" -6 "${WANT2}"
done

echo "ns80: both VPCs reach across sites and between dfw's two compute workers in both directions"
