#!/bin/bash
# verify-egress.sh — confirm the egress (masquerade) datapath end-to-end
# (datum-cloud/enhancements#865): ping tr1's own loopback (fc00:0:1::1) from
# ns10's iad pod, standing in for "an arbitrary internet destination" since
# this lab has no real internet uplink. tr1's loopback is a real address,
# already announced into the transit/fabric eBGP mesh (node_files/tr1/
# frr.conf's own "network fc00:0:1::1/128"), and — crucially — outside any
# SRv6 uSID locator or VPC ULA block this topology otherwise uses, so a
# successful ping only ever routes correctly if the whole chain actually
# worked: ns10's tenant VRF has a live ::/0 default route (internal/
# egressroute's reconciler, only installed once ns10's own
# NetworkEgressPolicy -- resources/galactic-gateway/iad/
# networkegresspolicy-ns10.yaml -- is Accepted and assigned a gateway node),
# that route encapsulates toward the assigned gateway's egress_sid,
# edgenat.c's egress-forward branch SNATs to that gateway's egress_address,
# and the reply gets DNAT'd back and delivered to the pod.
#
# ns10 (not ns60, the ingress canary) is used here specifically because its
# netshoot image has ping; ns60's nginx image doesn't.
#
# Only exercises iad: NetworkGateway/NetworkEgressPolicy only exist in
# iad's own Kind cluster (each site is a fully separate cluster in this
# lab, connected only by the data-plane SRv6/BGP mesh, not a shared
# control plane) -- so ns10's dfw/sjc attachments have no gateway-node pool
# to be assigned into at all, and only its iad attachment can egress here.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"

NS=ns10
TARGET=fc00:0:1::1 # tr1's own loopback -- the lab's stand-in "internet"

node=$(control_plane iad)
pod=$(pod_name "${node}" "${NS}")
echo "ns10/iad: pod=${pod}"

echo "--- ns10/iad -> internet (${TARGET}) ---"
ping_pod "${node}" "${NS}" "${pod}" -6 "${TARGET}"

echo "egress: ping OK from ns10/iad to ${TARGET}"
