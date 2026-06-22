#!/bin/bash
# Patch CRDs to fix JSON Schema maximum boundary for uint32 ASN fields.
#
# Kubebuilder v0.18.0 generates maximum: 4294967295 for uint32 fields,
# but JSON Schema's maximum keyword is limited to int32 (2147483647).
# This makes the CRD schema invalid — the API server treats every
# ASN value as empty/invalid.
#
# Fix: cap maximum at 2147483647 (int32 max). This still covers all
# 2-byte ASNs (1–65535) and most 4-byte ASNs up to 2^31-1.
set -euo pipefail

NODE="${1:?Usage: $0 <control-plane-node>}"

echo "Patching CRD maximum boundaries on ${NODE}..."

docker exec "${NODE}" kubectl patch crd bgppeers.bgp.miloapis.com --type=json \
  -p '[{"op": "replace", "path": "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/peerASN/maximum", "value": 2147483647}]'

docker exec "${NODE}" kubectl patch crd bgprouters.bgp.miloapis.com --type=json \
  -p '[{"op": "replace", "path": "/spec/versions/0/schema/openAPIV3Schema/properties/spec/properties/localASN/maximum", "value": 2147483647}]'

echo "Done."
