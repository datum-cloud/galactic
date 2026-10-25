#!/bin/bash
# service-api-bundle.sh — Build the Looking Glass service API release asset.
#
# Writes OUT_DIR/fabric-service-api-VERSION.tar.gz and OUT_DIR/SHA256SUMS.
# The archive holds:
#   proto/                  fabric/service/v1/service.proto and its imports
#                           (the google/protobuf well-known types ship with
#                           every protobuf toolchain and are not copied)
#   fabric-service-v1.pb    a descriptor set of the service with every import
#   README.md               the Go module version and how to generate a client
#
# Usage: service-api-bundle.sh VERSION OUT_DIR
# Run from the repository root; requires buf.
set -euo pipefail

version=${1:?usage: service-api-bundle.sh VERSION OUT_DIR}
out=${2:?usage: service-api-bundle.sh VERSION OUT_DIR}
name="fabric-service-api-${version}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stage="$work/$name"
mkdir -p "$stage/proto" "$out"

(cd api && buf export --path fabric/service/v1 -o "$stage/proto")
(cd api && buf build --path fabric/service/v1 --as-file-descriptor-set -o "$stage/fabric-service-v1.pb")

cat >"$stage/README.md" <<README
# Looking Glass service API ${version}

The gRPC contract a cell's fabric-api gateway serves to an authorized Looking
Glass service: \`fabric.service.v1.LookingGlassService\`. Its behavior is
specified in docs/fabric-api/service-contract.md of galactic ${version}.

## Go

Pin \`go.datum.net/galactic@${version}\` and import only:

- \`go.datum.net/galactic/api/fabric/service/v1\`
- \`go.datum.net/galactic/api/fabric/v1\`

## Other languages

Generate a client from \`proto/\`, whose imports beyond it are the standard
\`google/protobuf\` well-known types, or from the descriptor set
\`fabric-service-v1.pb\`, which includes every import. For example:

    buf generate "fabric-service-v1.pb#format=binpb" --template buf.gen.yaml
README

tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner --mtime='1970-01-01' \
  -czf "$out/$name.tar.gz" "$name"
(cd "$out" && sha256sum "$name.tar.gz" >SHA256SUMS)
echo "wrote $out/$name.tar.gz"
