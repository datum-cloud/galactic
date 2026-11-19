#!/bin/bash
# handoff-twice.sh: deploy the Local handoff fixture, run handoff-observe.sh
# twice and handoff-measure.sh once, remove the fixture, and require both
# observation runs to pass with identical results.json files that also match
# the committed handoffs/expected-results.json.
#
# Usage: handoff-twice.sh [OUTDIR]
#   OUTDIR defaults to bin/handoffs/<UTC timestamp> at the repository root.
#
# Set HANDOFF_WRITE_EXPECTED=1 to replace the expected results with run 1's
# once both runs pass and agree. Set HANDOFF_MEASURE=0 to skip the
# measurements.
#
# When a precondition does not hold it changes nothing, says which, and
# exits 0: ns80 must be deployed, and no earlier fixture or rig may remain.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/lib.sh"
LAB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPO=$(cd "${LAB_DIR}/../.." && pwd)
EXPECTED="${LAB_DIR}/handoffs/expected-results.json"
OUT=${1:-${REPO}/bin/handoffs/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "${OUT}"
OUT=$(cd "${OUT}" && pwd)
CP=$(control_plane dfw)

precondition() {
  echo "PRECONDITION: $*" | tee "${OUT}/precondition"
  exit 0
}

if ! docker exec "${CP}" kubectl get namespace ns80 >/dev/null 2>&1; then
  precondition "ns80 is not deployed (task deploy:ns80)"
fi
if docker exec "${CP}" kubectl get namespace ns80-tap >/dev/null 2>&1; then
  precondition "ns80-tap is already deployed; an earlier run did not remove it (task delete:ns80-tap)"
fi
if docker inspect handoff-rig >/dev/null 2>&1; then
  precondition "a rig container handoff-rig already exists; an earlier run did not clean up"
fi

rc=0
fixture_down() {
  "${SCRIPT_DIR}/handoff-fixture.sh" down || rc=1
}
trap 'status=$?; fixture_down; [ "${status}" -ne 0 ] && rc=${status}; exit "${rc}"' EXIT
"${SCRIPT_DIR}/handoff-fixture.sh" up 2>&1 | tee "${OUT}/fixture-up.log"

for run in 1 2; do
  echo "##### run ${run} #####"
  "${SCRIPT_DIR}/handoff-observe.sh" "${OUT}/run-${run}" 2>&1 | tee "${OUT}/run-${run}.log" || rc=1
  if [ -f "${OUT}/run-${run}/precondition" ]; then
    cp "${OUT}/run-${run}/precondition" "${OUT}/precondition"
    echo "stopped at a precondition: $(cat "${OUT}/precondition")"
    exit 0
  fi
done
if [ "${HANDOFF_MEASURE:-1}" = 1 ]; then
  echo "##### measurements #####"
  "${SCRIPT_DIR}/handoff-measure.sh" "${OUT}/measure" 2>&1 | tee "${OUT}/measure.log" || rc=1
fi

if diff -u "${OUT}/run-1/results.json" "${OUT}/run-2/results.json" >"${OUT}/runs.diff"; then
  echo "runs 1 and 2: identical results ($(sha256sum <"${OUT}/run-1/results.json" | cut -c1-16))"
else
  echo "FAIL: runs 1 and 2 differ:" >&2
  cat "${OUT}/runs.diff" >&2
  rc=1
fi
if [ "${rc}" -eq 0 ] && [ "${HANDOFF_WRITE_EXPECTED:-0}" = 1 ]; then
  mkdir -p "$(dirname "${EXPECTED}")"
  cp "${OUT}/run-1/results.json" "${EXPECTED}"
  echo "wrote ${EXPECTED}"
elif [ ! -f "${EXPECTED}" ]; then
  echo "FAIL: no ${EXPECTED}; rerun with HANDOFF_WRITE_EXPECTED=1 to create it" >&2
  rc=1
elif diff -u "${EXPECTED}" "${OUT}/run-1/results.json" >"${OUT}/expected.diff"; then
  echo "run 1 matches handoffs/expected-results.json"
else
  echo "FAIL: run 1 differs from handoffs/expected-results.json:" >&2
  cat "${OUT}/expected.diff" >&2
  rc=1
fi
echo "evidence in ${OUT}"
