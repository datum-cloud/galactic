#!/bin/bash
# baseline-twice.sh: record the pinned versions, run baseline-observe.sh twice
# in a row, and require both runs to pass with identical results.json files
# that also match the committed baseline/reference-results.json.
#
# Usage: baseline-twice.sh [OUTDIR]
#   OUTDIR defaults to bin/baseline/<UTC timestamp> at the repository root.
#
# Set BASELINE_WRITE_REFERENCE=1 to replace the reference with run-1's
# results once both runs agree, after a deliberate change to the fixture or
# its expectations.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
LAB_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPO=$(cd "${LAB_DIR}/../.." && pwd)
REFERENCE="${LAB_DIR}/baseline/reference-results.json"
OUT=${1:-${REPO}/bin/baseline/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "${OUT}"

rc=0
"${SCRIPT_DIR}/baseline-versions.sh" "${OUT}/versions.yaml" || rc=1
for run in 1 2; do
  echo "##### run ${run} #####"
  "${SCRIPT_DIR}/baseline-observe.sh" "${OUT}/run-${run}" 2>&1 | tee "${OUT}/run-${run}.log" ||
    rc=1
done

if diff -u "${OUT}/run-1/results.json" "${OUT}/run-2/results.json" >"${OUT}/runs.diff"; then
  echo "runs 1 and 2: identical results ($(sha256sum <"${OUT}/run-1/results.json" | cut -c1-16))"
else
  echo "FAIL: runs 1 and 2 differ:" >&2
  cat "${OUT}/runs.diff" >&2
  rc=1
fi

if [ "${rc}" -eq 0 ] && [ "${BASELINE_WRITE_REFERENCE:-0}" = 1 ]; then
  cp "${OUT}/run-1/results.json" "${REFERENCE}"
  echo "wrote ${REFERENCE}"
elif [ ! -f "${REFERENCE}" ]; then
  echo "FAIL: no ${REFERENCE}; rerun with BASELINE_WRITE_REFERENCE=1 to create it" >&2
  rc=1
elif diff -u "${REFERENCE}" "${OUT}/run-1/results.json" >"${OUT}/reference.diff"; then
  echo "run 1 matches baseline/reference-results.json"
else
  echo "FAIL: run 1 differs from baseline/reference-results.json:" >&2
  cat "${OUT}/reference.diff" >&2
  rc=1
fi

echo "evidence in ${OUT}"
exit "${rc}"
