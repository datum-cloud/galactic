# Guest DNS continuity validation, October 30, 2026

This is dated staging evidence, not production qualification. See the
[current private-service behavior](../../private-services/README.md#attachment-replacement-continuity).

## Cause and reproduction

At 03:37:47 UTC, deletion of an unrelated instance's attachment coincided with
three-second UDP DNS timeouts and one-second TCP retries in the existing DNS
performance guest. The route programmer closed the node-wide policy gate and
rebuilt every service route when any attachment changed.

A disposable instance reproduced the issue without replacing DNS backends:
two pod replacements from 04:49:11 through 04:49:31 UTC caused eight UDP timeouts
and four additional TCP responses taking at least one second. Maximum query
duration was 3001.044 ms. The disposable instance used its own network allocation.

## Candidate and staging result

Code revision: `d134d7f578673f880a7fdb1f92987d3014ae745e`.
The fix repairs changed references without withdrawing unrelated routes.

The compute router on `eris-giune` in `us-central-1-staging-lab` became ready
at 04:51:23.676 UTC with image
`ghcr.io/datum-cloud/galactic-router@sha256:2e002425adf91a56a04383c506705e27e64b926f1d7826ab6efc3ba104bf1b7e`.
This canary replaces only the router binary in the staging base image
`v0.0.0-main-20261030-042240`; inherited image labels identify that base,
while the binary version is `staging-dns-continuity-20261029`.

Five replacements of the disposable instance's pod completed between
04:51:45 and 04:52:25 UTC. The instance and its owned network allocation were
then deleted. Continuous queries from the existing guest covered UDP and TCP,
both resolver addresses (`fd53::53` and `fd53::54`), and private and public names.
The probe issued each stream every 100 ms with a three-second timeout.

From 2026-10-30T04:51:24.07494577Z through 2026-10-30T04:56:48.712465629Z:

- 25,688 DNS queries, zero failures and zero responses at least one second.
- Maximum 15.502 ms; p99 1.044 ms.
- All five pod replacements and final instance cleanup completed successfully.

## Tests and remaining limits

The full Linux service-route suite passed. A real-kernel continuity test issued
35,083 UDP/TCP service requests during 40 interface replacements with zero
failures and zero responses at least one second. The deterministic regression
test failed against the original code and passed with the repair.
Linux-targeted package lint passed. Full local `task ci` stopped on existing
Linux-only capability APIs unavailable on macOS; Linux CI is reported on the PR.

Router startup remains a separate interruption: deploying this canary produced
24 timed-out queries during the 04:51:00–04:51:24 UTC startup window, before the
successful measurement above. Startup intentionally closes the policy gate
until its authoritative snapshot is validated. Authorization expiry and failed
repairs also retain full-generation recovery. This result establishes
attachment-churn continuity, not zero-loss router rollouts.

## Deployment state and evidence

Only the central staging compute router runs this canary; edge routers retain
their prior images. The `galactic-router` DaemonSet has reconciliation disabled
and uses `OnDelete` to hold the scoped canary. Normal release promotion must
replace the temporary image and restore the prior strategy and reconciliation.
Do not restore `RollingUpdate` against the canary image unintentionally.

Local raw probes, churn events, test logs, and exact pre-canary DaemonSet/pod
snapshots are in `/tmp/dns-guest-continuity-20261029`. The disposable instance,
claim, network interface and attachment were confirmed absent after cleanup.
