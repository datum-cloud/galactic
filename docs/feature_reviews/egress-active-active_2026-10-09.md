# Architecture Review: egress-active-active

This document moved to [egress-active-active_2026-10-09](../archive/reviews/egress-active-active_2026-10-09.md). Update bookmarks to the maintained page.

<a id="summary"></a>

See [Summary](../archive/reviews/egress-active-active_2026-10-09.md#summary).

<a id="validation-evidence"></a>

See [Validation evidence](../archive/reviews/egress-active-active_2026-10-09.md#validation-evidence).

<a id="staging-acceptance-gates"></a>

See [Staging acceptance gates](../archive/reviews/egress-active-active_2026-10-09.md#staging-acceptance-gates).

<a id="architecture"></a>

See [Architecture](../archive/reviews/egress-active-active_2026-10-09.md#architecture).

<a id="findings"></a>

See [Findings](../archive/reviews/egress-active-active_2026-10-09.md#findings).

<a id="-p0--critical"></a>

See [🔴 P0 — Critical](../archive/reviews/egress-active-active_2026-10-09.md#-p0--critical).

<a id="-p1--high"></a>

See [🟠 P1 — High](../archive/reviews/egress-active-active_2026-10-09.md#-p1--high).

<a id="f01-do-not-disable-the-group-after-a-failed-ordered-mode-refresh"></a>

See [[F01] Do not disable the group after a failed ordered-mode refresh](../archive/reviews/egress-active-active_2026-10-09.md#f01-do-not-disable-the-group-after-a-failed-ordered-mode-refresh).

<a id="f04-validate-shard-translation-compatibility-before-adding-it-to-the-pool"></a>

See [[F04] Validate shard translation compatibility before adding it to the pool](../archive/reviews/egress-active-active_2026-10-09.md#f04-validate-shard-translation-compatibility-before-adding-it-to-the-pool).

<a id="f05-reserve-slot-generations-across-failed-group-publication"></a>

See [[F05] Reserve slot generations across failed group publication](../archive/reviews/egress-active-active_2026-10-09.md#f05-reserve-slot-generations-across-failed-group-publication).

<a id="-p2--medium"></a>

See [🟡 P2 — Medium](../archive/reviews/egress-active-active_2026-10-09.md#-p2--medium).

<a id="f02-require-successful-new-tenant-egress-in-the-drain-check"></a>

See [[F02] Require successful new-tenant egress in the drain check](../archive/reviews/egress-active-active_2026-10-09.md#f02-require-successful-new-tenant-egress-in-the-drain-check).

<a id="f03-remove-the-claim-that-deleting-a-shard-gracefully-drains-it"></a>

See [[F03] Remove the claim that deleting a shard gracefully drains it](../archive/reviews/egress-active-active_2026-10-09.md#f03-remove-the-claim-that-deleting-a-shard-gracefully-drains-it).

<a id="f06-read-a-coherent-shard-snapshot-during-concurrent-map-updates"></a>

See [[F06] Read a coherent shard snapshot during concurrent map updates](../archive/reviews/egress-active-active_2026-10-09.md#f06-read-a-coherent-shard-snapshot-during-concurrent-map-updates).

<a id="-p3--low"></a>

See [⚪ P3 — Low](../archive/reviews/egress-active-active_2026-10-09.md#-p3--low).

<a id="whats-working-well"></a>

See [What's Working Well](../archive/reviews/egress-active-active_2026-10-09.md#whats-working-well).

<a id="refactor-plan"></a>

See [Refactor Plan](../archive/reviews/egress-active-active_2026-10-09.md#refactor-plan).

<a id="step-1-preserve-refresh-errors-through-rollback"></a>

See [Step 1: Preserve refresh errors through rollback](../archive/reviews/egress-active-active_2026-10-09.md#step-1-preserve-refresh-errors-through-rollback).

<a id="step-2-make-shard-publication-and-identity-retry-safe"></a>

See [Step 2: Make shard publication and identity retry-safe](../archive/reviews/egress-active-active_2026-10-09.md#step-2-make-shard-publication-and-identity-retry-safe).

<a id="step-3-enforce-compatible-translation-identities"></a>

See [Step 3: Enforce compatible translation identities](../archive/reviews/egress-active-active_2026-10-09.md#step-3-enforce-compatible-translation-identities).

<a id="step-4-make-drain-verification-fail-on-absence-of-traffic"></a>

See [Step 4: Make drain verification fail on absence of traffic](../archive/reviews/egress-active-active_2026-10-09.md#step-4-make-drain-verification-fail-on-absence-of-traffic).

<a id="step-5-correct-deletion-procedure"></a>

See [Step 5: Correct deletion procedure](../archive/reviews/egress-active-active_2026-10-09.md#step-5-correct-deletion-procedure).

<a id="additional-constraints-and-coverage-observations"></a>

See [Additional constraints and coverage observations](../archive/reviews/egress-active-active_2026-10-09.md#additional-constraints-and-coverage-observations).
