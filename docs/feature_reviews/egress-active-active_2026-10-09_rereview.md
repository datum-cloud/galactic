# Architecture Review: egress-active-active

This document moved to [egress-active-active_2026-10-09_rereview](../archive/reviews/egress-active-active_2026-10-09_rereview.md). Update bookmarks to the maintained page.

<a id="summary"></a>

See [Summary](../archive/reviews/egress-active-active_2026-10-09_rereview.md#summary).

<a id="original-findings-disposition"></a>

See [Original findings disposition](../archive/reviews/egress-active-active_2026-10-09_rereview.md#original-findings-disposition).

<a id="validation-and-reproductions"></a>

See [Validation and reproductions](../archive/reviews/egress-active-active_2026-10-09_rereview.md#validation-and-reproductions).

<a id="architecture"></a>

See [Architecture](../archive/reviews/egress-active-active_2026-10-09_rereview.md#architecture).

<a id="findings"></a>

See [Findings](../archive/reviews/egress-active-active_2026-10-09_rereview.md#findings).

<a id="-p0--critical"></a>

See [🔴 P0 — Critical](../archive/reviews/egress-active-active_2026-10-09_rereview.md#-p0--critical).

<a id="-p1--high"></a>

See [🟠 P1 — High](../archive/reviews/egress-active-active_2026-10-09_rereview.md#-p1--high).

<a id="r01-closing-groups-does-not-exclude-in-flight-cni-sentinel-writes"></a>

See [[R01] Closing groups does not exclude in-flight CNI sentinel writes](../archive/reviews/egress-active-active_2026-10-09_rereview.md#r01-closing-groups-does-not-exclude-in-flight-cni-sentinel-writes).

<a id="r02-empty-hashed-membership-silently-restores-static-shard-routes"></a>

See [[R02] Empty hashed membership silently restores static shard routes](../archive/reviews/egress-active-active_2026-10-09_rereview.md#r02-empty-hashed-membership-silently-restores-static-shard-routes).

<a id="r03-skipping-an-unserved-nat64-prefix-lets-nat66-default-route-catch-it"></a>

See [[R03] Skipping an unserved NAT64 prefix lets NAT66 default route catch it](../archive/reviews/egress-active-active_2026-10-09_rereview.md#r03-skipping-an-unserved-nat64-prefix-lets-nat66-default-route-catch-it).

<a id="r05-do-not-reuse-a-translation-class-group-while-old-routes-reference-it"></a>

See [[R05] Do not reuse a translation-class group while old routes reference it](../archive/reviews/egress-active-active_2026-10-09_rereview.md#r05-do-not-reuse-a-translation-class-group-while-old-routes-reference-it).

<a id="-p2--medium"></a>

See [🟡 P2 — Medium](../archive/reviews/egress-active-active_2026-10-09_rereview.md#-p2--medium).

<a id="r04-fresh-address-counter-is-lost-in-command-substitutions"></a>

See [[R04] Fresh-address counter is lost in command substitutions](../archive/reviews/egress-active-active_2026-10-09_rereview.md#r04-fresh-address-counter-is-lost-in-command-substitutions).

<a id="r06-withdraw-every-route-source-before-measuring-shard-unreachable-convergence"></a>

See [[R06] Withdraw every route source before measuring shard-unreachable convergence](../archive/reviews/egress-active-active_2026-10-09_rereview.md#r06-withdraw-every-route-source-before-measuring-shard-unreachable-convergence).

<a id="-p3--low"></a>

See [⚪ P3 — Low](../archive/reviews/egress-active-active_2026-10-09_rereview.md#-p3--low).

<a id="whats-working-well"></a>

See [What's Working Well](../archive/reviews/egress-active-active_2026-10-09_rereview.md#whats-working-well).

<a id="refactor-plan"></a>

See [Refactor Plan](../archive/reviews/egress-active-active_2026-10-09_rereview.md#refactor-plan).

<a id="step-1-make-group-retirement-exclude-concurrent-writers"></a>

See [Step 1: Make group retirement exclude concurrent writers](../archive/reviews/egress-active-active_2026-10-09_rereview.md#step-1-make-group-retirement-exclude-concurrent-writers).

<a id="step-2-preserve-fail-closed-translation-classes"></a>

See [Step 2: Preserve fail-closed translation classes](../archive/reviews/egress-active-active_2026-10-09_rereview.md#step-2-preserve-fail-closed-translation-classes).

<a id="step-3-reconcile-translation-class-lifetime"></a>

See [Step 3: Reconcile translation-class lifetime](../archive/reviews/egress-active-active_2026-10-09_rereview.md#step-3-reconcile-translation-class-lifetime).

<a id="step-4-make-fresh-probes-deterministic"></a>

See [Step 4: Make fresh probes deterministic](../archive/reviews/egress-active-active_2026-10-09_rereview.md#step-4-make-fresh-probes-deterministic).

<a id="step-5-make-the-bgp-acceptance-failure-remove-all-usable-paths"></a>

See [Step 5: Make the BGP acceptance failure remove all usable paths](../archive/reviews/egress-active-active_2026-10-09_rereview.md#step-5-make-the-bgp-acceptance-failure-remove-all-usable-paths).

<a id="remaining-staging-gates-and-review-observations"></a>

See [Remaining staging gates and review observations](../archive/reviews/egress-active-active_2026-10-09_rereview.md#remaining-staging-gates-and-review-observations).
