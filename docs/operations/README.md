# Shared operations

Use these guides for settings and changes that cross component boundaries.

- [Node labels](node-labels.md): which roles and opt-ins place each DaemonSet.
- [XDP attach mode](xdp-attach-mode.md): host mode selection, readiness, migration and rollback.
- [Legacy API consolidation](migrations/galactic-api-consolidation.md): cutover for installations with legacy cloud or network API-group objects.
- [Observability](../observability/README.md): scrape configuration, metric interpretation and alerts.
- [Fabric routing operations](../fabric-routing/operations.md): staged FRR configuration changes and recovery.
- [Fabric-api operations](../fabric-api/operations.md): diagnostic rollout and verification.
- [NAT active/active rollout](../nat/active-active-rollout.md): prerequisites, draining and rollback.
- [Traffic-policy rollout](../traffic-policy/rollout.md): audit before enforcing interface grants.
- [Edge troubleshooting](../edge/troubleshooting.md): attachment and route lifecycle diagnosis.

Use component deployment guides for installation. A migration guide applies only to installations in the starting state it names; it is not the default path for a fresh installation.
