# Fabric looking glass

Use fabric-api to query FRR state and run bounded ICMP diagnostics from fabric routers. It is opt-in and separate from the L4 ingress gateway.

- [Architecture](architecture.md): ownership, execution, recovery and isolation.
- [Deployment](deployment.md): prerequisites, cell gateway, node sidecar and certificate pods.
- [Configuration](configuration.md): ports, flags, budgets, index settings and cleanup.
- [Security](security.md): identities, certificate rotation and probe destination policy.
- [Operations](operations.md): observability, rollout, verification and troubleshooting.
- [FabricQuery API](api.md): query and result semantics, conditions and errors.
- [Load-test procedure](load-test.md): repeat the full-table diagnostic qualification.
- [Looking Glass qualification](qualification.md): run the service's acceptance suite on real fabric routers.
- [Metric reference](../observability/fabric-api.md): exported series and alerts.

The [Looking Glass service contract](../designs/looking-glass-service.md) specifies proposed service behavior. It does not announce a customer API or qualified aggregate limits.
