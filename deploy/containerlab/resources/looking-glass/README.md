# Looking Glass service on dfw

The overlays `deploy:looking-glass` applies to qualify the Looking Glass
service (`verify:looking-glass`), one per step of the enabling order in
[docs/fabric-api/operations.md](../../../../docs/fabric-api/operations.md#enabling-aggregate-probe-budgets).
Each builds on the step before it:

| Step | Overlay                      | Applied from        | Adds                                                     |
| ---- | ---------------------------- | ------------------- | -------------------------------------------------------- |
| 1    | `fabric-router/dfw/permits/` | `dfw-control-plane` | `components/fabric-api-permits`; restarts FRR            |
| 2    | `gateway/dfw/budgets/`       | host                | `components/aggregate-budgets`                           |
| 3    | `fabric-router/dfw/require/` | `dfw-control-plane` | `components/fabric-api-require-permits`; restarts FRR    |
| 4    | `gateway/dfw/service/`       | host                | `components/service`, switched off until the deploy ends |

`pki/services.yaml` holds the service certificates the suite authenticates
with. `undeploy:looking-glass` switches the service off and walks the steps
back in reverse, ending on the lab's ordinary `fabric-router` and gateway
overlays.

The `fabric-router` overlays are applied on `dfw-control-plane`, where
`deploy-fabric.sh` copies `resources/fabric-router/` and nests
`config/fabric-router/` under it as `fabric-router/base/fabric`; their
relative paths resolve there, not in this checkout.
