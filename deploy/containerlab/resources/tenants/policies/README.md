# Lab traffic policies

The lab enforces interface traffic policy (`GALACTIC_CNI_TRAFFIC_POLICY=enforce`
in `resources/galactic-cni/shared/`), so a tenant interface forwards only what
its bindings grant. These are the grants, one set per kind of tenant, each an
ingress and an egress policy granting only the paths that tenant's checks use:

| Set              | Tenants                | Egress grants                                          | Ingress grants                                         |
| ---------------- | ---------------------- | ------------------------------------------------------ | ------------------------------------------------------ |
| `private-nat`    | ns10, ns20, ns30, ns71 | Private, PublicNAT                                     | Private (except TCP 9), PublicNAT                      |
| `private`        | ns40                   | Private                                                | Private (except TCP 9)                                 |
| `public-service` | ns60                   | PublicService, Private TCP from port 80 to `fe80::/10` | PublicService, Private TCP to port 80 from `fe80::/10` |

The TCP 9 deny on Private ingress, and every path a set leaves out, are what
`verify:traffic-policy` uses to prove a denial is enforced and counted. Each
tenant's `<ns>/policy/` applies one set into its namespace and binds every
attachment the tenant has to it, in both directions.
