# FRR-K8s as the fabric backend: evaluation

The plan asked whether FRR-K8s could replace the existing FRR reload path.
It cannot, for the current underlay. The existing path stays the
implementation baseline.

Evaluated: FRR-K8s `v0.0.27` (`metallb/frr-k8s` at `d5dee8c`), API
`frrk8s.metallb.io/v1beta1` `FRRConfiguration`
(`api/v1beta1/frrconfiguration_types.go`) and its renderer
(`internal/frr/templates`, `internal/frr/config.go`), against the 19
rendered configurations and [conformance.md](conformance.md).

## Behavior it cannot express

| Required behavior                                                                                                                      | FRR-K8s v0.0.27                                                                               |
| -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `aggregate-address` with contributor semantics (30 lines)                                                                              | No aggregation field.                                                                         |
| `redistribute connected route-map` with `match interface lo` and prefix-list conjunction (29 + 48 lines)                               | No redistribution or interface match.                                                         |
| `network` origination through a named route-map setting standard and large communities                                                 | `toAdvertise` attaches per-prefix communities to a neighbor's export, not origination policy. |
| Ordered first-match export policy with community-only deny terms (`NO-ADVERTISE`, `NO-EXPORT`) and terms matching prefix AND community | Allow-lists of prefixes per neighbor; no ordered terms or community matches.                  |
| `weight 100` on private mesh peers (30 lines)                                                                                          | Not present.                                                                                  |
| `maximum-prefix 100 80 warning-only`                                                                                                   | Not present.                                                                                  |
| `ebgp-multihop 2`                                                                                                                      | Boolean only, like the legacy Galactic field.                                                 |
| `advertisement-interval`                                                                                                               | Not present.                                                                                  |
| `ipv6 route P Null0` discard routes (79 lines)                                                                                         | Not present.                                                                                  |
| `route-reflector-client` without next-hop-self                                                                                         | Not present.                                                                                  |
| BMP targets                                                                                                                            | Not present.                                                                                  |
| Deny-all import (`route-map DENY in`) on provider sessions                                                                             | Representable (`toReceive` empty).                                                            |

The only way to fill these gaps is `rawConfig`, which the project's README
marks unsupported and for experimentation only.

## Empty first diff

FRR-K8s generates its own object names: route-maps `<neighbor>-in` and
`<neighbor>-out` (`neighboripfamily.tmpl`), prefix lists named from the
neighbor ID and family (`config.go`). The first activation would delete
and re-add every route-map, prefix list and community list on every
router, which is the session-affecting change the migration must avoid.

## Writer and recovery contract

FRR-K8s applies configuration through its own reloader
(`cmd/reloader/frr-reloader.sh`) and merges every matching
`FRRConfiguration` additively, so a broader allow from one object widens
another's filter. The fabric contract needs one writer gated by an
activation epoch, a journal, a recovery checkpoint and an authorized
recovery target ([contracts.md](contracts.md)). Adopting FRR-K8s would mean
forking its reconciler to add all of that, which leaves little of it in
use.

## Result

Keep FRR with the existing `fabric-config-agent` reload path. Its current
`Check`/`Reload`/`Neighbors`/`Routes`/`ResetNeighbor` interface
(`internal/fabricconfig/frr.go`) becomes the new
`Validate`/`Plan`/`Apply`/`Observe`/`Recover` adapter. Re-evaluate FRR-K8s
when it supports ordered policy terms, aggregation, filtered
redistribution and stable object names; the conformance matrix is the
measuring stick.
