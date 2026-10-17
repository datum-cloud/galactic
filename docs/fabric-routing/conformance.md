# Fabric routing conformance matrix

This matrix maps every FRR construct in the rendered underlay
configurations to the typed `galactic.datumapis.com/v1alpha1` field that
will produce it. It is the parity contract for the fabric compiler: each
field listed here is to be implemented, defaulted and tested as written,
and a construct with no row cannot be produced.

Source: the 19 rendered configurations in infra
`apps/galactic-system/rendered/fabric-router/` at infra `1261df1be`
(5 clusters, 7,050 lines). The plan's earlier counts (17 routers, 6,011
lines) predate the second staging edges added in each staging lab
(`c1890da92`, `6c9546416`). The construct inventory below came from
normalizing every line of all 19 files to its command shape; the counts
are occurrences across the fleet.

Pinned implementation: FRR 10.7.1 (`containers/fabric-router/Dockerfile`).
Parity is measured with that build's `frr-reload.py --test --input
<current> <candidate>`, which parses both files with FRR's own config model
and prints the lines it would add or delete. An empty result is the
acceptance criterion for the first activation, so names, descriptions and
otherwise unused definitions are preserved, not only routing semantics.

## Conventions

- **Name** columns give the FRR object name. Each named kind carries an
  optional `frr.name` (`frr.peerGroupName`, `frr.routeMapName`); when unset
  the compiler uses `metadata.name`. Infra's generator sets the legacy
  names, so the first revision renders the existing names.
- **Reject** means the compiler refuses the router's revision with
  `Accepted=False`, reason `UnsupportedField`, naming the field. Nothing is
  silently ignored.
- Policy terms evaluate in ascending `sequence`; match fields within a term
  are ANDed; the entries of one prefix list or community set are ORed; a
  term with no match fields matches every route; the implicit end of a
  policy is deny.

## Router and implementation parameters

| FRR construct (count)                                  | Typed source                                                                            | Default                     | Notes / reject                                                                                                                                                                                                                                                  |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `frr defaults traditional` (19)                        | `FRRRouterParameters.spec.defaultsProfile: traditional`                                 | none, required              | `datacenter` accepted; changing it restarts bgpd, so the compiler classifies the change as `RestartRequired`.                                                                                                                                                   |
| `hostname <node>-fabric` (19)                          | `FRRRouterParameters.spec.hostnameSuffix: -fabric` + the bound Node name                | empty suffix                | The Node name comes from the resolved `BGPRouter.spec.targetRef`.                                                                                                                                                                                               |
| `log file /var/log/frr/frr.log informational` (19)     | `FRRRouterParameters.spec.logFile.{path,level}`                                         | unset renders no line       | Levels: the FRR syslog levels.                                                                                                                                                                                                                                  |
| `ipv6 forwarding` (19)                                 | `FRRRouterParameters.spec.ipv6Forwarding: true`                                         | false                       | Zebra's flag only. The kernel sysctl stays with host provisioning; the agent never writes sysctls.                                                                                                                                                              |
| `router bgp 33438` (19)                                | `BGPRouter.spec.localASN`                                                               | required                    | 1–4294967295.                                                                                                                                                                                                                                                   |
| `bgp router-id A.B.C.D` (19)                           | `BGPRouter.spec.routerID`                                                               | required                    | Unique within the routing domain (compiler check across routers of one class).                                                                                                                                                                                  |
| `bgp log-neighbor-changes` (19)                        | `FRRRouterParameters.spec.logNeighborChanges: true`                                     | false                       |                                                                                                                                                                                                                                                                 |
| `no bgp default ipv4-unicast` (19)                     | `FRRRouterParameters.spec.ipv4UnicastDefault: false`                                    | false renders the `no` line |                                                                                                                                                                                                                                                                 |
| `bgp allow-martian-nexthop` (0 today; template branch) | `FRRRouterParameters.spec.allowMartianNexthop`                                          | false                       | Kept because the template can emit it.                                                                                                                                                                                                                          |
| `bmp targets <name>` … `exit` (7, staging only)        | `FRRRouterParameters.spec.bmpTargets[]`                                                 | none                        | Each target: `name`, `connect.{address,port,minRetryMilliseconds,maxRetryMilliseconds}`, `monitors[].{afi,safi,mode}` with mode `LocRIB` (`loc-rib`), `PrePolicy`, `PostPolicy`. Production parameters omit it, so production never acquires the staging block. |
| Class selection                                        | `BGPRouter.spec.routerClassName` → `BGPRouterClass.spec.{controllerName,parametersRef}` | none                        | Fabric routers name a class whose `controllerName` is `galactic.datumapis.com/fabric-router`.                                                                                                                                                                   |

`FRRRouterParameters` is cluster-scoped and its spec is immutable; a new
parameter set is a new object, referenced by a new class or a class
change on a router. That keeps a revision's parameters reproducible.

## Static routes

| FRR construct (count)                              | Typed source                                                             | Notes / reject                                                                                   |
| -------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------ |
| `ipv6 route P Null0` (55), `ip route P Null0` (24) | `BGPStaticRoute{routerRef, addressFamily, destination, action: Discard}` | One object per route per router. Destination family must match `addressFamily`.                  |
| `ip route P <next-hop>` (template branch, 0 today) | `action: NextHop`, `nextHop`                                             | Next hop family must match.                                                                      |
| VRF/table placement                                | not representable                                                        | Default instance only; a non-default instance is a later capability, rejected until implemented. |

A static route never implies an advertisement, and an aggregate never
creates a discard route. The shared `/48` discard route the template
emits only for nodes without their own `/64` is ordinary static-route
intent where it exists.

## Peer groups, peers and profiles

FRR peer groups are a rendering of `BGPPeerProfile`. A profile renders as
one peer group named `frr.peerGroupName`; each `BGPPeer` that references
the profile renders as a member.

| FRR construct (count)                                 | Typed source                                                                            | Default                                                  | Notes / reject                                                                                                                                               |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `neighbor PG peer-group` (50)                         | `BGPPeerProfile` (referenced, or listed in `BGPRouter.spec.frr.retain.peerProfileRefs`) | —                                                        | An unreferenced profile is not rendered unless retained.                                                                                                     |
| `neighbor PG remote-as N` (50)                        | `BGPPeerProfile.spec.peerASN`                                                           | unset: rendered per neighbor from `BGPPeer.spec.peerASN` | When set, every member's `peerASN` must equal it (reject on mismatch). Retained empty groups need it.                                                        |
| `neighbor PG ebgp-multihop 2` (20)                    | `spec.transport.ebgpMultihopTTL`                                                        | unset: no line                                           | 1–255. The legacy boolean `BGPPeer.spec.ebgpMultiHop` is rejected for fabric routers; it cannot express TTL 2.                                               |
| `neighbor PG advertisement-interval N` (50)           | `spec.transport.advertisementIntervalSeconds`                                           | unset: FRR default, no line                              | 0–600.                                                                                                                                                       |
| `neighbor A peer-group PG` (136)                      | `BGPPeer.spec.peerProfileRef`                                                           | —                                                        |                                                                                                                                                              |
| `neighbor A description D` (136, 52 distinct texts)   | `BGPPeer.spec.description`                                                              | —                                                        | Exact text, including spaces and the `: node` suffixes.                                                                                                      |
| `neighbor A update-source S` (136)                    | `BGPPeer.spec.updateSource`                                                             | —                                                        | Address or interface name.                                                                                                                                   |
| `neighbor PG activate` (43)                           | `addressFamilies[].afi/safi` on the profile                                             | —                                                        | Only families listed on the profile are activated.                                                                                                           |
| `neighbor PG soft-reconfiguration inbound` (43)       | `addressFamilies[].softReconfigurationInbound`                                          | false                                                    |                                                                                                                                                              |
| `neighbor PG maximum-prefix 100 80 warning-only` (20) | `addressFamilies[].prefixLimit.{maximum,warningThresholdPercent,action: WarnOnly}`      | none                                                     | `Restart` renders `restart <minutes>` (requires `restartMinutes`); `Shutdown` renders no suffix.                                                             |
| `neighbor PG send-community both` (43)                | `addressFamilies[].sendCommunity: both`                                                 | unset: no line                                           | Preserves the spelling. Receiver-side propagation of standard, extended and large communities is tested on the pinned build, not inferred from the keyword.  |
| `neighbor PG allowas-in 1` (20)                       | `addressFamilies[].allowASIn`                                                           | none                                                     | 1–10.                                                                                                                                                        |
| `neighbor PG route-map R in` / `out` (43 each)        | `addressFamilies[].importPolicyRef` / `exportPolicyRef`                                 | none                                                     | A peer family with no export policy is rejected: default-reject (RFC 8212) is explicit.                                                                      |
| `neighbor PG next-hop-self` (19)                      | `addressFamilies[].nextHopMode: Self`                                                   | `Unchanged`: no line                                     |                                                                                                                                                              |
| `neighbor PG route-reflector-client` (4)              | `addressFamilies[].routeReflectorClient: true`                                          | false                                                    | Reflector-side profile. No `cluster-id` is configured today; none is generated. `bgp route-reflector allow-outbound-policy` stays unset, the pinned default. |
| `neighbor A weight 100` (30)                          | `BGPPeer.spec.familySettings[].frr.weight`                                              | none                                                     | FRR-specific local preference; never translated to LOCAL_PREF.                                                                                               |
| Peer without a profile                                | `BGPPeer.spec.familySettings[]`                                                         | —                                                        | Same field set as a profile family; rendered on the neighbor itself.                                                                                         |

Precedence for a peer family: a field set in `BGPPeer.spec.familySettings`
wins over the same field in the profile's family; unset fields fall
through to the profile. `BGPPeer.spec.transport` overrides the profile's
`transport` the same way, field by field. There is no profile inheritance
and no map merge.

Address families: a fabric router's `spec.addressFamilies` lists the
families it renders an `address-family` block for (both unicast families
on edges, IPv6 only on compute and reflectors). A fabric peer's
`spec.addressFamilies` becomes optional when it references a profile; it
then inherits the profile's families, and when set must be a subset of
them. Every peer family must be one of its router's families.
A field that differs from the profile renders on the neighbor, so a group
stays one FRR peer group.

Rejected on fabric-class peers (legacy EVPN fields with no parity row):
`ebgpMultiHop`, `bfd`, `gracefulRestart`, `multiSession`, `routeMapIn`,
`routeMapOut`, `nextHopSelf`, `removePrivateAS`, `sendCommunity`,
`allowASIn`, `maximumPrefix`, `defaultOriginRoute`, `routerSelector`, and
plain-text `authentication.password`. `authSecretRef` is supported and is
an activation dependency (see `contracts.md`).

## Advertisements

| FRR construct (count)                     | Typed source                                                                                 | Notes / reject                                                                                                                                                                                                                                                                                  |
| ----------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `network P route-map R` (55 v6, 24 v4)    | `BGPAdvertisement{addressFamily, prefixes[], policyRef}`                                     | One statement per prefix, all with the advertisement's policy. Prefixes are canonicalized (`2607:ed40:010c::/48` renders `2607:ed40:10c::/48`, which FRR's own parser produces from either spelling). The route must exist in the RIB, normally from a `BGPStaticRoute` or a connected address. |
| `aggregate-address P route-map R` (30)    | `BGPAdvertisement.spec.aggregation.{prefix, summaryOnly: false, asSet: false}` + `policyRef` | FRR aggregates only from contributors already in the BGP table, so `aggregation` never creates a discard route. `summaryOnly`/`asSet` render `summary-only`/`as-set`. Mutually exclusive with `prefixes` and `redistribute` on one advertisement.                                               |
| `redistribute connected route-map R` (29) | `BGPAdvertisement.spec.redistribute: [connected]` + `policyRef`                              | `static` and `kernel` render the same way. A redistribution without a policy is rejected for fabric routers.                                                                                                                                                                                    |

Rejected on fabric-class advertisements: `originateFrom`, `communities`,
`localPreference`, `vrfID`, `function` (EVPN/tenant fields), and a missing
`policyRef`.

## Policy, prefix lists and community sets

| FRR construct (count)                                                                          | Typed source                                                     | Notes / reject                                                                                                                                                                                                                                        |                                                                                         |                                                                                                            |
| ---------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `route-map R permit\                                                                           | deny N` (365 permit, 271 deny)                                   | `BGPPolicy.spec.terms[].{sequence, action}`; name from `spec.frr.routeMapName`                                                                                                                                                                        | 1–65535, unique.                                                                        |                                                                                                            |
| route-map `description D` (481)                                                                | `terms[].description`                                            | Exact text.                                                                                                                                                                                                                                           |                                                                                         |                                                                                                            |
| `match ip\                                                                                     | ipv6 address prefix-list L` (28, 117)                            | `terms[].match.prefixListRef`                                                                                                                                                                                                                         | Family keyword from the list's family.                                                  |                                                                                                            |
| `match community C` (193)                                                                      | `terms[].match.communitySetRef` (set `type: standard`)           |                                                                                                                                                                                                                                                       |                                                                                         |                                                                                                            |
| `match large-community C` (template branch)                                                    | `terms[].match.largeCommunitySetRef` (set `type: large`)         |                                                                                                                                                                                                                                                       |                                                                                         |                                                                                                            |
| `match interface lo` (48)                                                                      | `terms[].match.interface`                                        | Meaningful only for redistribution. The compiler checks each attachment: a policy with an interface match referenced from a peer, a `network` or an aggregate fails that router's revision, while the same policy used by `redistribute` is accepted. |                                                                                         |                                                                                                            |
| term with no `match`                                                                           | match fields all unset (`any: true` is equivalent)               | Matches every route.                                                                                                                                                                                                                                  |                                                                                         |                                                                                                            |
| `set community X ... additive` (48 + 30)                                                       | `terms[].set.standardCommunities{operation: Add, values}`        |                                                                                                                                                                                                                                                       |                                                                                         |                                                                                                            |
| `set community X` (163)                                                                        | `standardCommunities{operation: Replace, values}`                |                                                                                                                                                                                                                                                       |                                                                                         |                                                                                                            |
| `set large-community X [additive]` (163, 10)                                                   | `largeCommunities{operation, values}`                            | Independent of the standard operation.                                                                                                                                                                                                                |                                                                                         |                                                                                                            |
| `set comm-list L delete` / `set large-comm-list L delete` (template-capable)                   | `set.deleteCommunitySetRef` / `deleteLargeCommunitySetRef`       | Removal names a set, as FRR requires.                                                                                                                                                                                                                 |                                                                                         |                                                                                                            |
| `set as-path prepend 33438 33438 33438` (4)                                                    | `set.asPath.{prepend: 3, asn: 33438}`                            | ASN defaults to the router's local ASN.                                                                                                                                                                                                               |                                                                                         |                                                                                                            |
| `set local-preference 0` (19)                                                                  | `set.localPreference`                                            |                                                                                                                                                                                                                                                       |                                                                                         |                                                                                                            |
| `ip\                                                                                           | ipv6 prefix-list L seq N permit\                                 | deny P [ge G] [le E]` (34, 113)                                                                                                                                                                                                                       | `BGPPrefixList.spec.entries[].{sequence, action, prefix, ge, le}`; name `spec.frr.name` | `ge`/`le` are family-aware (≤32 IPv4, ≤128 IPv6), `prefixlen ≤ ge ≤ le`. Sequence 1–4294967295 as `int64`. |
| `bgp community-list standard L permit V` (392: 343 numeric, 49 with the four well-known names) | `BGPCommunitySet{type: standard, entries}`; name `spec.frr.name` | Entries are ORed. Well-known names render as FRR spells them.                                                                                                                                                                                         |                                                                                         |                                                                                                            |
| `bgp large-community-list standard L permit V` (200)                                           | `BGPCommunitySet{type: large}`                                   |                                                                                                                                                                                                                                                       |                                                                                         |                                                                                                            |

`BGPPolicy` becomes a reusable definition: `routerRef`/`routerSelector`
and `direction` are optional, and a policy binds to a router only through
a peer family or an advertisement that references it. The existing
`direction`, `prefixList`, `communityMatch`, `asPathFilter`,
`evpnRouteType`, `vni`, `macAddress`, `ipPrefix`, `localPreference` and
`med` match fields and the `communities`, `extCommunities`, `origin`,
`nextHop`, `metric` and `color` set fields are rejected on fabric routers.
The GoBGP EVPN runtime reads only `any`, `addressFamilies`, community
add/remove and local preference from policies bound to a classless router
by `routerRef` or `routerSelector` (see `ownership-inventory.md`), so a
router-bound policy keeps a required `direction` and may not use the
fabric-only fields.

A missing or deleted referenced set, list or policy is an unresolved
dependency: the router's revision stays pending with `ResolvedRefs=False`
and the running configuration is unchanged. It is never treated as
"no filter".

## Compatibility retention

The legacy renderer emits definitions no session or advertisement uses
(for example `IBGP-OUT`, `RTBH`, `DEFAULT-ONLY` on some nodes, the
`IBGP-PEER` group on edges, and the full community-list catalogue). An
empty first diff requires rendering them too. `BGPRouter.spec.frr.retain`
lists the policies, prefix lists, community sets and peer profiles to
render even when unreferenced. Retained objects never create sessions or
advertisements; removing them is a separate validated revision once the
router is on the typed path.

## Unsupported constructs

The compiler rejects, rather than drops, anything outside this matrix,
including BFD, graceful restart, MD5 by plain-text password, VRF/table
placement, `cluster-id`, route-maps attached to `network` statements in
non-default instances, and EVPN address families on fabric routers.

## Fixtures

The compiler change adds `internal/fabric/routing/testdata/` with the 19
rendered configurations and the typed resources infra's generator emits for
them. A unit test compiles each router and compares FRR's normalized form;
an integration test (build tag `frr`, needs Docker) runs the pinned
`frr-reload.py --test --input` against each rendered file and fails on any
delta.
