# API Reference

## Packages
- [galactic.datumapis.com/v1alpha1](#galacticdatumapiscomv1alpha1)


## galactic.datumapis.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the galactic.datumapis.com/v1alpha1 API group.

### Resource Types
- [BGPAdvertisement](#bgpadvertisement)
- [BGPCommunitySet](#bgpcommunityset)
- [BGPPeer](#bgppeer)
- [BGPPeerProfile](#bgppeerprofile)
- [BGPPolicy](#bgppolicy)
- [BGPRouter](#bgprouter)
- [BGPRouterClass](#bgprouterclass)
- [BGPStaticRoute](#bgpstaticroute)
- [BGPVRFInstance](#bgpvrfinstance)
- [EgressShard](#egressshard)
- [FRRRouterParameters](#frrrouterparameters)
- [FabricEndpoint](#fabricendpoint)
- [FabricReleaseAuthorization](#fabricreleaseauthorization)
- [FabricRolloutPolicy](#fabricrolloutpolicy)
- [FabricRouterDeployment](#fabricrouterdeployment)
- [FabricRouterRevision](#fabricrouterrevision)
- [FabricTopology](#fabrictopology)
- [ServiceEndpoint](#serviceendpoint)
- [ServiceRoutePolicy](#serviceroutepolicy)
- [ServiceVIPBinding](#servicevipbinding)



#### AFI

_Underlying type:_ _string_

AFI is the Address Family Indicator for a BGP address family.

_Validation:_
- Enum: [ipv4 ipv6 l2vpn]

_Appears in:_
- [AddressFamily](#addressfamily)
- [BGPPeerFamilySettings](#bgppeerfamilysettings)
- [BGPStaticRouteSpec](#bgpstaticroutespec)
- [BMPMonitor](#bmpmonitor)

| Field | Description |
| --- | --- |
| `ipv4` |  |
| `ipv6` |  |
| `l2vpn` |  |


#### ASPathFilter



ASPathFilter matches BGP routes by AS path using a regex pattern.



_Appears in:_
- [BGPPolicyMatch](#bgppolicymatch)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `pattern` _string_ | Pattern is a regular expression matched against the AS path.<br />The AS path is represented as a space-separated string of ASNs. |  | MaxLength: 256 <br />MinLength: 1 <br /> |
| `matchType` _[ASPathMatchType](#aspathmatchtype)_ | MatchType determines whether the pattern must match the full path<br />or can match a substring. Default: "contains". | contains | Enum: [full contains] <br /> |


#### ASPathMatchType

_Underlying type:_ _string_

ASPathMatchType determines how an AS path filter pattern is applied.

_Validation:_
- Enum: [full contains]

_Appears in:_
- [ASPathFilter](#aspathfilter)

| Field | Description |
| --- | --- |
| `full` | ASPathMatchFull requires the pattern to match the entire AS path.<br /> |
| `contains` | ASPathMatchContains requires the pattern to match a substring of the AS path.<br /> |


#### AddressClaimRef



AddressClaimRef names the addressing-service claim an assigned address came
from. It is a record, not a lookup: the addressing service is an aggregated
API served on a project control-plane path and defines no CustomResourceDefinition,
so no claim object exists in the cluster a shard runs in and nothing here
resolves one. Reading it means addressing that project's control plane
directly, with a credential a translating node is deliberately not given.

Every field is a plain string and this group depends on no addressing-service
type. The shape matches that service's own opaque cross-API reference, plus
the project, because a claim is namespaced within a project and a namespace
name alone does not identify one from outside.

Populate it with the coordinates of the claim whose allocation produced the
address written alongside it:

	shardAddressIPv6: 2001:db8:f00d::100
	shardAddressIPv6ClaimRef:
	  project: datum-network-edge
	  namespace: egress
	  name: egress-shard-node-a-ipv6

The claim cannot record this relationship itself. The addressing service
overwrites a claim's spec.ownerRef on create with the identity that requested
it, so a claim made by a cell controller is attributed to that controller's
project rather than to the shard it was made for. Attribution therefore runs
in this direction only, and an operator asking which claim holds a shard's
address has this field or nothing.



_Appears in:_
- [EgressShardSpec](#egressshardspec)
- [FabricEndpointSource](#fabricendpointsource)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroup` _string_ | APIGroup is the group of the claim resource. | ipam.miloapis.com | MinLength: 1 <br /> |
| `kind` _string_ | Kind is the kind of the claim resource. | IPClaim | MinLength: 1 <br /> |
| `project` _string_ | Project is the project whose control plane serves the claim. Required:<br />a claim is namespaced within a project, and this reference is read from<br />outside every project. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `namespace` _string_ | Namespace is the namespace holding the claim within Project. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `name` _string_ | Name is the name of the claim. The addressing service derives it from<br />the thing being addressed, so it is stable across a shard's lifetime and<br />is what a replacement finds again. |  | MinLength: 1 <br />Required: \{\} <br /> |


#### AddressFamily



AddressFamily is a BGP address family expressed as an AFI/SAFI pair.
Valid combinations: ipv4/unicast, ipv6/unicast, l2vpn/evpn.



_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)
- [BGPPeerSpec](#bgppeerspec)
- [BGPPolicyMatch](#bgppolicymatch)
- [BGPRouterSpec](#bgprouterspec)
- [ResolvedRouterConfig](#resolvedrouterconfig)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `afi` _[AFI](#afi)_ | AFI is the address family indicator. |  | Enum: [ipv4 ipv6 l2vpn] <br /> |
| `safi` _[SAFI](#safi)_ | SAFI is the subsequent address family indicator. |  | Enum: [unicast evpn] <br /> |


#### AdvertisementOriginateFrom



AdvertisementOriginateFrom defines how routes are sourced from a local system
resource rather than from the static Prefixes list.



_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[AdvertisementOriginateType](#advertisementoriginatetype)_ | Type is the source from which routes are originated. |  | Enum: [interface kernel] <br /> |
| `interfaceName` _string_ | InterfaceName is the name of the interface to originate routes from.<br />Required when type is "interface". |  | MinLength: 1 <br /> |


#### AdvertisementOriginateType

_Underlying type:_ _string_

AdvertisementOriginateType is the source from which routes are originated.

_Validation:_
- Enum: [interface kernel]

_Appears in:_
- [AdvertisementOriginateFrom](#advertisementoriginatefrom)

| Field | Description |
| --- | --- |
| `interface` | OriginateTypeInterface originates routes from local interface addresses.<br /> |
| `kernel` | OriginateTypeKernel originates routes learned from the kernel routing table.<br /> |


#### AdvertisementPolicyRef



AdvertisementPolicyRef references a BGPPolicy by name to apply as a conditional
filter before advertisement.



_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the BGPPolicy within the same namespace. |  | MinLength: 1 <br /> |


#### AsPathSet



AsPathSet defines AS path manipulation operations.



_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `prepend` _integer_ | Prepend adds an ASN to the AS path N times. |  | Maximum: 10 <br />Minimum: 1 <br /> |
| `asn` _integer_ | ASN is the AS number to prepend (used when prepend is set).<br />Defaults to the local ASN if not specified. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `replace` _integer array_ | Replace replaces the entire AS path with the given list.<br />Mutually exclusive with prepend. |  | MaxItems: 32 <br /> |


#### BGPAdvertisement



BGPAdvertisement defines routing information to advertise from a single BGPRouter.
Routes are originated from static Prefixes, redistributed routing table entries,
or local interface/kernel routes. Fan-out via routerSelector is intentionally not
supported to avoid ambiguous prefix attribution across multiple routers.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPAdvertisement` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPAdvertisementSpec](#bgpadvertisementspec)_ |  |  |  |
| `status` _[BGPAdvertisementStatus](#bgpadvertisementstatus)_ |  |  |  |


#### BGPAdvertisementSpec



BGPAdvertisementSpec defines the desired advertisement state.
At least one of prefixes, redistribute, or originateFrom must be specified.



_Appears in:_
- [BGPAdvertisement](#bgpadvertisement)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `expiresAt` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | ExpiresAt is the serving lease deadline. The router withdraws the advertisement<br />at or after this time unless the producer renews it. Unset preserves unleased behavior. |  |  |
| `routerRef` _[RouterRef](#routerref)_ | RouterRef targets a single BGPRouter by name. |  | Required: \{\} <br /> |
| `addressFamily` _[AddressFamily](#addressfamily)_ | AddressFamily defines the AFI/SAFI for this advertisement. |  | Required: \{\} <br /> |
| `prefixes` _[Prefix](#prefix) array_ | Prefixes is the list of CIDR prefixes to advertise.<br />At least one of Prefixes, Redistribute, or OriginateFrom must be specified. |  | MaxItems: 256 <br />MaxLength: 64 <br /> |
| `redistribute` _[RedistributeSource](#redistributesource) array_ | Redistribute defines routing table sources to redistribute into BGP.<br />Routes matching the source type are originated without requiring explicit CIDR entries.<br />At least one of Prefixes, Redistribute, or OriginateFrom must be specified. |  | Enum: [static connected kernel] <br />MaxItems: 3 <br /> |
| `originateFrom` _[AdvertisementOriginateFrom](#advertisementoriginatefrom)_ | OriginateFrom defines how routes are sourced from a local interface or kernel table.<br />When set, routes are originated from the specified source in addition to any static Prefixes.<br />At least one of Prefixes, Redistribute, or OriginateFrom must be specified. |  |  |
| `aggregation` _[BGPAggregation](#bgpaggregation)_ | Aggregation originates an aggregate of contributing routes already in<br />the BGP table. It never installs a discard route; pair it with a<br />BGPStaticRoute where one is wanted. Honored by the fabric router<br />implementation only. |  |  |
| `policyRef` _[AdvertisementPolicyRef](#advertisementpolicyref)_ | PolicyRef references a BGPPolicy to apply as a conditional filter before advertisement.<br />Only routes that match the policy are originated. |  |  |
| `communities` _[Community](#community) array_ | Communities is the default list of BGP communities to attach to all advertised prefixes.<br />Per-prefix communities in Prefixes[n].communities replace this value for individual prefixes. |  | MaxItems: 64 <br />MaxLength: 32 <br /> |
| `localPreference` _integer_ | LocalPreference sets the default BGP LOCAL_PREF attribute for all advertised prefixes.<br />Per-prefix localPreference in Prefixes[n].localPreference overrides this value.<br />Only meaningful for iBGP sessions. |  | Minimum: 0 <br /> |
| `vrfID` _integer_ | VRFID is the 16-bit PoP-local VRF identifier this advertisement's SRv6<br />SID resolves into, per RFC 9800 uSID Argument addressing. Required when<br />Function is set. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `function` _[SRv6Function](#srv6function)_ | Function is the RFC 8986 SRv6 endpoint behavior applied when this<br />advertisement originates a compressed uSID. Required when VRFID is set. |  | Enum: [End.DT4 End.DT6 End.DT46] <br /> |


#### BGPAdvertisementStatus



BGPAdvertisementStatus defines the observed state of BGPAdvertisement.



_Appears in:_
- [BGPAdvertisement](#bgpadvertisement)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `advertisedPrefixes` _integer_ | AdvertisedPrefixes is the count of prefixes currently being originated. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPAggregation



BGPAggregation is one aggregate route.



_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `prefix` _string_ | Prefix is the aggregate in CIDR notation. |  | MaxLength: 43 <br />MinLength: 1 <br /> |
| `summaryOnly` _boolean_ | SummaryOnly suppresses the contributing routes, advertising only the<br />aggregate. |  |  |
| `asSet` _boolean_ | ASSet carries the contributors' AS numbers in an AS_SET. |  |  |


#### BGPCommunitySet



BGPCommunitySet defines a named list of BGP community values used by BGPPolicy
terms to match or set communities on routes. It is referenced by name from
BGPPolicyMatch.communitySetRef.

A single BGPCommunitySet holds either standard or large communities — the type
is declared upfront and all entries are validated against it via CEL.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPCommunitySet` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPCommunitySetSpec](#bgpcommunitysetspec)_ |  |  |  |
| `status` _[BGPCommunitySetStatus](#bgpcommunitysetstatus)_ |  |  |  |


#### BGPCommunitySetSpec



BGPCommunitySetSpec defines the desired state of BGPCommunitySet.



_Appears in:_
- [BGPCommunitySet](#bgpcommunityset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `frr` _[FRRNameOverride](#frrnameoverride)_ | FRR holds FRR rendering settings. |  |  |
| `type` _[BGPCommunitySetType](#bgpcommunitysettype)_ | Type is the community format for all entries in this set. |  | Enum: [standard large] <br />Required: \{\} <br /> |
| `entries` _string array_ | Entries is the list of community values.<br />Standard: ASN:NN, IP:NN, or well-known names (graceful-shutdown, no-export,<br />no-advertise, blackhole).<br />Large: ASN:NN:NN. |  | MaxItems: 256 <br />MinItems: 1 <br />items:MaxLength: 32 <br /> |


#### BGPCommunitySetStatus



BGPCommunitySetStatus defines the observed state of BGPCommunitySet.



_Appears in:_
- [BGPCommunitySet](#bgpcommunityset)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPCommunitySetType

_Underlying type:_ _string_

BGPCommunitySetType distinguishes standard from large BGP communities.

_Validation:_
- Enum: [standard large]

_Appears in:_
- [BGPCommunitySetSpec](#bgpcommunitysetspec)

| Field | Description |
| --- | --- |
| `standard` | BGPCommunitySetTypeStandard covers ASN:NN, IP:NN, and well-known names<br />(graceful-shutdown, no-export, no-advertise, blackhole).<br /> |
| `large` | BGPCommunitySetTypeLarge covers ASN:NN:NN large communities.<br /> |


#### BGPMaximumPrefix



BGPMaximumPrefix defines the maximum number of routes accepted from a peer
before triggering a shutdown action.



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `limit` _integer_ | Limit is the maximum number of routes accepted from this peer. |  | Minimum: 1 <br /> |
| `thresholdPercent` _integer_ | ThresholdPercent is the percentage threshold at which a warning is<br />logged (e.g., 75 means warn at 75% of Limit). Range: 1-100. |  | Maximum: 100 <br />Minimum: 1 <br /> |
| `shutdownAction` _[MaxPrefixShutdownAction](#maxprefixshutdownaction)_ | ShutdownAction is the action taken when the Limit is exceeded. |  | Enum: [warning-only restart shutdown] <br />Required: \{\} <br /> |


#### BGPNextHopMode

_Underlying type:_ _string_

BGPNextHopMode controls the next hop a peer family advertises.

_Validation:_
- Enum: [Unchanged Self SelfForce]

_Appears in:_
- [BGPPeerFamilySettings](#bgppeerfamilysettings)

| Field | Description |
| --- | --- |
| `Unchanged` | BGPNextHopUnchanged keeps the implementation's default next hop.<br /> |
| `Self` | BGPNextHopSelf rewrites the next hop to the local session address.<br /> |
| `SelfForce` | BGPNextHopSelfForce rewrites the next hop to the local session<br />address on reflected routes too, which Self leaves unchanged.<br /> |


#### BGPOrigin

_Underlying type:_ _string_

BGPOrigin is the BGP origin attribute per RFC 4271.

_Validation:_
- Enum: [igp egp incomplete]

_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description |
| --- | --- |
| `igp` | BGPOriginIGP indicates the route was learned via an IGP.<br /> |
| `egp` | BGPOriginEGP indicates the route was learned via the EGP protocol.<br /> |
| `incomplete` | BGPOriginIncomplete indicates the route origin is unknown.<br /> |


#### BGPPeer



BGPPeer defines a BGP session to a remote peer. It binds to one or more
BGPRouter instances via routerRef or routerSelector.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPPeer` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPPeerSpec](#bgppeerspec)_ |  |  |  |
| `status` _[BGPPeerStatus](#bgppeerstatus)_ |  |  |  |


#### BGPPeerAuthentication



BGPPeerAuthentication defines authentication configuration for a BGP peer.

Supports both secret-ref-based (MD5/TCP-AO) and plain-text passwords.
The plain-text password is primarily for non-production environments.



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `password` _string_ | Password is a plain-text authentication password.<br />Prefer AuthSecretRef for production deployments. |  |  |


#### BGPPeerBFD



BGPPeerBFD defines BFD (Bidirectional Forwarding Detection) parameters for a BGP peer.

BFD provides sub-second failure detection for BGP sessions, enabling fast
convergence without relying on BGP hold timers (default 90s).



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enabled` _boolean_ | Enabled indicates whether BFD is enabled for this peer. |  |  |
| `minimumTx` _integer_ | MinimumTx is the minimum transmission interval in microseconds.<br />FRR / GoBGP use microseconds — the controller converts to milliseconds<br />when programming the runtime. Defaults to 300000 (300ms). |  |  |
| `minimumRx` _integer_ | MinimumRx is the minimum reception interval in microseconds.<br />Defaults to 300000 (300ms). |  |  |
| `detectMultiplier` _integer_ | DetectMultiplier is the number of missed packets before declaring the<br />BFD session down. Default is 3. |  | Maximum: 50 <br />Minimum: 3 <br /> |
| `multiHop` _boolean_ | MultiHop enables BFD for eBGP multi-hop sessions (RFC 5883).<br />Must be true when ebgpMultiHop is true. |  |  |


#### BGPPeerFamilySettings



BGPPeerFamilySettings holds one address family's session settings for a
peer or a peer profile. Every field is optional: on a peer, an unset field
falls through to the profile's setting for the same family.



_Appears in:_
- [BGPPeerProfileSpec](#bgppeerprofilespec)
- [BGPPeerSpec](#bgppeerspec)
- [FabricSessionSettings](#fabricsessionsettings)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `afi` _[AFI](#afi)_ | AFI is the address family indicator. |  | Enum: [ipv4 ipv6 l2vpn] <br /> |
| `safi` _[SAFI](#safi)_ | SAFI is the subsequent address family indicator. |  | Enum: [unicast evpn] <br /> |
| `softReconfigurationInbound` _boolean_ | SoftReconfigurationInbound keeps a copy of the routes received from<br />the peer, so an import policy change applies without a refresh. |  |  |
| `prefixLimit` _[BGPPrefixLimit](#bgpprefixlimit)_ | PrefixLimit bounds the prefixes the peer may send in this family. |  |  |
| `sendCommunity` _[SendCommunityType](#sendcommunitytype)_ | SendCommunity restricts the community attributes sent to the peer to<br />the named ones. Unset sends every community attribute, the pinned<br />FRR's default. |  | Enum: [standard extended large both] <br /> |
| `allowASIn` _integer_ | AllowASIn accepts routes whose AS path holds the local ASN up to this<br />many times. |  | Maximum: 10 <br />Minimum: 1 <br /> |
| `importPolicyRef` _[LocalObjectRef](#localobjectref)_ | ImportPolicyRef names the BGPPolicy applied to routes received from<br />the peer in this family. |  |  |
| `exportPolicyRef` _[LocalObjectRef](#localobjectref)_ | ExportPolicyRef names the BGPPolicy applied to routes sent to the peer<br />in this family. A fabric peer family must resolve one: there is no<br />implicit export-everything default. |  |  |
| `nextHopMode` _[BGPNextHopMode](#bgpnexthopmode)_ | NextHopMode controls the advertised next hop. |  | Enum: [Unchanged Self SelfForce] <br /> |
| `routeReflectorClient` _boolean_ | RouteReflectorClient treats the peer as a route-reflector client in<br />this family. |  |  |
| `frr` _[FRRPeerFamilySettings](#frrpeerfamilysettings)_ | FRR holds FRR-specific settings. |  |  |


#### BGPPeerGracefulRestart



BGPPeerGracefulRestart defines BGP graceful restart parameters for a peer.

Graceful restart (RFC 4724) allows a BGP speaker to restart its control plane
without tearing down sessions. Routes are preserved during the restart period,
preventing MAC/IP flapping in EVPN deployments.



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enabled` _boolean_ | Enabled indicates whether graceful restart is enabled for this peer. |  |  |
| `restartTime` _integer_ | RestartTime is the maximum time (in seconds) the peer expects the<br />local system to complete a graceful restart. Range: 1-1200.<br />Default: 120 seconds. |  | Maximum: 1200 <br />Minimum: 1 <br /> |


#### BGPPeerProfile



BGPPeerProfile is a reusable set of session settings that BGPPeers
reference with spec.peerProfileRef. The FRR implementation renders a
profile as one peer group and each referencing peer as a member. There
is no profile inheritance: a peer's own transport and family settings
override the profile field by field.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPPeerProfile` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPPeerProfileSpec](#bgppeerprofilespec)_ |  |  | Required: \{\} <br /> |
| `status` _[BGPPeerProfileStatus](#bgppeerprofilestatus)_ |  |  |  |


#### BGPPeerProfileFRR



BGPPeerProfileFRR holds FRR rendering settings for a peer profile.



_Appears in:_
- [BGPPeerProfileSpec](#bgppeerprofilespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `peerGroupName` _[FRRObjectName](#frrobjectname)_ | PeerGroupName is the FRR peer group name. When unset the profile's<br />metadata.name is used. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9][A-Za-z0-9_.-]*$` <br /> |


#### BGPPeerProfileSpec



BGPPeerProfileSpec defines a peer profile's settings.



_Appears in:_
- [BGPPeerProfile](#bgppeerprofile)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `frr` _[BGPPeerProfileFRR](#bgppeerprofilefrr)_ | FRR holds FRR rendering settings. |  |  |
| `peerASN` _integer_ | PeerASN, when set, is the remote ASN of every member. A member whose<br />own peerASN differs is rejected. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `transport` _[BGPPeerTransport](#bgppeertransport)_ | Transport holds session transport settings. |  |  |
| `addressFamilies` _[BGPPeerFamilySettings](#bgppeerfamilysettings) array_ | AddressFamilies lists the families a member activates, with their<br />settings. |  | MaxItems: 8 <br /> |


#### BGPPeerProfileStatus



BGPPeerProfileStatus defines the observed state of BGPPeerProfile.



_Appears in:_
- [BGPPeerProfile](#bgppeerprofile)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPPeerSpec



BGPPeerSpec defines the desired state of BGPPeer.



_Appears in:_
- [BGPPeer](#bgppeer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerRef` _[RouterRef](#routerref)_ | RouterRef targets a single BGPRouter by name.<br />Mutually exclusive with routerSelector. |  |  |
| `routerSelector` _[RouterSelector](#routerselector)_ | RouterSelector targets one or more BGPRouters by label.<br />Mutually exclusive with routerRef. |  |  |
| `peerASN` _integer_ | PeerASN is the remote AS number. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `address` _string_ | Address is the remote peer's IPv4 or IPv6 address. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `remotePort` _integer_ | RemotePort is the TCP port used to establish the BGP session with<br />this peer. Defaults to 179 (the IANA-assigned BGP port) if unset. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `description` _string_ | Description is a human-readable label for this peer (e.g., "spine-1"). |  | MaxLength: 80 <br />Pattern: `^[^\r\n]*$` <br /> |
| `authSecretRef` _[LocalSecretRef](#localsecretref)_ | AuthSecretRef references a Secret in the same namespace containing the<br />MD5 TCP authentication password under the key "password". |  |  |
| `addressFamilies` _[AddressFamily](#addressfamily) array_ | AddressFamilies defines the address families negotiated on this session.<br />Required unless peerProfileRef is set; a peer with a profile and no<br />list activates the profile's families, and a list must then be a<br />subset of them. |  | MaxItems: 8 <br />MinItems: 1 <br /> |
| `peerProfileRef` _[LocalObjectRef](#localobjectref)_ | PeerProfileRef names the BGPPeerProfile whose settings this peer<br />uses. Honored by the fabric router implementation only; the Galactic<br />EVPN router rejects a peer that sets it. |  |  |
| `transport` _[BGPPeerTransport](#bgppeertransport)_ | Transport overrides the profile's transport settings field by field.<br />Honored by the fabric router implementation only. |  |  |
| `familySettings` _[BGPPeerFamilySettings](#bgppeerfamilysettings) array_ | FamilySettings holds per-family settings. A field set here overrides<br />the same field in the profile's family. Honored by the fabric router<br />implementation only. |  | MaxItems: 8 <br /> |
| `holdTime` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#duration-v1-meta)_ | HoldTime is the BGP hold timer. Must be 0 (disabled) or >= 3s.<br />Defaults to 90s if unset. |  |  |
| `keepaliveTime` _[Duration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#duration-v1-meta)_ | KeepaliveTime is the BGP keepalive interval. Must be <= HoldTime / 3.<br />Defaults to 30s if unset. Maximum is 30s; the controller enforces<br />the keepalive <= holdTime / 3 constraint with an Accepted=False condition. |  |  |
| `ebgpMultiHop` _boolean_ | EbgpMultiHop enables eBGP multihop when the peer is not directly connected.<br />When true, the TTL for BGP packets is set to 64 (vs. 1 for direct). |  |  |
| `bfd` _[BGPPeerBFD](#bgppeerbfd)_ | BFD configures Bidirectional Forwarding Detection for fast failure<br />detection (sub-500ms). Without BFD, convergence relies on BGP hold<br />timers (default 90s). |  |  |
| `gracefulRestart` _[BGPPeerGracefulRestart](#bgppeergracefulrestart)_ | GracefulRestart configures BGP graceful restart for this peer.<br />Prevents route flapping during control-plane restarts. |  |  |
| `multiSession` _boolean_ | MultiSession enables BFD over MP-BGP (RFC 8935). When true, each<br />AFI/SAFI negotiates its own BFD session independently. When false<br />(default), a single BFD session covers all AFI/SAFIs. |  |  |
| `routeMapIn` _string_ | RouteMapIn is the name of a BGPPolicy term set applied to routes<br />received from this peer (import direction). The name must match<br />a BGPPolicy resource in the same namespace. |  |  |
| `routeMapOut` _string_ | RouteMapOut is the name of a BGPPolicy term set applied to routes<br />advertised to this peer (export direction). The name must match<br />a BGPPolicy resource in the same namespace. |  |  |
| `nextHopSelf` _boolean_ | NextHopSelf controls next-hop behavior for iBGP sessions.<br />When true, the local router's IP is used as next-hop for all<br />advertised routes. Common in EVPN iBGP peering. |  |  |
| `removePrivateAS` _integer_ | RemovePrivateAS strips private AS numbers (64512-65535, 4200000000-4294967294)<br />from the AS path on eBGP export. If set to a non-zero value, private ASNs<br />are replaced with the specified value before export. |  | Minimum: 0 <br /> |
| `updateSource` _string_ | UpdateSource is the local IP address or interface name used as the<br />source for the BGP TCP session. Useful when the local router has<br />multiple addresses or when pinning to a specific loopback. |  | MaxLength: 45 <br /> |
| `sendCommunity` _[SendCommunityType](#sendcommunitytype)_ | SendCommunity controls which BGP community attributes are propagated<br />to this peer. When unset, communities are not sent. |  | Enum: [standard extended large both] <br /> |
| `allowASIn` _integer_ | AllowASIn allows routes that contain the local ASN in the AS_PATH<br />to be accepted from this peer. The value specifies the maximum number<br />of times the local ASN may appear. Range: 1-10. |  | Maximum: 10 <br />Minimum: 1 <br /> |
| `maximumPrefix` _[BGPMaximumPrefix](#bgpmaximumprefix)_ | MaximumPrefix defines the maximum number of routes accepted from this<br />peer before triggering a shutdown action. |  |  |
| `defaultOriginRoute` _[OriginType](#origintype)_ | DefaultOriginRoute controls default route origination for this peer.<br />"igp" originates a default route with IGP origin.<br />"egp" originates a default route with EGP origin.<br />"incomplete" originates a default route with incomplete origin.<br />Empty or unset means no default route origination. |  | Enum: [igp egp incomplete] <br /> |
| `authentication` _[BGPPeerAuthentication](#bgppeerauthentication)_ | Authentication configures peer authentication.<br />AuthSecretRef takes precedence when both are set. |  |  |


#### BGPPeerState

_Underlying type:_ _string_

BGPPeerState represents the BGP Finite State Machine state of a session.



_Appears in:_
- [BGPPeerStatus](#bgppeerstatus)

| Field | Description |
| --- | --- |
| `Idle` |  |
| `Connect` |  |
| `Active` |  |
| `OpenSent` |  |
| `OpenConfirm` |  |
| `Established` |  |


#### BGPPeerStatus



BGPPeerStatus defines the observed state of BGPPeer.



_Appears in:_
- [BGPPeer](#bgppeer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `sessionState` _[BGPPeerState](#bgppeerstate)_ | SessionState is the current BGP FSM state of this session. |  |  |
| `lastEstablishedTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | LastEstablishedTime is the timestamp of the most recent Established transition. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPPeerTransport



BGPPeerTransport holds session transport settings shared by a peer and its
profile. A field set on a BGPPeer overrides the same field on its profile.



_Appears in:_
- [BGPPeerProfileSpec](#bgppeerprofilespec)
- [BGPPeerSpec](#bgppeerspec)
- [FabricSessionSettings](#fabricsessionsettings)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ebgpMultihopTTL` _integer_ | EBGPMultihopTTL allows an eBGP session over up to this many hops.<br />Unset renders no multihop line. |  | Maximum: 255 <br />Minimum: 1 <br /> |
| `advertisementIntervalSeconds` _integer_ | AdvertisementIntervalSeconds is the minimum interval between UPDATE<br />messages. Unset leaves the implementation's default. |  | Maximum: 600 <br />Minimum: 0 <br /> |


#### BGPPolicy



BGPPolicy defines composable, ordered routing policy statements applied to a
BGPRouter in a specific direction (import or export). It binds to one or more
BGPRouter instances via routerRef or routerSelector.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPPolicy` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPPolicySpec](#bgppolicyspec)_ |  |  |  |
| `status` _[BGPPolicyStatus](#bgppolicystatus)_ |  |  |  |


#### BGPPolicyAction

_Underlying type:_ _string_

BGPPolicyAction is the disposition applied when a policy term matches.

_Validation:_
- Enum: [permit deny]

_Appears in:_
- [BGPPolicyTerm](#bgppolicyterm)
- [BGPPrefixListEntry](#bgpprefixlistentry)

| Field | Description |
| --- | --- |
| `permit` | BGPPolicyActionPermit allows the route and optionally applies set actions.<br /> |
| `deny` | BGPPolicyActionDeny drops the route. Set actions must not be specified.<br /> |


#### BGPPolicyDirection

_Underlying type:_ _string_

BGPPolicyDirection is the direction in which a BGPPolicy is applied.

_Validation:_
- Enum: [import export]

_Appears in:_
- [BGPPolicySpec](#bgppolicyspec)

| Field | Description |
| --- | --- |
| `import` | BGPPolicyDirectionImport applies the policy to routes received from peers.<br /> |
| `export` | BGPPolicyDirectionExport applies the policy to routes advertised to peers.<br /> |


#### BGPPolicyFRR



BGPPolicyFRR holds FRR rendering settings for a policy.



_Appears in:_
- [BGPPolicySpec](#bgppolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routeMapName` _[FRRObjectName](#frrobjectname)_ | RouteMapName is the FRR route-map name. When unset the policy's<br />metadata.name is used. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9][A-Za-z0-9_.-]*$` <br /> |


#### BGPPolicyMatch



BGPPolicyMatch defines the conditions under which a policy term fires.



_Appears in:_
- [BGPPolicyTerm](#bgppolicyterm)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `any` _boolean_ | Any matches all routes. When true, all other match fields are ignored. |  |  |
| `addressFamilies` _[AddressFamily](#addressfamily) array_ | AddressFamilies constrains the match to specific AFI/SAFI combinations.<br />If empty, all address families are matched. |  | MaxItems: 8 <br /> |
| `prefixList` _string array_ | PrefixList constrains the match to routes whose prefix matches one of<br />the given CIDR blocks. Each entry must be a valid IPv4 or IPv6 CIDR. |  | MaxItems: 256 <br />items:MaxLength: 43 <br /> |
| `asPathFilter` _[ASPathFilter](#aspathfilter)_ | ASPathFilter matches routes by AS path using a regex pattern.<br />The pattern is matched against the full AS path string (space-separated ASNs). |  |  |
| `communityMatch` _string array_ | CommunityMatch matches routes by BGP community.<br />Each entry is a community string in ASN:NN or IP:NN format. |  | MaxItems: 32 <br />items:MaxLength: 32 <br /> |
| `evpnRouteType` _[EVPNRouteType](#evpnroutetype) array_ | EVPNRouteType matches specific EVPN route types.<br />Only meaningful when l2vpn/evpn address family is configured. |  | Enum: [inclusiveMulticastEthernetTag macIPAdvertisement iPPrefixAdvertisement stickyMACAddress iPv6PrefixAdvertisement] <br />MaxItems: 5 <br /> |
| `vni` _integer_ | VNI matches routes by VNI (VXLAN Network Identifier).<br />Range: 0–16777215 (24-bit VNI). |  | Maximum: 1.6777215e+07 <br />Minimum: 0 <br /> |
| `macAddress` _string_ | MACAddress matches MAC-IP routes (EVPN Type-2) by MAC address.<br />Format: colon-separated hex bytes (e.g., "aa:bb:cc:dd:ee:ff"). |  | Pattern: `^([0-9a-fA-F]\{2\}:)\{5\}[0-9a-fA-F]\{2\}$` <br /> |
| `ipPrefix` _string_ | IPPrefix matches routes by exact IP prefix (CIDR notation). |  | MaxLength: 43 <br /> |
| `localPreference` _integer_ | LocalPreference matches routes by BGP LOCAL_PREF value. |  | Minimum: 0 <br /> |
| `prefixListRef` _[LocalObjectRef](#localobjectref)_ | PrefixListRef matches routes whose prefix the named BGPPrefixList<br />permits. |  |  |
| `communitySetRef` _[LocalObjectRef](#localobjectref)_ | CommunitySetRef matches routes carrying a community the named<br />standard BGPCommunitySet permits. |  |  |
| `largeCommunitySetRef` _[LocalObjectRef](#localobjectref)_ | LargeCommunitySetRef matches routes carrying a large community the<br />named large BGPCommunitySet permits. |  |  |
| `interface` _string_ | Interface matches routes whose interface is the named one. Meaningful<br />only in a policy attached to a redistribution. |  | MaxLength: 15 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9_.@-]+$` <br /> |
| `med` _integer_ | MED matches routes by Multi-Exit Discriminator value. |  | Minimum: 0 <br /> |


#### BGPPolicySetActions



BGPPolicySetActions defines mutations applied when a term matches with action "permit".



_Appears in:_
- [BGPPolicyTerm](#bgppolicyterm)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `communities` _[CommunitySet](#communityset)_ | Communities defines community add/remove operations. |  |  |
| `localPreference` _integer_ | LocalPreference sets the LOCAL_PREF attribute.<br />Only meaningful on import (iBGP) or export to iBGP peers. |  | Minimum: 0 <br /> |
| `origin` _[BGPOrigin](#bgporigin)_ | Origin sets the BGP origin attribute. |  | Enum: [igp egp incomplete] <br /> |
| `asPath` _[AsPathSet](#aspathset)_ | AsPath manipulates the AS path (prepend or replace). |  |  |
| `nextHop` _[NextHopSet](#nexthopset)_ | NextHop overrides the next-hop attribute. |  |  |
| `extCommunities` _[ExtendedCommunitySet](#extendedcommunityset)_ | ExtCommunities defines extended community add/remove operations.<br />Each entry must be in a valid extended community format (ASN:NN, IP:NN,<br />or type-specific like "rt:65000:100"). |  |  |
| `metric` _integer_ | Metric sets the MED (Multi-Exit Discriminator) attribute. |  | Minimum: 0 <br /> |
| `standardCommunities` _[StandardCommunityAction](#standardcommunityaction)_ | StandardCommunities adds to or replaces the route's standard<br />communities. |  |  |
| `largeCommunities` _[LargeCommunityAction](#largecommunityaction)_ | LargeCommunities adds to or replaces the route's large communities,<br />independently of StandardCommunities. |  |  |
| `deleteCommunitySetRef` _[LocalObjectRef](#localobjectref)_ | DeleteCommunitySetRef removes the standard communities the named<br />BGPCommunitySet permits. |  |  |
| `deleteLargeCommunitySetRef` _[LocalObjectRef](#localobjectref)_ | DeleteLargeCommunitySetRef removes the large communities the named<br />BGPCommunitySet permits. |  |  |
| `color` _integer_ | Color sets the SRv6 policy color for path selection. |  | Minimum: 0 <br /> |
| `source` _string_ | Source is the preferred source address of the routes the policy<br />installs in the kernel. It must be in the address family of every<br />peer family or advertisement the policy is attached to. Honored by<br />the fabric router implementation only. |  | MaxLength: 45 <br /> |


#### BGPPolicySpec



BGPPolicySpec defines the desired route policy state.



_Appears in:_
- [BGPPolicy](#bgppolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerRef` _[RouterRef](#routerref)_ | RouterRef targets a single BGPRouter by name.<br />Mutually exclusive with routerSelector. |  |  |
| `routerSelector` _[RouterSelector](#routerselector)_ | RouterSelector targets one or more BGPRouters by label.<br />Mutually exclusive with routerRef. |  |  |
| `direction` _[BGPPolicyDirection](#bgppolicydirection)_ | Direction is the policy direction: import or export. Required when<br />the policy binds to routers through routerRef or routerSelector. A<br />policy without either is a reusable definition whose direction comes<br />from the peer family or advertisement that references it. |  | Enum: [import export] <br /> |
| `frr` _[BGPPolicyFRR](#bgppolicyfrr)_ | FRR holds FRR rendering settings. |  |  |
| `terms` _[BGPPolicyTerm](#bgppolicyterm) array_ | Terms is the ordered list of policy statements.<br />Evaluated from lowest to highest sequence number. |  | MaxItems: 32 <br />MinItems: 1 <br /> |


#### BGPPolicyStatus



BGPPolicyStatus defines the observed state of BGPPolicy.



_Appears in:_
- [BGPPolicy](#bgppolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPPolicyTerm



BGPPolicyTerm is a single ordered policy statement with match conditions and an action.



_Appears in:_
- [BGPPolicySpec](#bgppolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `description` _string_ | Description is a free-text note rendered with the term. |  | MaxLength: 255 <br />Pattern: `^[^\r\n]*$` <br /> |
| `sequence` _integer_ | Sequence is the evaluation order. Lower values are evaluated first.<br />Must be unique within the policy. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `match` _[BGPPolicyMatch](#bgppolicymatch)_ | Match defines the conditions under which this term fires. |  |  |
| `action` _[BGPPolicyAction](#bgppolicyaction)_ | Action is the disposition when this term matches. |  | Enum: [permit deny] <br /> |
| `set` _[BGPPolicySetActions](#bgppolicysetactions)_ | Set defines mutations applied when action is "permit".<br />Must not be set when action is "deny". |  |  |


#### BGPPrefixLimit



BGPPrefixLimit bounds the prefixes a peer may send in one family.



_Appears in:_
- [BGPPeerFamilySettings](#bgppeerfamilysettings)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `maximum` _integer_ | Maximum is the number of prefixes accepted before the action applies. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `warningThresholdPercent` _integer_ | WarningThresholdPercent logs a warning once received prefixes reach<br />this share of maximum. |  | Maximum: 100 <br />Minimum: 1 <br /> |
| `action` _[BGPPrefixLimitAction](#bgpprefixlimitaction)_ | Action is what happens once maximum is exceeded. |  | Enum: [WarnOnly Restart Shutdown] <br /> |
| `restartMinutes` _integer_ | RestartMinutes is the delay before a Restart action re-establishes<br />the session. |  | Maximum: 65535 <br />Minimum: 1 <br /> |


#### BGPPrefixLimitAction

_Underlying type:_ _string_

BGPPrefixLimitAction is what a session does once a family's received
prefixes exceed the limit.

_Validation:_
- Enum: [WarnOnly Restart Shutdown]

_Appears in:_
- [BGPPrefixLimit](#bgpprefixlimit)

| Field | Description |
| --- | --- |
| `WarnOnly` | BGPPrefixLimitWarnOnly logs and keeps the session up.<br /> |
| `Restart` | BGPPrefixLimitRestart shuts the session down and restarts it after<br />restartMinutes.<br /> |
| `Shutdown` | BGPPrefixLimitShutdown shuts the session down until it is cleared.<br /> |


#### BGPPrefixListEntry



BGPPrefixListEntry defines a single entry in a named BGP prefix-list.
Entries are evaluated in ascending sequence order.

GE and LE bound the matched prefix length. Both are limited by the
entry's family (32 for IPv4, 128 for IPv6), GE may not be shorter than
the prefix's own length, and LE may not be shorter than GE (or the
prefix's length when GE is unset): FRR's own rule, mask length <= ge <= le.
A malformed prefix is reported by the prefix field's rule alone.



_Appears in:_
- [BGPPrefixListSpec](#bgpprefixlistspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `sequence` _integer_ | Sequence is the evaluation order for this entry. Entries with lower<br />sequence numbers are evaluated first. Must be unique within the list.<br />The range is FRR's: 1 to 4294967295. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `action` _[BGPPolicyAction](#bgppolicyaction)_ | Action is the disposition when a route's prefix matches this entry. |  | Enum: [permit deny] <br />Required: \{\} <br /> |
| `prefix` _string_ | Prefix is the IPv4 or IPv6 CIDR to match against. |  | MaxLength: 43 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `ge` _integer_ | GE is the minimum prefix-length to match (greater-than-or-equal).<br />For example, "10.0.0.0/8 ge 16" matches lengths /16 through /32, and<br />"2607:ed40:8003::/48 ge 49" lengths /49 through /128.<br />When unset, the prefix-length of Prefix is the lower bound. |  | Maximum: 128 <br />Minimum: 0 <br /> |
| `le` _integer_ | LE is the maximum prefix-length to match (less-than-or-equal).<br />For example, "10.0.0.0/8 le 24" matches 10.0.0.0/8 through 10.0.0.0/24.<br />When unset, the prefix-length of Prefix is the upper bound, unless GE<br />is set, in which case the family's maximum length is. |  | Maximum: 128 <br />Minimum: 0 <br /> |






#### BGPRouter



BGPRouter defines a logical BGP routing context. It abstracts a processing
instance bound to a specific execution context (e.g., a VRF or network
namespace) on a target node and acts as the primary ownership boundary for
BGPPeer, BGPAdvertisement, and BGPPolicy resources.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPRouter` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPRouterSpec](#bgprouterspec)_ |  |  |  |
| `status` _[BGPRouterStatus](#bgprouterstatus)_ |  |  |  |


#### BGPRouterClass



BGPRouterClass names the implementation that owns the BGPRouters
referencing it, the way a GatewayClass or StorageClass does. Selecting a
class is what lets several routing implementations coexist on one node:
each acts only on routers of its own classes.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPRouterClass` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPRouterClassSpec](#bgprouterclassspec)_ |  |  |  |
| `status` _[BGPRouterClassStatus](#bgprouterclassstatus)_ |  |  |  |


#### BGPRouterClassParametersRef



BGPRouterClassParametersRef references a cluster-scoped parameters object.



_Appears in:_
- [BGPRouterClassSpec](#bgprouterclassspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `group` _string_ | Group is the API group of the parameters object. |  | MaxLength: 253 <br /> |
| `kind` _string_ | Kind is the kind of the parameters object. |  | MaxLength: 63 <br />MinLength: 1 <br /> |
| `name` _string_ | Name is the name of the parameters object. |  | MaxLength: 253 <br />MinLength: 1 <br /> |


#### BGPRouterClassSpec



BGPRouterClassSpec defines the implementation behind a BGPRouterClass.



_Appears in:_
- [BGPRouterClass](#bgprouterclass)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `controllerName` _string_ | ControllerName identifies the controller that owns routers of this<br />class, as a domain-prefixed path. Immutable. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/[A-Za-z0-9][-A-Za-z0-9_./]*$` <br />Required: \{\} <br /> |
| `parametersRef` _[BGPRouterClassParametersRef](#bgprouterclassparametersref)_ | ParametersRef references the implementation's parameters for routers<br />of this class, such as FRRRouterParameters. Immutable: a parameter<br />change is a new parameters object referenced by a new class. |  |  |


#### BGPRouterClassStatus



BGPRouterClassStatus is the observed state of a BGPRouterClass, written by
its controller.



_Appears in:_
- [BGPRouterClass](#bgprouterclass)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPRouterFRR



BGPRouterFRR holds FRR settings for one router.



_Appears in:_
- [BGPRouterSpec](#bgprouterspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `rolloutPolicyRef` _[LocalObjectRef](#localobjectref)_ | RolloutPolicyRef names the FabricRolloutPolicy the rollout manager<br />applies to this router. Unset uses the policy defaults. |  |  |
| `retain` _[BGPRouterFRRRetain](#bgprouterfrrretain)_ | Retain lists definitions rendered on this router even when no peer<br />or advertisement references them, so a migrated router's first<br />configuration matches the one it replaces. Retained definitions never<br />create sessions or advertisements. |  |  |


#### BGPRouterFRRRetain



BGPRouterFRRRetain names definitions to render while unreferenced.



_Appears in:_
- [BGPRouterFRR](#bgprouterfrr)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRefs` _[LocalObjectRef](#localobjectref) array_ | PolicyRefs names BGPPolicies. |  | MaxItems: 256 <br /> |
| `prefixListRefs` _[LocalObjectRef](#localobjectref) array_ | PrefixListRefs names BGPPrefixLists. |  | MaxItems: 256 <br /> |
| `communitySetRefs` _[LocalObjectRef](#localobjectref) array_ | CommunitySetRefs names BGPCommunitySets. |  | MaxItems: 512 <br /> |
| `peerProfileRefs` _[LocalObjectRef](#localobjectref) array_ | PeerProfileRefs names BGPPeerProfiles. |  | MaxItems: 64 <br /> |


#### BGPRouterFabricStatus



BGPRouterFabricStatus is the fabric router controller's view of a router.



_Appears in:_
- [BGPRouterStatus](#bgprouterstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `latestRevision` _string_ | LatestRevision is the newest FabricRouterRevision compiled for the<br />router's current inputs. |  |  |
| `activationDependencyDigest` _string_ | ActivationDependencyDigest is that revision's digest. |  |  |
| `renderedDigest` _string_ | RenderedDigest is the SHA-256 of the frr.conf that revision renders. |  |  |


#### BGPRouterPeerSummary



BGPRouterPeerSummary summarizes BGP peer session counts.



_Appears in:_
- [BGPRouterStatus](#bgprouterstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `total` _integer_ | Total is the total number of configured peers. |  |  |
| `established` _integer_ | Established is the count of peers currently in the Established state. |  |  |


#### BGPRouterPhase

_Underlying type:_ _string_

BGPRouterPhase describes the lifecycle phase of a BGPRouter.



_Appears in:_
- [BGPRouterStatus](#bgprouterstatus)

| Field | Description |
| --- | --- |
| `Pending` |  |
| `Ready` |  |
| `Failed` |  |


#### BGPRouterSpec



BGPRouterSpec defines the desired state of a BGPRouter.



_Appears in:_
- [BGPRouter](#bgprouter)
- [FabricRouterConfiguration](#fabricrouterconfiguration)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerClassName` _string_ | RouterClassName names the BGPRouterClass whose controller owns this<br />router. A router without one is owned by the Galactic EVPN<br />implementation (galactic-router and its related controllers). A<br />router naming a class is ignored by every component except that<br />class's controller, and by every component when the class does not<br />exist. Immutable. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `plane` _[BGPRoutingPlane](#bgproutingplane)_ | Plane is the routing plane this router belongs to. Unset means the<br />tenant EVPN overlay. Underlay requires a routerClassName. Immutable. |  | Enum: [Underlay Overlay] <br /> |
| `frr` _[BGPRouterFRR](#bgprouterfrr)_ | FRR holds settings for routers whose class is implemented with FRR. |  |  |
| `targetRef` _[TargetRef](#targetref)_ | TargetRef identifies the Node this router executes on. |  | Required: \{\} <br /> |
| `localASN` _integer_ | LocalASN is the BGP Autonomous System Number for this router.<br />Must be a valid 2-byte or 4-byte ASN per RFC 6793. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `routerID` _string_ | RouterID is a unique 32-bit identifier expressed in IPv4 dotted-decimal notation.<br />In an IPv6-only underlay this is a logical identifier only. |  | Format: ipv4 <br />Required: \{\} <br /> |
| `addressFamilies` _[AddressFamily](#addressfamily) array_ | AddressFamilies defines the address families this router activates. |  | MinItems: 1 <br /> |
| `srv6Locator` _string_ | SRv6Locator is the SRv6 locator block this router owns, expressed as an<br />IPv6 CIDR (e.g. "2001:db8:ff01::/48"). Individual SRv6 endpoint SIDs are<br />host addresses within this block. |  |  |
| `nodeID` _integer_ | NodeID is this router's 16-bit slot within its PoP's SRv6Locator block,<br />used for RFC 9800 NEXT-CSID compression. Unique within the PoP.<br />The uSID carrier format reserves 0x0000 and 0xE000-0xFFFF (the latter is<br />Function space, not Node-ID space), leaving 0x0001-0xDFFF assignable. |  | Maximum: 57343 <br />Minimum: 1 <br /> |
| `listenPort` _integer_ | ListenPort is the TCP port this router listens on for incoming BGP<br />peer connections. Defaults to 179 (the IANA-assigned BGP port) if unset. |  | Maximum: 65535 <br />Minimum: 1 <br /> |


#### BGPRouterStatus



BGPRouterStatus defines the observed state of a BGPRouter.



_Appears in:_
- [BGPRouter](#bgprouter)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `supportsAdvertisementLeases` _boolean_ | SupportsAdvertisementLeases reports independent expiry enforcement by the router.<br />Consumers must also require current observedGeneration and a healthy router. |  |  |
| `lastSuccessfulReconcileTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | LastSuccessfulReconcileTime is the last healthy apply or verified no-op reconciliation. |  |  |
| `phase` _[BGPRouterPhase](#bgprouterphase)_ | Phase is the high-level lifecycle state of this router. |  |  |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `peers` _[BGPRouterPeerSummary](#bgprouterpeersummary)_ | Peers summarizes peer session counts. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |
| `fabric` _[BGPRouterFabricStatus](#bgprouterfabricstatus)_ | Fabric is the fabric router controller's view of a classed router.<br />Unset on routers the Galactic EVPN implementation owns. |  |  |


#### BGPRoutingPlane

_Underlying type:_ _string_

BGPRoutingPlane names which routing plane a BGPRouter belongs to.

_Validation:_
- Enum: [Underlay Overlay]

_Appears in:_
- [BGPRouterSpec](#bgprouterspec)

| Field | Description |
| --- | --- |
| `Underlay` | BGPRoutingPlaneUnderlay is the fabric underlay that carries the<br />overlay's sessions and SRv6 locators between nodes.<br /> |
| `Overlay` | BGPRoutingPlaneOverlay is the tenant EVPN overlay.<br /> |


#### BGPStaticRoute



BGPStaticRoute installs one static route in a router's default routing
instance. Installing a route never advertises it: advertisement is a
separate BGPAdvertisement, and an aggregate never creates a discard route.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPStaticRoute` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPStaticRouteSpec](#bgpstaticroutespec)_ |  |  | Required: \{\} <br /> |
| `status` _[BGPStaticRouteStatus](#bgpstaticroutestatus)_ |  |  |  |


#### BGPStaticRouteAction

_Underlying type:_ _string_

BGPStaticRouteAction is what a static route does with matching traffic.

_Validation:_
- Enum: [Discard NextHop]

_Appears in:_
- [BGPStaticRouteSpec](#bgpstaticroutespec)

| Field | Description |
| --- | --- |
| `Discard` | BGPStaticRouteDiscard drops matching traffic (FRR's Null0).<br /> |
| `NextHop` | BGPStaticRouteNextHop forwards matching traffic to nextHop.<br /> |


#### BGPStaticRouteSpec



BGPStaticRouteSpec defines one static route.



_Appears in:_
- [BGPStaticRoute](#bgpstaticroute)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerRef` _[RouterRef](#routerref)_ | RouterRef names the BGPRouter whose routing instance holds the route. |  |  |
| `addressFamily` _[AFI](#afi)_ | AddressFamily is the route's family: ipv4 or ipv6. |  | Enum: [ipv4 ipv6 l2vpn] <br /> |
| `destination` _string_ | Destination is the route's prefix in CIDR notation. |  | MaxLength: 43 <br />MinLength: 1 <br /> |
| `action` _[BGPStaticRouteAction](#bgpstaticrouteaction)_ | Action is what the route does with matching traffic. |  | Enum: [Discard NextHop] <br /> |
| `nextHop` _string_ | NextHop is the gateway address for action NextHop. |  | MaxLength: 45 <br /> |


#### BGPStaticRouteStatus



BGPStaticRouteStatus defines the observed state of BGPStaticRoute.



_Appears in:_
- [BGPStaticRoute](#bgpstaticroute)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### BGPVRFInstance



BGPVRFInstance configures an L2VPN EVPN VRF on matched BGPRouters.
The referenced BGPRouter must have l2vpn-evpn in its addressFamilies.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `BGPVRFInstance` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BGPVRFInstanceSpec](#bgpvrfinstancespec)_ |  |  |  |
| `status` _[BGPVRFInstanceStatus](#bgpvrfinstancestatus)_ |  |  |  |


#### BGPVRFInstanceSpec



BGPVRFInstanceSpec defines the desired VRF configuration.



_Appears in:_
- [BGPVRFInstance](#bgpvrfinstance)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerRef` _[RouterRef](#routerref)_ | RouterRef targets a single BGPRouter by name.<br />Mutually exclusive with routerSelector. |  |  |
| `routerSelector` _[RouterSelector](#routerselector)_ | RouterSelector targets one or more BGPRouters by label.<br />Mutually exclusive with routerRef. |  |  |
| `vrfID` _integer_ | VRFID is the 16-bit PoP-local VRF identifier used for RFC 9800 uSID<br />Argument addressing and to derive the RFC 4364 Type 1 Route<br />Distinguisher ("routerID:vrfID"). Unique per (VPC, PoP). Value 0 is<br />reserved. |  | Maximum: 65535 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `importRouteTargets` _[RouteTarget](#routetarget) array_ | ImportRouteTargets is the list of BGP extended community route targets<br />used to import routes into this VRF. |  | MaxItems: 32 <br />MinItems: 1 <br /> |
| `exportRouteTargets` _[RouteTarget](#routetarget) array_ | ExportRouteTargets is the list of BGP extended community route targets<br />attached to routes exported from this VRF. |  | MaxItems: 32 <br />MinItems: 1 <br /> |
| `nptv6` _[NPTv6Spec](#nptv6spec)_ | NPTv6 configures stateless RFC 6296 Network Prefix Translation for<br />this VRF: backends presenting an address within ULAPrefix are<br />translated, checksum-neutrally and bidirectionally, to the<br />corresponding address in PublicPrefix. Unset means this VRF's traffic<br />crosses the SRv6 fabric with its own ULA source/destination<br />unmodified — the common case. Keyed by this VRFID, never by address,<br />specifically so two VRFs may configure the identical ULAPrefix (e.g.<br />both using the same private range) without collision — each VRF's<br />mapping is independent, looked up only after this VRF's own identity<br />is already resolved from the SRv6 uSID Argument, never derived from<br />address content alone. |  |  |


#### BGPVRFInstanceStatus



BGPVRFInstanceStatus defines the observed state of BGPVRFInstance.



_Appears in:_
- [BGPVRFInstance](#bgpvrfinstance)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are top-level conditions for this BGPVRFInstance. |  |  |
| `routers` _[RouterStatus](#routerstatus) array_ | Routers holds per-router reconciliation status. |  |  |


#### BMPConnect



BMPConnect is where FRR opens a BMP session.



_Appears in:_
- [BMPTarget](#bmptarget)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `address` _string_ | Address is the collector's IP address. |  | MaxLength: 45 <br /> |
| `port` _integer_ | Port is the collector's TCP port. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `minRetryMilliseconds` _integer_ | MinRetryMilliseconds is the shortest reconnect backoff. FRR's bmp<br />connect command needs at least one backoff and fills in its default<br />for the other: 30000 for this one, 720000 for the longest. |  | Maximum: 8.64e+07 <br />Minimum: 100 <br /> |
| `maxRetryMilliseconds` _integer_ | MaxRetryMilliseconds is the longest reconnect backoff. |  | Maximum: 8.64e+07 <br />Minimum: 100 <br /> |
| `sourceInterface` _string_ | SourceInterface is the local interface whose address the session is<br />sourced from. Unset lets the kernel choose the source address. |  | MaxLength: 15 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9_.@-]+$` <br /> |


#### BMPMonitor



BMPMonitor streams one family's RIB to a BMP target.



_Appears in:_
- [BMPTarget](#bmptarget)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `afi` _[AFI](#afi)_ | AFI is the address family indicator. |  | Enum: [ipv4 ipv6 l2vpn] <br /> |
| `safi` _[SAFI](#safi)_ | SAFI is the subsequent address family indicator. |  | Enum: [unicast evpn] <br /> |
| `mode` _[BMPMonitorMode](#bmpmonitormode)_ | Mode selects the RIB. |  | Enum: [LocRIB PrePolicy PostPolicy] <br /> |


#### BMPMonitorMode

_Underlying type:_ _string_

BMPMonitorMode selects which RIB a BMP target streams.

_Validation:_
- Enum: [LocRIB PrePolicy PostPolicy]

_Appears in:_
- [BMPMonitor](#bmpmonitor)

| Field | Description |
| --- | --- |
| `LocRIB` | BMPMonitorLocRIB streams the selected routes (`loc-rib`).<br /> |
| `PrePolicy` | BMPMonitorPrePolicy streams Adj-RIB-In before import policy.<br /> |
| `PostPolicy` | BMPMonitorPostPolicy streams Adj-RIB-In after import policy.<br /> |


#### BMPTarget



BMPTarget is one `bmp targets` block.



_Appears in:_
- [FRRRouterParametersSpec](#frrrouterparametersspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _[FRRObjectName](#frrobjectname)_ | Name is the target's FRR name. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9][A-Za-z0-9_.-]*$` <br /> |
| `connect` _[BMPConnect](#bmpconnect)_ | Connect is the collector this target streams to. |  |  |
| `statsIntervalMilliseconds` _integer_ | StatsIntervalMilliseconds is how often the target sends BMP<br />statistics reports. Unset sends none. |  | Maximum: 8.64e+07 <br />Minimum: 100 <br /> |
| `monitors` _[BMPMonitor](#bmpmonitor) array_ | Monitors lists the RIBs streamed. |  | MaxItems: 6 <br />MinItems: 1 <br /> |


#### BackendHealthState

_Underlying type:_ _string_

BackendHealthState is a backend's health decision.

_Validation:_
- Enum: [Healthy Unhealthy Unknown]

_Appears in:_
- [ServiceEndpointProducerStatus](#serviceendpointproducerstatus)
- [ServiceVIPBindingHealth](#servicevipbindinghealth)

| Field | Description |
| --- | --- |
| `Healthy` | BackendHealthHealthy: the last HealthyThreshold probes succeeded.<br /> |
| `Unhealthy` | BackendHealthUnhealthy: the last UnhealthyThreshold probes failed. Only<br />this state filters a backend with FailOpen; FailClosed also filters<br />Unknown, missing and expired decisions.<br /> |
| `Unknown` | BackendHealthUnknown: too few probes have completed to decide, or the<br />probe cannot run on the backend's node.<br /> |


#### Community

_Underlying type:_ _string_

Community is a BGP community in ASN:NN or IP:NN format.

_Validation:_
- MaxLength: 32

_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)



#### CommunityOperation

_Underlying type:_ _string_

CommunityOperation is how a community action combines with the route's
existing communities.

_Validation:_
- Enum: [Add Replace]

_Appears in:_
- [LargeCommunityAction](#largecommunityaction)
- [StandardCommunityAction](#standardcommunityaction)

| Field | Description |
| --- | --- |
| `Add` | CommunityOperationAdd keeps the route's communities and adds values.<br /> |
| `Replace` | CommunityOperationReplace replaces the route's communities with values.<br /> |


#### CommunitySet



CommunitySet defines community add and remove operations.



_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `add` _string array_ | Add is a list of communities to attach. |  | MaxItems: 32 <br />items:MaxLength: 24 <br /> |
| `remove` _string array_ | Remove is a list of communities to strip. |  | MaxItems: 32 <br />items:MaxLength: 24 <br /> |


#### EVPNRouteType

_Underlying type:_ _string_

EVPNRouteType is an EVPN route type per RFC 7432.

_Validation:_
- Enum: [inclusiveMulticastEthernetTag macIPAdvertisement iPPrefixAdvertisement stickyMACAddress iPv6PrefixAdvertisement]

_Appears in:_
- [BGPPolicyMatch](#bgppolicymatch)

| Field | Description |
| --- | --- |
| `inclusiveMulticastEthernetTag` | EVPNRouteTypeInclusiveMulticastEthernetTag is Type-1: Inclusive Multicast Ethernet Tag route.<br /> |
| `macIPAdvertisement` | EVPNRouteTypeMACIPAdvertisement is Type-2: MAC-IP Advertisement route.<br /> |
| `iPPrefixAdvertisement` | EVPNRouteTypeIPPrefixAdvertisement is Type-3: IP Prefix Advertisement route.<br /> |
| `stickyMACAddress` | EVPNRouteTypeStickyMACAddress is Type-4: Sticky MAC Address route.<br /> |
| `iPv6PrefixAdvertisement` | EVPNRouteTypeIPv6PrefixAdvertisement is Type-5: IPv6 Prefix Advertisement route.<br /> |


#### EgressShard



EgressShard marks a single node as a member of the sharded, stateful egress
translation tier (galactic-nat) — a component deliberately kept off the
ingress load-balancer's own consistent-hash ring (see NetworkGateway):
tenant egress traffic (backend -> arbitrary internet destination) is a
different traffic pattern from ingress (fixed VIP, fixed backend pool)
and needs its own placement ring, own per-flow state, and its own
self-routing return path, entirely independent of any NetworkGateway node.

A shard serves one or both address families. NAT66 (IPv6 -> IPv6) and NAT64
(IPv6 -> IPv4, RFC 6146) are the same function — stateful egress PAT with a
VRF-scoped session table — over different families, so one shard object
describes both rather than there being a second, near-duplicate kind.
Spec.ShardAddressIPv6 and Spec.ShardAddressIPv4 are each assigned only for
the family this shard translates; a shard with no IPv4 address performs no
NAT64.

Every shard owns a dedicated, publicly-routable address per family it
serves, and a flow's allocated masquerade port lives within it — so a reply
is delivered to the correct shard by ordinary unicast routing alone, with
no hashing or cross-shard lookup on the return path at all (the "any node
can determine the owning shard from the tuple alone" property, satisfied by
construction rather than by a replicated hash table).

A shard is told which addresses to translate to; it does not choose them.
The controller that owns a cell claims one address per family from the
addressing service and writes it into this spec, which keeps the
addressing-service credential off every translating node and keeps the
allocation request out of the path that attaches a workload. Status reports
what the node's datapath is actually programmed with, so an unclaimed
address, a stale datapath, and a divergence between the two are each
distinguishable.

A shard names nothing that selects it. Which shards serve which consumer
intent is decided entirely by label selectors evaluated on the selecting
side (see the LabelEgressShard* keys), so no consumer-facing API appears in
this group and no reference points from a datapath resource back at the
resource that placed traffic on it.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EgressShard` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EgressShardSpec](#egressshardspec)_ |  |  |  |
| `status` _[EgressShardStatus](#egressshardstatus)_ |  |  |  |


#### EgressShardSpec



EgressShardSpec defines the desired state of an EgressShard.

The address fields are written by the controller that owns the cell, not by
the shard and not by a consumer. Each is optional: an address the addressing
service has not yet handed out is absent rather than blank-but-required, so
a shard object exists from the moment its node is labelled and gains its
identity afterwards.

Each is also write-once, and cannot be unassigned once assigned. The
datapath claims a reply by exact match against the address it translates to,
so reassigning one strands the return traffic of every flow already
established through it, with no drain and no dual-address grace period
available to cover the change. A shard holding the wrong address is deleted
and recreated instead, which breaks those flows at a moment someone chose.

A claim reference alongside an address records where that address came from,
and is write-once on the same terms. It is deliberately not required with an
address, in either direction. Requiring an address before a claim reference
would forbid recording a claim whose allocation has not resolved yet, which
is the window a restarting controller most needs to see so that it finds the
claim it already made instead of making a second one. Requiring a claim
reference before an address would forbid an address allocated by hand, and
whether such an address may be recorded here at all is an open migration
question this validation would answer by fiat. An address with no reference
is therefore accepted and is unattributable, which is a fact about the
allocation rather than something a schema can repair.



_Appears in:_
- [EgressShard](#egressshard)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRef` _[TargetRef](#targetref)_ | TargetRef identifies the Node this shard executes on. |  | Required: \{\} <br /> |
| `shardSID` _string_ | ShardSID is this shard's own SRv6 uSID, the outer destination a tenant<br />VRF's egress route encapsulates toward. The shard claims a packet by its<br />Block and Node-ID alone, the Argument carrying the tenant, so those 64<br />bits must be reserved for this shard and disjoint from every BGPRouter<br />locator: a value another node already uses silently diverts that node's<br />traffic.<br />Write-once for the same reason the addresses are: every established<br />flow's reply is re-encapsulated from this SID, so changing it strands<br />them. Operator-chosen until the addressing service hands out identifiers<br />of this kind.<br />Empty means no SID is assigned yet, and the shard claims no packet. |  |  |
| `shardAddressIPv6` _string_ | ShardAddressIPv6 is the dedicated, publicly-routable IPv6 address this<br />shard translates to — every NAT66 masquerade port it allocates lives<br />within this address, so any node can route a reply to the owning shard<br />using ordinary unicast routing on it alone, with no per-flow state<br />lookup anywhere but that shard.<br />Empty means no IPv6 address is assigned to this shard. |  |  |
| `shardAddressIPv6ClaimRef` _[AddressClaimRef](#addressclaimref)_ | ShardAddressIPv6ClaimRef records the addressing-service claim<br />ShardAddressIPv6 came from — see AddressClaimRef. Set it in the same<br />write as the address whenever that address came from a claim.<br />Nothing here resolves it and no component reads it to program anything;<br />it is the only trail from a translating address back to the allocation<br />accountable for it. |  |  |
| `shardAddressIPv4` _string_ | ShardAddressIPv4 is the dedicated, publicly-routable IPv4 address this<br />shard translates to, and the source an IPv4-only destination sees.<br />Unlike ShardAddressIPv6, reachability for it is not established by a<br />BGPAdvertisement into the EVPN fabric: an IPv4 reply arrives from the<br />internet, so the underlay or an upstream announcement must attract this<br />address to this node.<br />Empty means no IPv4 address is assigned to this shard. |  |  |
| `shardAddressIPv4ClaimRef` _[AddressClaimRef](#addressclaimref)_ | ShardAddressIPv4ClaimRef records the addressing-service claim<br />ShardAddressIPv4 came from — see AddressClaimRef. Set it in the same<br />write as the address whenever that address came from a claim.<br />Nothing here resolves it and no component reads it to program anything;<br />it is the only trail from a translating address back to the allocation<br />accountable for it. |  |  |
| `nat64Prefix` _string_ | NAT64Prefix is the IPv6 prefix whose synthesized addresses this shard<br />translates to IPv4 — a Datum-operated Network-Specific Prefix, shared<br />fabric-wide, never per-tenant. TranslateWellKnownPrefix adds the RFC 6052<br />Well-Known Prefix alongside it. It must be the prefix the resolver<br />synthesizes into; a shard translating for a different one is a<br />blackhole with no symptom on either side.<br />Set together with ShardAddressIPv4 or not at all: an address with no<br />prefix has nothing to translate for, and a prefix with no address has<br />nothing to translate into. Write-once for the same reason the addresses<br />are: a shard that starts translating a different prefix blackholes every<br />destination the resolver already synthesized into the old one. |  |  |
| `translateWellKnownPrefix` _boolean_ | TranslateWellKnownPrefix additionally translates destinations inside the<br />RFC 6052 Well-Known Prefix 64:ff9b::/96 to IPv4 from ShardAddressIPv4, so<br />clients using a public DNS64 resolver reach IPv4 destinations. Requires<br />NAT64Prefix.<br />RFC 6052 §3.1 forbids the Well-Known Prefix from representing non-global<br />IPv4 addresses; the implementation must refuse such destinations.<br />Mutable, unlike NAT64Prefix. Disabling it blackholes every destination<br />clients already resolved into the Well-Known Prefix until their DNS TTLs<br />expire. |  |  |
| `drain` _boolean_ | Drain stops this shard from taking new tenants while it keeps serving<br />the ones it has. Compute nodes that spread egress across a cluster's<br />shards give a draining shard no share of new tenant addresses, but keep<br />sending it every flow already pinned to it until that flow goes idle, so<br />established sessions finish where their translation state lives.<br />It changes nothing on the shard itself: the shard keeps translating,<br />advertising its SID and receiving replies. A shard is safe to remove<br />once its session count has fallen to zero. Clearing it puts the shard<br />back into rotation.<br />Compute nodes that send each tenant to a single configured shard ignore<br />it. |  |  |


#### EgressShardStatus



EgressShardStatus defines the observed state of an EgressShard.

The address and prefix fields report what this node's datapath is programmed
with, not what it was asked for. A value here that disagrees with the spec is
a shard that has not converged; a value here with no counterpart in the spec
is a shard still translating to an address nothing assigns any more.



_Appears in:_
- [EgressShard](#egressshard)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `shardSID` _string_ | ShardSID is this shard's own uSID locator — a real SRv6 uSID (unlike<br />the ShardAddress fields, which are plain routable addresses),<br />advertised into BGP the same way any other node-reachability route is<br />(a /128 BGPAdvertisement, no VRFID/Function) so every other node learns<br />a kernel SEG6 route toward it before installing a tenant VRF's egress<br />route against it. One SID serves both families: which translation a<br />packet gets is decided from the inner destination, not from a second<br />SID.<br />Reports the SID this node's datapath is programmed with, from<br />Spec.ShardSID. |  |  |
| `shardAddressIPv6` _string_ | ShardAddressIPv6 is the IPv6 masquerade source this shard's datapath is<br />programmed with. Empty means it translates no IPv6 flow. |  |  |
| `shardAddressIPv4` _string_ | ShardAddressIPv4 is the IPv4 masquerade source this shard's datapath is<br />programmed with. Empty means it performs no NAT64. Publishing it is also<br />what makes the underlay reachability prerequisite in<br />Spec.ShardAddressIPv4 checkable. |  |  |
| `nat64Prefix` _string_ | NAT64Prefix is the prefix this shard's datapath is programmed to<br />translate. Empty whenever ShardAddressIPv4 is empty. |  |  |
| `translatesWellKnownPrefix` _boolean_ | TranslatesWellKnownPrefix reports whether this shard's datapath is<br />programmed to translate the RFC 6052 Well-Known Prefix 64:ff9b::/96, from<br />Spec.TranslateWellKnownPrefix. False whenever ShardAddressIPv4 is empty. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource,<br />including Programmed (see ConditionTypeProgrammed). |  |  |


#### ExtendedCommunitySet



ExtendedCommunitySet defines extended community add and remove operations.



_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `add` _string array_ | Add is a list of extended communities to attach. |  | MaxItems: 32 <br />items:MaxLength: 64 <br /> |
| `remove` _string array_ | Remove is a list of extended communities to strip. |  | MaxItems: 32 <br />items:MaxLength: 64 <br /> |


#### FRRDefaultsProfile

_Underlying type:_ _string_

FRRDefaultsProfile is FRR's `frr defaults` profile.

_Validation:_
- Enum: [traditional datacenter]

_Appears in:_
- [FRRRouterParametersSpec](#frrrouterparametersspec)

| Field | Description |
| --- | --- |
| `traditional` | FRRDefaultsTraditional is FRR's traditional defaults profile.<br /> |
| `datacenter` | FRRDefaultsDatacenter is FRR's datacenter defaults profile.<br /> |


#### FRRLogFile



FRRLogFile is FRR's `log file` setting.



_Appears in:_
- [FRRRouterParametersSpec](#frrrouterparametersspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `path` _string_ | Path is the log file's absolute path in the router container. |  | MaxLength: 255 <br />MinLength: 2 <br />Pattern: `^/[^\s]*$` <br /> |
| `level` _[FRRLogLevel](#frrloglevel)_ | Level is the lowest level written. |  | Enum: [emergencies alerts critical errors warnings notifications informational debugging] <br /> |


#### FRRLogLevel

_Underlying type:_ _string_

FRRLogLevel is an FRR syslog level.

_Validation:_
- Enum: [emergencies alerts critical errors warnings notifications informational debugging]

_Appears in:_
- [FRRLogFile](#frrlogfile)
- [FRRRouterParametersSpec](#frrrouterparametersspec)

| Field | Description |
| --- | --- |
| `debugging` |  |


#### FRRNameOverride



FRRNameOverride sets the name an object renders under in FRR. When unset
the object's metadata.name is used.



_Appears in:_
- [BGPCommunitySetSpec](#bgpcommunitysetspec)
- [BGPPrefixListSpec](#bgpprefixlistspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _[FRRObjectName](#frrobjectname)_ | Name is the FRR object name. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9][A-Za-z0-9_.-]*$` <br /> |


#### FRRObjectName

_Underlying type:_ _string_

FRRObjectName is the name an object renders under in FRR: a route-map,
prefix-list, community-list or peer group. The fleet's legacy names are
letters, digits, '-' and '_'; '.' is also accepted.

_Validation:_
- MaxLength: 63
- MinLength: 1
- Pattern: `^[A-Za-z0-9][A-Za-z0-9_.-]*$`

_Appears in:_
- [BGPPeerProfileFRR](#bgppeerprofilefrr)
- [BGPPolicyFRR](#bgppolicyfrr)
- [BMPTarget](#bmptarget)
- [FRRNameOverride](#frrnameoverride)



#### FRRPeerFamilySettings



FRRPeerFamilySettings holds FRR-specific peer family settings with no
implementation-neutral equivalent.



_Appears in:_
- [BGPPeerFamilySettings](#bgppeerfamilysettings)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `weight` _integer_ | Weight is FRR's local, non-propagated path preference for routes<br />learned from the peer. It is not LOCAL_PREF. |  | Maximum: 65535 <br />Minimum: 0 <br /> |


#### FRRRouterParameters



FRRRouterParameters holds the FRR implementation settings a
BGPRouterClass applies to every router of the class: daemon-wide lines
that are not routing intent. Its spec is immutable, so a revision's
parameters stay reproducible; a new parameter set is a new object.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FRRRouterParameters` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FRRRouterParametersSpec](#frrrouterparametersspec)_ |  |  | Required: \{\} <br /> |
| `status` _[FRRRouterParametersStatus](#frrrouterparametersstatus)_ |  |  |  |


#### FRRRouterParametersSpec



FRRRouterParametersSpec defines FRR implementation settings.



_Appears in:_
- [FRRRouterParameters](#frrrouterparameters)
- [FabricRouterConfiguration](#fabricrouterconfiguration)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `defaultsProfile` _[FRRDefaultsProfile](#frrdefaultsprofile)_ | DefaultsProfile is the `frr defaults` profile. Changing a router's<br />profile restarts bgpd. |  | Enum: [traditional datacenter] <br /> |
| `hostnameSuffix` _string_ | HostnameSuffix is appended to the bound Node's name to form the<br />router hostname. |  | MaxLength: 63 <br />Pattern: `^[A-Za-z0-9.-]*$` <br /> |
| `logFile` _[FRRLogFile](#frrlogfile)_ | LogFile is FRR's log file. Unset renders no log file line. |  |  |
| `logSyslog` _[FRRLogLevel](#frrloglevel)_ | LogSyslog is the lowest level FRR sends to syslog. Unset renders no<br />log syslog line. |  | Enum: [emergencies alerts critical errors warnings notifications informational debugging] <br /> |
| `logNeighborChanges` _boolean_ | LogNeighborChanges logs BGP session state changes. |  |  |
| `ipv4UnicastDefault` _boolean_ | IPv4UnicastDefault activates IPv4 unicast for every neighbor by<br />default. False renders `no bgp default ipv4-unicast`. |  |  |
| `allowMartianNexthop` _boolean_ | AllowMartianNexthop accepts next hops FRR otherwise treats as<br />martian. |  |  |
| `ebgpRequiresPolicy` _boolean_ | EBGPRequiresPolicy is FRR's RFC 8212 behavior: an eBGP session with<br />no policy in a direction exchanges no routes in it. Unset or true<br />keeps FRR's default, which is on; false renders<br />`no bgp ebgp-requires-policy`. False also lets the routers' peer<br />families, iBGP and eBGP alike, leave exportPolicyRef unset, which<br />exports every route the router selects to that peer; any other class<br />refuses a peer family with no export policy. Either way an eBGP peer<br />family with no importPolicyRef accepts every route the peer sends<br />once this is false. |  |  |
| `bmpTargets` _[BMPTarget](#bmptarget) array_ | BMPTargets lists the BMP collectors every router of the class streams<br />to. The router image must load bgpd's BMP module. |  | MaxItems: 4 <br /> |


#### FRRRouterParametersStatus



FRRRouterParametersStatus defines the observed state of FRRRouterParameters.



_Appears in:_
- [FRRRouterParameters](#frrrouterparameters)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### FabricActivationSettings



FabricActivationSettings are the rollout policy's settings for one
epoch, resolved by the rollout manager.



_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `stabilizationSeconds` _integer_ | StabilizationSeconds is how long an applied revision must stay<br />healthy before the agent commits it. |  | Maximum: 3600 <br />Minimum: 0 <br /> |
| `applyTimeoutSeconds` _integer_ | ApplyTimeoutSeconds bounds one reload. |  | Maximum: 900 <br />Minimum: 5 <br /> |
| `offlineBootSeconds` _integer_ | OfflineBootSeconds is how long the committed configuration may be<br />restored at boot without the API. |  | Maximum: 7.776e+06 <br />Minimum: 0 <br /> |
| `requiredPeers` _string array_ | RequiredPeers are the peer addresses that must reach Established<br />for the activation to count as healthy. |  | MaxItems: 128 <br />items:MaxLength: 45 <br /> |
| `requiredStaticRoutes` _string array_ | RequiredStaticRoutes are the prefixes that must be in the FIB. |  | MaxItems: 128 <br />items:MaxLength: 43 <br /> |


#### FabricActivationStage

_Underlying type:_ _string_

FabricActivationStage is the last journaled stage of an epoch.

_Validation:_
- Enum: [Accepted Applied ApplyFailed Committed Recovered Degraded]

_Appears in:_
- [FabricEpochStatus](#fabricepochstatus)

| Field | Description |
| --- | --- |
| `Accepted` |  |
| `Applied` |  |
| `ApplyFailed` |  |
| `Committed` |  |
| `Recovered` |  |
| `Degraded` |  |


#### FabricChangeClass

_Underlying type:_ _string_

FabricChangeClass classifies what applying a candidate would disturb.

_Validation:_
- Enum: [NoChange NonDisruptive SessionReset RestartRequired]

_Appears in:_
- [FabricStagedRevision](#fabricstagedrevision)

| Field | Description |
| --- | --- |
| `NoChange` |  |
| `NonDisruptive` |  |
| `SessionReset` |  |
| `RestartRequired` |  |


#### FabricConfigSource

_Underlying type:_ _string_

FabricConfigSource names which writer owns a node's FRR configuration.

_Validation:_
- Enum: [ConfigMap Shadow CRD]

_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)
- [FabricRouterDeploymentStatus](#fabricrouterdeploymentstatus)

| Field | Description |
| --- | --- |
| `ConfigMap` | FabricConfigSourceConfigMap applies the node's rendered ConfigMap.<br /> |
| `Shadow` | FabricConfigSourceShadow applies the ConfigMap and stages the typed<br />revision beside it, reporting the difference without writing it.<br /> |
| `CRD` | FabricConfigSourceCRD applies the active FabricRouterRevision.<br /> |


#### FabricEndpoint



FabricEndpoint is where one fabric router is reached on one transport
network: its addresses there, the ASN it speaks, the cell that owns it and
its failure domain. A FabricTopology generates both ends of a managed
session from two endpoint records, so a router's record must be present
in every cell whose routers peer with it, including cells where the router
itself does not run. Whoever distributes the rest of the cell's intent
distributes these records too; nothing in the cluster copies them between
cells.

An endpoint is a record, not an allocation: nothing here asks an
addressing service for an address. spec.source says where the addresses
came from.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FabricEndpoint` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FabricEndpointSpec](#fabricendpointspec)_ |  |  | Required: \{\} <br /> |
| `status` _[FabricEndpointStatus](#fabricendpointstatus)_ |  |  |  |


#### FabricEndpointAddresses



FabricEndpointAddresses are a router's addresses on one transport.



_Appears in:_
- [FabricEndpointSpec](#fabricendpointspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ipv4` _string_ | IPv4 is the router's IPv4 address on the transport. |  | MaxLength: 15 <br /> |
| `ipv6` _string_ | IPv6 is the router's IPv6 address on the transport. |  | MaxLength: 45 <br /> |


#### FabricEndpointSource



FabricEndpointSource records where an endpoint's addresses came from. A
claim reference is provenance: nothing resolves it, and the addresses in
the spec are what sessions use.



_Appears in:_
- [FabricEndpointSpec](#fabricendpointspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[FabricEndpointSourceType](#fabricendpointsourcetype)_ | Type is Manual or AddressClaim. | Manual | Enum: [Manual AddressClaim] <br /> |
| `ipv4ClaimRef` _[AddressClaimRef](#addressclaimref)_ | IPv4ClaimRef is the claim the IPv4 address was allocated by. |  |  |
| `ipv6ClaimRef` _[AddressClaimRef](#addressclaimref)_ | IPv6ClaimRef is the claim the IPv6 address was allocated by. |  |  |


#### FabricEndpointSourceType

_Underlying type:_ _string_

FabricEndpointSourceType names who wrote an endpoint's addresses.

_Validation:_
- Enum: [Manual AddressClaim]

_Appears in:_
- [FabricEndpointSource](#fabricendpointsource)

| Field | Description |
| --- | --- |
| `Manual` | FabricEndpointSourceManual is an address an operator or the<br />deployment pipeline authored, with no allocation behind it.<br /> |
| `AddressClaim` | FabricEndpointSourceAddressClaim is an address allocated by an<br />addressing-service claim, which the endpoint records.<br /> |


#### FabricEndpointSpec



FabricEndpointSpec is one router's presence on one transport network. Its
identity (routing domain, cell, router and transport) is immutable: moving
a router to another transport is a new endpoint and the removal of the
old one, so the old one's sessions drain like any other removal.



_Appears in:_
- [FabricEndpoint](#fabricendpoint)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routingDomain` _string_ | RoutingDomain is the fabric this endpoint belongs to. A topology<br />considers only endpoints of its own routing domain. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `cell` _string_ | Cell is the cell that runs the router. The router exists as a<br />BGPRouter only in that cell; every other cell knows it through this<br />record alone. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `routerRef` _[LocalObjectRef](#localobjectref)_ | RouterRef names the BGPRouter, in this namespace of the owning cell. |  |  |
| `transport` _string_ | Transport names the network the addresses are on, such as<br />private-mesh or public. Two endpoints peer only over a transport they<br />share. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `asn` _integer_ | ASN is the router's local ASN, the remote ASN of every session toward<br />this endpoint. In the owning cell it must equal the BGPRouter's. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |
| `addresses` _[FabricEndpointAddresses](#fabricendpointaddresses)_ | Addresses are the router's addresses on the transport, at most one<br />per family. A session is generated only in a family both ends carry. |  |  |
| `interface` _string_ | Interface is the router's interface on the transport. It is required<br />with a link-local IPv6 address. The topology generator does not yet<br />generate sessions toward an endpoint that names one. |  | MaxLength: 15 <br />Pattern: `^[A-Za-z0-9_.@-]\{1,15\}$` <br /> |
| `failureDomain` _string_ | FailureDomain is the failure domain the router is in. Unset, the<br />owning cell reads it from the router's Node label the topology names. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$` <br /> |
| `source` _[FabricEndpointSource](#fabricendpointsource)_ | Source records where the addresses came from. | \{ type:Manual \} |  |


#### FabricEndpointStatus



FabricEndpointStatus is this cell's view of an endpoint.



_Appears in:_
- [FabricEndpoint](#fabricendpoint)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the generation the conditions describe. |  |  |
| `local` _boolean_ | Local is true when a FabricTopology in this namespace generates<br />sessions for the endpoint's cell, so its router runs here. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are Ready and Conflict. |  |  |


#### FabricEpochStatus



FabricEpochStatus is one epoch's journaled outcome.



_Appears in:_
- [FabricRouterDeploymentStatus](#fabricrouterdeploymentstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `epoch` _integer_ |  |  | Minimum: 1 <br /> |
| `revision` _string_ |  |  | MaxLength: 253 <br /> |
| `stage` _[FabricActivationStage](#fabricactivationstage)_ |  |  | Enum: [Accepted Applied ApplyFailed Committed Recovered Degraded] <br /> |
| `recoveryTarget` _string_ | RecoveryTarget is the recovery target journaled with the epoch. |  | MaxLength: 253 <br /> |
| `revokedPrefixes` _integer_ | RevokedPrefixes counts the revoked prefixes journaled with it. |  |  |
| `detail` _string_ | Detail explains a failure. |  | MaxLength: 1024 <br /> |


#### FabricExternalPeer



FabricExternalPeer is one external router.



_Appears in:_
- [FabricExternalRelationship](#fabricexternalrelationship)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `address` _string_ | Address is the external router's address. A session runs in its<br />family. |  | MaxLength: 45 <br /> |
| `asn` _integer_ | ASN is the external router's ASN. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br /> |


#### FabricExternalRelationship



FabricExternalRelationship peers member routers with routers outside
every topology. Its peers are explicit: an external router has no
endpoint record.



_Appears in:_
- [FabricTopologySpec](#fabrictopologyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name identifies the relationship on its generated peers. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `routers` _[FabricTopologyMembers](#fabrictopologymembers)_ | Routers selects the members that peer with every external peer. |  |  |
| `transport` _string_ | Transport is the transport of the local endpoint sessions are<br />sourced from. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `updateSource` _[FabricUpdateSource](#fabricupdatesource)_ | UpdateSource is where sessions are sourced from. | EndpointAddress | Enum: [EndpointAddress None] <br /> |
| `peers` _[FabricExternalPeer](#fabricexternalpeer) array_ | Peers are the external routers. |  | MaxItems: 16 <br />MinItems: 1 <br /> |
| `settings` _[FabricSessionSettings](#fabricsessionsettings)_ | Settings apply to every generated peer. |  |  |


#### FabricFence



FabricFence records that a node was cut off from the fabric.



_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `nodeUID` _string_ | NodeUID is the fenced node. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `method` _string_ | Method is how it was fenced, such as a switch port shutdown. |  | MaxLength: 256 <br />MinLength: 1 <br /> |
| `fencedBy` _string_ | FencedBy is who confirmed it. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `fencedAt` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | FencedAt is when. |  |  |


#### FabricMeshRelationship



FabricMeshRelationship peers every selected endpoint with every other on
the same transport.



_Appears in:_
- [FabricTopologySpec](#fabrictopologyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name identifies the relationship on its generated peers. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `transports` _string array_ | Transports are the transports the mesh runs over. Two endpoints peer<br />over each transport both are on. |  | MaxItems: 16 <br />MinItems: 1 <br />items:MaxLength: 63 <br />items:Pattern: ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ <br /> |
| `families` _[FabricSessionFamily](#fabricsessionfamily) array_ | Families are the IP families sessions run over: one session per<br />family both endpoints have an address in. |  | Enum: [ipv4 ipv6] <br />MaxItems: 2 <br />MinItems: 1 <br /> |
| `updateSource` _[FabricUpdateSource](#fabricupdatesource)_ | UpdateSource is where sessions are sourced from. | EndpointAddress | Enum: [EndpointAddress None] <br /> |
| `endpointSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | EndpointSelector selects the mesh's endpoints by label. An empty<br />selector selects every endpoint of the routing domain. |  |  |
| `settings` _[FabricSessionSettings](#fabricsessionsettings)_ | Settings apply to every generated peer. |  |  |


#### FabricNodeIdentity



FabricNodeIdentity names a Node by name and UID.



_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `nodeName` _string_ |  |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `nodeUID` _string_ |  |  | MaxLength: 36 <br />MinLength: 1 <br /> |


#### FabricObjectIdentity



FabricObjectIdentity names an object by name and UID.



_Appears in:_
- [FabricRecovery](#fabricrecovery)
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)
- [FabricSourceHandoff](#fabricsourcehandoff)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `uid` _string_ |  |  | MaxLength: 36 <br />MinLength: 1 <br /> |


#### FabricRebind



FabricRebind approves accepting this deployment over a journal bound to
another deployment UID.



_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `fromDeploymentUID` _string_ | FromDeploymentUID is the deployment UID the agent's journal is bound<br />to; the agent rebinds only when it matches. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `approvedBy` _string_ | ApprovedBy is who confirmed the old deployment is gone. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `approvedAt` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | ApprovedAt is when. |  |  |


#### FabricRecovery



FabricRecovery is what a failed activation may fall back to.



_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRevisionRef` _[LocalObjectRef](#localobjectref)_ | TargetRevisionRef is the revision the agent restores on a confirmed<br />failure of this activation. Unset means no rollback: the agent<br />reports NoEligibleRecovery. |  |  |
| `targetDependencyDigest` _string_ | TargetDependencyDigest is the recovery target's digest. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |
| `revokedPrefixes` _string array_ | RevokedPrefixes are prefixes no recovery target may originate. They<br />can be added, never removed. |  | MaxItems: 64 <br />items:MaxLength: 43 <br /> |
| `revokedCredentials` _[FabricObjectIdentity](#fabricobjectidentity) array_ | RevokedCredentials are Secrets no recovery target may use. They can<br />be added, never removed. |  | MaxItems: 32 <br /> |
| `retired` _boolean_ | Retired means the router is decommissioned; no revision may be<br />restored. It is set with the router's last promotion, which usually<br />withdraws everything. Since a retired router is never promoted again<br />and recovery changes only with a promotion, it cannot be cleared. |  |  |


#### FabricReflectionRelationship



FabricReflectionRelationship peers every reflector with every client on
the same transport. Reflectors do not peer with each other here.



_Appears in:_
- [FabricTopologySpec](#fabrictopologyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name identifies the relationship on its generated peers. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `transports` _string array_ | Transports are the transports reflection runs over. |  | MaxItems: 16 <br />MinItems: 1 <br />items:MaxLength: 63 <br />items:Pattern: ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ <br /> |
| `families` _[FabricSessionFamily](#fabricsessionfamily) array_ | Families are the IP families sessions run over. |  | Enum: [ipv4 ipv6] <br />MaxItems: 2 <br />MinItems: 1 <br /> |
| `updateSource` _[FabricUpdateSource](#fabricupdatesource)_ | UpdateSource is where sessions are sourced from. | EndpointAddress | Enum: [EndpointAddress None] <br /> |
| `reflectorSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | ReflectorSelector selects the reflectors' endpoints by label. |  |  |
| `clientSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | ClientSelector selects the clients' endpoints by label. |  |  |
| `reflector` _[FabricSessionSettings](#fabricsessionsettings)_ | Reflector applies to the peers a reflector generates toward its<br />clients, each of which is a route-reflector client in every family. |  |  |
| `client` _[FabricSessionSettings](#fabricsessionsettings)_ | Client applies to the peers a client generates toward its<br />reflectors. |  |  |


#### FabricReleaseAuthorization



FabricReleaseAuthorization permits the rollout manager to promote named
revisions in this cell, as part of one fleet release. Its spec is
immutable. Within a routing domain at most one authorization is
outstanding at a time, and fleet sequences only rise: the controller
enforces that within a cell, keeping an outstanding authorization with a
finalizer, and the fleet release tool across cells.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FabricReleaseAuthorization` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FabricReleaseAuthorizationSpec](#fabricreleaseauthorizationspec)_ |  |  | Required: \{\} <br /> |
| `status` _[FabricReleaseAuthorizationStatus](#fabricreleaseauthorizationstatus)_ |  |  |  |


#### FabricReleaseAuthorizationSpec



FabricReleaseAuthorizationSpec is what a release permits.



_Appears in:_
- [FabricReleaseAuthorization](#fabricreleaseauthorization)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _[FabricReleaseType](#fabricreleasetype)_ | Type is Release or EmergencyWithdrawal. |  | Enum: [Release EmergencyWithdrawal] <br /> |
| `routingDomain` _string_ | RoutingDomain is the fabric the release belongs to. |  | MaxLength: 63 <br />MinLength: 1 <br /> |
| `fleetReleaseID` _string_ | FleetReleaseID identifies the release across cells. |  | MaxLength: 63 <br />MinLength: 1 <br /> |
| `fleetSequence` _integer_ | FleetSequence orders releases in the routing domain. |  | Minimum: 1 <br /> |
| `deployments` _[FabricReleaseTarget](#fabricreleasetarget) array_ | Deployments lists each deployment, revision and digest the release<br />may activate. |  | MaxItems: 256 <br />MinItems: 1 <br /> |
| `withdrawnPrefixes` _string array_ | WithdrawnPrefixes are the originations an EmergencyWithdrawal<br />removes; its revisions may change nothing else. |  | MaxItems: 256 <br />items:MaxLength: 43 <br /> |
| `failureDomains` _string array_ | FailureDomains are the failure domains the release touches. |  | MaxItems: 64 <br />items:MaxLength: 63 <br /> |
| `inputManifest` _[FabricRevisionInput](#fabricrevisioninput) array_ | InputManifest pins the inputs of a release that changes several<br />mutable objects; a candidate whose inputs differ is not promoted. |  | MaxItems: 4096 <br /> |
| `startDeadline` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | StartDeadline is the last time the release may start. Passing it<br />stops a start; it never ends a release whose outcome is unknown. |  |  |


#### FabricReleaseAuthorizationStatus



FabricReleaseAuthorizationStatus is a release's progress.



_Appears in:_
- [FabricReleaseAuthorization](#fabricreleaseauthorization)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `phase` _[FabricReleasePhase](#fabricreleasephase)_ | Phase is the release's progress. A release is outstanding while<br />Pending, Started or Unknown. |  | Enum: [Pending Started Completed Failed Cancelled Unknown] <br /> |
| `startedAt` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ |  |  |  |
| `finishedAt` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ |  |  |  |
| `recoveryVerified` _boolean_ | RecoveryVerified is set on a Failed release once every touched<br />router is confirmed back on its recovery target. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ |  |  |  |


#### FabricReleasePhase

_Underlying type:_ _string_

FabricReleasePhase is a release's progress.

_Validation:_
- Enum: [Pending Started Completed Failed Cancelled Unknown]

_Appears in:_
- [FabricReleaseAuthorizationStatus](#fabricreleaseauthorizationstatus)

| Field | Description |
| --- | --- |
| `Pending` |  |
| `Started` |  |
| `Completed` |  |
| `Failed` |  |
| `Cancelled` |  |
| `Unknown` |  |


#### FabricReleaseTarget



FabricReleaseTarget is one deployment a release may activate.



_Appears in:_
- [FabricReleaseAuthorizationSpec](#fabricreleaseauthorizationspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `deployment` _string_ | Deployment is the FabricRouterDeployment's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `deploymentUID` _string_ | DeploymentUID is its UID, so a recreated deployment is not covered. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `revision` _string_ | Revision is the FabricRouterRevision to activate. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `activationDependencyDigest` _string_ | ActivationDependencyDigest is that revision's digest. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |
| `retire` _boolean_ | Retire decommissions the router with this promotion: its revision<br />is the last it runs, nothing is restored over it and no later<br />release promotes it. |  |  |
| `reactivate` _boolean_ | Reactivate promotes the revision as a new epoch even when the<br />deployment already reports it committed, so a node that lost its<br />state starts from it again. Without it such a target counts as<br />committed at once and nothing is promoted. The promotion passes<br />every check an ordinary one does, and the deployment must run the<br />revision, committed, when the release starts and when it is<br />promoted. It has no recovery target: a failure reports<br />NoEligibleRecovery rather than restoring another revision. Only a<br />Release re-activates. |  |  |


#### FabricReleaseType

_Underlying type:_ _string_

FabricReleaseType is what a release authorizes.

_Validation:_
- Enum: [Release EmergencyWithdrawal]

_Appears in:_
- [FabricReleaseAuthorizationSpec](#fabricreleaseauthorizationspec)

| Field | Description |
| --- | --- |
| `Release` | FabricReleaseTypeRelease authorizes ordinary promotions.<br /> |
| `EmergencyWithdrawal` | FabricReleaseTypeEmergencyWithdrawal authorizes only revisions that<br />withdraw the named originations, and may be issued while a release<br />is outstanding.<br /> |


#### FabricRevisionCompiler



FabricRevisionCompiler identifies the compiler and FRR build.



_Appears in:_
- [FabricRouterRevisionSpec](#fabricrouterrevisionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `semanticsVersion` _string_ | SemanticsVersion is the compiler's semantics version; a change that<br />alters rendered output for the same input bumps it. |  | MaxLength: 32 <br />MinLength: 1 <br /> |
| `frrVersion` _string_ | FRRVersion is the FRR build the configuration targets. |  | MaxLength: 32 <br />MinLength: 1 <br /> |


#### FabricRevisionInput



FabricRevisionInput is one source object of a revision.



_Appears in:_
- [FabricReleaseAuthorizationSpec](#fabricreleaseauthorizationspec)
- [FabricRouterRevisionSpec](#fabricrouterrevisionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `kind` _string_ | Kind is the object's kind. |  | MaxLength: 63 <br />MinLength: 1 <br /> |
| `name` _string_ | Name is the object's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `uid` _string_ | UID is the object's UID. |  | MaxLength: 36 <br /> |
| `generation` _integer_ | Generation is the object's metadata.generation when it was read. |  |  |
| `digest` _string_ | Digest is the SHA-256, in hex, of the object's spec in canonical<br />JSON. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |


#### FabricRevisionParameters



FabricRevisionParameters identifies the parameters a revision used.



_Appears in:_
- [FabricRouterRevisionSpec](#fabricrouterrevisionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the FRRRouterParameters name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `uid` _string_ | UID is the FRRRouterParameters UID. |  | MaxLength: 36 <br /> |


#### FabricRolloutPolicy



FabricRolloutPolicy sets how the rollout manager promotes and observes
the routers that reference it.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FabricRolloutPolicy` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FabricRolloutPolicySpec](#fabricrolloutpolicyspec)_ |  |  | Required: \{\} <br /> |


#### FabricRolloutPolicySpec



FabricRolloutPolicySpec are the rollout settings. The rollout manager
copies the ones the agent needs into each promotion's activation
settings.



_Appears in:_
- [FabricRolloutPolicy](#fabricrolloutpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `maxUnavailable` _integer_ | MaxUnavailable is how many routers of one failure domain, within one<br />cell, may be activating at once. | 1 | Minimum: 1 <br /> |
| `failureDomainLabel` _string_ | FailureDomainLabel is the Node label that groups routers. | topology.kubernetes.io/zone | MaxLength: 317 <br />Pattern: `^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$` <br /> |
| `stabilizationSeconds` _integer_ | StabilizationSeconds is how long an applied revision must stay<br />healthy before the agent commits it. | 60 | Maximum: 3600 <br />Minimum: 0 <br /> |
| `applyTimeoutSeconds` _integer_ | ApplyTimeoutSeconds bounds one reload. | 60 | Maximum: 900 <br />Minimum: 5 <br /> |
| `heartbeatTimeoutSeconds` _integer_ | HeartbeatTimeoutSeconds is how long an agent's silence leaves its<br />router healthy before readiness becomes Unknown. | 60 | Maximum: 3600 <br />Minimum: 10 <br /> |
| `offlineBootSeconds` _integer_ | OfflineBootSeconds is how long a committed checkpoint may be applied<br />at boot without the API. | 604800 | Maximum: 7.776e+06 <br />Minimum: 0 <br /> |
| `optionalPeers` _[LocalObjectRef](#localobjectref) array_ | OptionalPeers names BGPPeers, in the policy's namespace, that need not<br />reach Established for a router to be healthy. |  | MaxItems: 256 <br /> |
| `maintenancePeers` _[LocalObjectRef](#localobjectref) array_ | MaintenancePeers names BGPPeers, in the policy's namespace, that are<br />administratively down and excluded from health. |  | MaxItems: 256 <br /> |
| `minWitnesses` _integer_ | MinWitnesses is how many other routers must see a router's<br />originations before a promotion counts as healthy. | 1 | Minimum: 1 <br /> |


#### FabricRouterConfiguration



FabricRouterConfiguration is the resolved typed configuration of one
fabric router: the router and parameters specs, and the specs of every
peer, profile, policy, list, set, advertisement and static route it
renders, each list ordered by name.



_Appears in:_
- [FabricRouterRevisionSpec](#fabricrouterrevisionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `router` _[BGPRouterSpec](#bgprouterspec)_ |  |  |  |
| `parameters` _[FRRRouterParametersSpec](#frrrouterparametersspec)_ |  |  |  |


#### FabricRouterDeployment



FabricRouterDeployment is the single activation point of one fabric
router: the revision a node agent stages and the revision it runs. The
rollout manager writes its spec and promotes a revision by raising the
activation epoch together with the active revision, its digest, the
release it is promoted under, the activation settings and the recovery
authorization, in one update; the node agent writes its status. It is
named after the router, and created at epoch zero.

Admission checks the shape of a promotion, not that its authorization
exists and covers this deployment, revision and digest: the rollout
manager checks that before writing, and the node agent again before
applying.

The agent binds its journal to the deployment's UID. Deleting and
recreating a deployment does not reset its epochs: the agent refuses the
new UID with RecoveryConflict until spec.rebind names the old one.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FabricRouterDeployment` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)_ |  |  | Required: \{\} <br /> |
| `status` _[FabricRouterDeploymentStatus](#fabricrouterdeploymentstatus)_ |  |  |  |


#### FabricRouterDeploymentSpec



FabricRouterDeploymentSpec is what the rollout manager asks of a node.

Rules that hold on every write:
Transition rules:



_Appears in:_
- [FabricRouterDeployment](#fabricrouterdeployment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerRef` _[FabricObjectIdentity](#fabricobjectidentity)_ | RouterRef is the BGPRouter this deployment activates. |  |  |
| `target` _[FabricNodeIdentity](#fabricnodeidentity)_ | Target is the Node the router runs on, by name and UID. |  |  |
| `source` _[FabricConfigSource](#fabricconfigsource)_ | Source is the writer of the node's FRR configuration. Once a node is<br />on CRD it returns only to ConfigMap, with sourceHandoff. | ConfigMap | Enum: [ConfigMap Shadow CRD] <br /> |
| `sourceHandoff` _[FabricSourceHandoff](#fabricsourcehandoff)_ | SourceHandoff names the ConfigMap version the agent verifies before<br />handing the node back from CRD to ConfigMap. |  |  |
| `candidateRevisionRef` _[LocalObjectRef](#localobjectref)_ | CandidateRevisionRef is the revision the agent stages and validates<br />without applying. |  |  |
| `activeRevisionRef` _[LocalObjectRef](#localobjectref)_ | ActiveRevisionRef is the revision the agent applies at<br />activationEpoch. |  |  |
| `activationEpoch` _integer_ | ActivationEpoch numbers promotions. It rises by one with each new<br />active revision, and a retry of the same revision is a new epoch. |  | Maximum: 9.007199254740991e+15 <br />Minimum: 0 <br /> |
| `activationDependencyDigest` _string_ | ActivationDependencyDigest is the active revision's digest, so an<br />agent never applies a revision that differs from the one promoted. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |
| `authorizationRef` _[FabricObjectIdentity](#fabricobjectidentity)_ | AuthorizationRef is the FabricReleaseAuthorization the active epoch<br />was promoted under. |  |  |
| `activation` _[FabricActivationSettings](#fabricactivationsettings)_ | Activation holds the settings the agent applies the active epoch<br />with, copied from the router's rollout policy at promotion so the<br />agent needs nothing else. |  |  |
| `recovery` _[FabricRecovery](#fabricrecovery)_ | Recovery is what the agent may restore, and what it must never<br />restore, if this activation fails. It changes only with the epoch. |  |  |
| `fence` _[FabricFence](#fabricfence)_ | Fence records that the router's previous node was cut off from the<br />fabric, which moving the router to another node requires. |  |  |
| `rebind` _[FabricRebind](#fabricrebind)_ | Rebind lets the agent accept this deployment although its journal is<br />bound to another deployment UID, after an operator confirmed that<br />deployment is gone for good. |  |  |
| `suspended` _boolean_ | Suspended stops promotion; the agent keeps running what it has. |  |  |


#### FabricRouterDeploymentStatus



FabricRouterDeploymentStatus is what the node agent observed.



_Appears in:_
- [FabricRouterDeployment](#fabricrouterdeployment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the spec generation the agent acted on. |  |  |
| `effectiveSource` _[FabricConfigSource](#fabricconfigsource)_ | EffectiveSource is the writer the agent is actually honouring. |  | Enum: [ConfigMap Shadow CRD] <br /> |
| `boundDeploymentUID` _string_ | BoundDeploymentUID is the deployment UID the agent's journal is bound<br />to; a different UID here than the object's own is a RecoveryConflict. |  | MaxLength: 36 <br /> |
| `clusterID` _string_ | ClusterID is the cluster the agent's state is bound to. |  | MaxLength: 36 <br /> |
| `staged` _[FabricStagedRevision](#fabricstagedrevision)_ | Staged reports the candidate the agent validated without applying. |  |  |
| `appliedEpoch` _integer_ | AppliedEpoch, AppliedRevision and AppliedDigest are the last<br />activation the agent committed. |  |  |
| `appliedRevision` _string_ |  |  | MaxLength: 253 <br /> |
| `appliedDigest` _string_ |  |  | Pattern: `^([0-9a-f]\{64\})?$` <br /> |
| `journalHighWater` _integer_ | JournalHighWater is the highest epoch the agent's journal accepted<br />for this deployment UID. |  |  |
| `epochs` _[FabricEpochStatus](#fabricepochstatus) array_ | Epochs reports the journal's last stage for the most recent epochs,<br />newest first, so the rollout manager knows a failed epoch is spent. |  | MaxItems: 16 <br /> |
| `bootAuthorizedUntil` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | BootAuthorizedUntil is when the committed configuration stops being<br />restorable at boot without the API. |  |  |
| `requiresAPI` _boolean_ | RequiresAPI means the committed configuration has sessions that need<br />credentials from the API and are not restored offline. |  |  |
| `heartbeatTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | HeartbeatTime is the agent's last report. |  |  |
| `agentVersion` _string_ | AgentVersion is the reporting agent's build. |  | MaxLength: 64 <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are Accepted, Staged, Programmed, Ready, Degraded,<br />RecoveryConflict and Bootstrapping. |  |  |


#### FabricRouterRevision



FabricRouterRevision is one immutable, fully resolved configuration for
one fabric router: the typed specs of every object the router's
configuration depends on, captured at one moment, with the identities and
digests that make an activation reproducible. It carries no Secret
material and no rendered FRR text; the node agent compiles the
configuration with the same compiler that produced the digests.

The fabric router controller creates revisions and never updates them.
Its name is the router's name and the first ten hex digits of the
activation dependency digest, so identical inputs map to one object.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FabricRouterRevision` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FabricRouterRevisionSpec](#fabricrouterrevisionspec)_ |  |  | Required: \{\} <br /> |


#### FabricRouterRevisionSpec



FabricRouterRevisionSpec is a revision's content. It is immutable.



_Appears in:_
- [FabricRouterRevision](#fabricrouterrevision)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `target` _[FabricRouterTarget](#fabricroutertarget)_ | Target is the router and Node this revision configures. |  |  |
| `parameters` _[FabricRevisionParameters](#fabricrevisionparameters)_ | Parameters identifies the FRRRouterParameters the configuration<br />used. |  |  |
| `compiler` _[FabricRevisionCompiler](#fabricrevisioncompiler)_ | Compiler identifies the compiler semantics and the FRR build the<br />configuration targets. |  |  |
| `configuration` _[FabricRouterConfiguration](#fabricrouterconfiguration)_ | Configuration is the resolved typed configuration. It is validated<br />by the controller that writes it rather than by this schema, which<br />would otherwise repeat every source kind's rules. |  | Schemaless: \{\} <br />Type: object <br /> |
| `inputs` _[FabricRevisionInput](#fabricrevisioninput) array_ | Inputs lists every object the configuration was resolved from. |  | MaxItems: 4096 <br /> |
| `semanticsDigest` _string_ | SemanticsDigest is the SHA-256, in hex, of the configuration in<br />canonical JSON. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |
| `activationDependencyDigest` _string_ | ActivationDependencyDigest is the SHA-256, in hex, over the target<br />identity, the semantics digest, the parameters identity and the<br />compiler and FRR versions. Two revisions with the same digest<br />activate identically. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |
| `renderedDigest` _string_ | RenderedDigest is the SHA-256, in hex, of the frr.conf the compiler<br />renders from the configuration, so an agent can check that its own<br />compile matches. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |


#### FabricRouterTarget



FabricRouterTarget is the router and Node a revision configures, by name
and UID, so a recreated router or a replaced Node never inherits one.



_Appears in:_
- [FabricRouterRevisionSpec](#fabricrouterrevisionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerName` _string_ | RouterName is the BGPRouter's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `routerUID` _string_ | RouterUID is the BGPRouter's UID. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `nodeName` _string_ | NodeName is the Node the router runs on. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `nodeUID` _string_ | NodeUID is the Node's UID. Empty when the Node was not found. |  | MaxLength: 36 <br /> |


#### FabricSessionFamily

_Underlying type:_ _string_

FabricSessionFamily is an IP family a session runs over, and the unicast
family it carries when no peer profile names its families.

_Validation:_
- Enum: [ipv4 ipv6]

_Appears in:_
- [FabricMeshRelationship](#fabricmeshrelationship)
- [FabricReflectionRelationship](#fabricreflectionrelationship)

| Field | Description |
| --- | --- |
| `ipv4` |  |
| `ipv6` |  |


#### FabricSessionSettings



FabricSessionSettings are the settings of the peers one side of a
relationship generates. Route-reflector clients are set by the
relationship, never here.



_Appears in:_
- [FabricExternalRelationship](#fabricexternalrelationship)
- [FabricMeshRelationship](#fabricmeshrelationship)
- [FabricReflectionRelationship](#fabricreflectionrelationship)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `peerProfileRef` _[LocalObjectRef](#localobjectref)_ | PeerProfileRef names the BGPPeerProfile of every generated peer. With<br />one, a peer activates the profile's families; without one, the<br />unicast family of the transport family it runs over. |  |  |
| `transport` _[BGPPeerTransport](#bgppeertransport)_ | Transport overrides the profile's transport settings. |  |  |
| `familySettings` _[BGPPeerFamilySettings](#bgppeerfamilysettings) array_ | FamilySettings are per-family settings: import and export policies,<br />next-hop mode, local weight, prefix limits. Without a profile only<br />the entry for a peer's own family applies to it. |  | MaxItems: 2 <br /> |


#### FabricSourceHandoff



FabricSourceHandoff names the ConfigMap version a node returns to.



_Appears in:_
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `configMap` _[FabricObjectIdentity](#fabricobjectidentity)_ | ConfigMap is the node's per-node ConfigMap, by name and UID. |  |  |
| `resourceVersion` _string_ | ResourceVersion is the ConfigMap version the agent may apply. |  | MaxLength: 64 <br />MinLength: 1 <br /> |


#### FabricStagedRevision



FabricStagedRevision is a validated, unapplied candidate.



_Appears in:_
- [FabricRouterDeploymentStatus](#fabricrouterdeploymentstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `revision` _string_ | Revision is the candidate's name. |  | MaxLength: 253 <br /> |
| `digest` _string_ | Digest is its activation dependency digest. |  | Pattern: `^[0-9a-f]\{64\}$` <br /> |
| `class` _[FabricChangeClass](#fabricchangeclass)_ | Class classifies what applying it would disturb. |  | Enum: [NoChange NonDisruptive SessionReset RestartRequired] <br /> |
| `linesAdded` _integer_ | LinesAdded and LinesRemoved count the reload's changes. |  |  |
| `linesRemoved` _integer_ |  |  |  |
| `diff` _string_ | Diff is the reload's change list, truncated. |  | MaxLength: 8192 <br /> |
| `validatedAt` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | ValidatedAt is when the agent validated it. |  |  |


#### FabricTopology



FabricTopology generates the BGPPeers of one cell's fabric routers from
FabricEndpoint records. It names the cell's member routers and the
relationships between endpoints of one routing domain: a full mesh, route
reflection, and external peers. For every relationship it creates the
local side only: a peer on each member router toward each endpoint the
relationship pairs it with. The cell on the other end generates the
reciprocal peer from its own copy of the records and its own topology;
the two ends agree only while those copies and relationships agree,
which status.recordsDigest and status.relationshipsDigest let cells
compare.

Generated peers are ordinary BGPPeers, labelled as generated and
annotated with the topology's UID, with no owner reference; the revision
compiler reads them like any other peer. The topology never changes or
deletes a peer it did not create, and reports a conflict where one is in
its way. A session is identified by its router and remote address, so a
peer keeps its name when the relationship or record producing it is
renamed.

A session the topology no longer generates is kept until one of its ends
is out of service: the router is deleted, its FabricRouterDeployment
committed a retiring release, the other cell deleted the endpoint record,
or spec.drain names it. Entries in spec.drain stay until an operator
removes them.

Deleting the topology drops no session, whatever the deletion's
propagation policy: generated peers have no owner reference for the
garbage collector to follow, and before the topology goes the controller
hands every peer it generated to manual control by removing its
generated labels and UID, so the peers keep compiling as hand-authored
ones. A topology created again reports them as conflicts
rather than adopting them.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `FabricTopology` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[FabricTopologySpec](#fabrictopologyspec)_ |  |  | Required: \{\} <br /> |
| `status` _[FabricTopologyStatus](#fabrictopologystatus)_ |  |  |  |


#### FabricTopologyDrain



FabricTopologyDrain names what may lose its retained sessions.



_Appears in:_
- [FabricTopologySpec](#fabrictopologyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routers` _[LocalObjectRef](#localobjectref) array_ | Routers names BGPRouters of this cell. Every retained session from<br />or toward one is released. |  | MaxItems: 256 <br /> |
| `endpoints` _[LocalObjectRef](#localobjectref) array_ | Endpoints names FabricEndpoints, of any cell. Every retained session<br />toward or sourced from one is released. |  | MaxItems: 256 <br /> |


#### FabricTopologyMembers



FabricTopologyMembers selects BGPRouters by label, by name, or both.



_Appears in:_
- [FabricExternalRelationship](#fabricexternalrelationship)
- [FabricTopologySpec](#fabrictopologyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | RouterSelector selects BGPRouters by label. |  |  |
| `routers` _[LocalObjectRef](#localobjectref) array_ | Routers names BGPRouters. |  | MaxItems: 256 <br /> |


#### FabricTopologySpec



FabricTopologySpec is one cell's routing relationships.



_Appears in:_
- [FabricTopology](#fabrictopology)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routingDomain` _string_ | RoutingDomain is the fabric whose FabricEndpoints the topology reads. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `cell` _string_ | Cell is the cell the topology generates for. Endpoints of this cell<br />belong to routers that run here; every other endpoint is remote. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `members` _[FabricTopologyMembers](#fabrictopologymembers)_ | Members are the fabric-class BGPRouters, in this namespace, the<br />topology generates peers on. |  |  |
| `mesh` _[FabricMeshRelationship](#fabricmeshrelationship) array_ | Mesh relationships peer every selected endpoint with every other. |  | MaxItems: 8 <br /> |
| `reflection` _[FabricReflectionRelationship](#fabricreflectionrelationship) array_ | Reflection relationships peer every reflector with every client. |  | MaxItems: 8 <br /> |
| `external` _[FabricExternalRelationship](#fabricexternalrelationship) array_ | External relationships peer members with routers no topology<br />manages, such as providers' and transits'. |  | MaxItems: 32 <br /> |
| `failureDomainLabel` _string_ | FailureDomainLabel is the Node label that gives a local endpoint<br />without spec.failureDomain its failure domain. | topology.kubernetes.io/zone | MaxLength: 317 <br />Pattern: `^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$` <br /> |
| `maxSessionsPerRouter` _integer_ | MaxSessionsPerRouter bounds the peers the topology generates on one<br />router. A topology that would exceed it changes nothing and reports<br />Accepted False. | 64 | Maximum: 1024 <br />Minimum: 1 <br /> |
| `drain` _[FabricTopologyDrain](#fabrictopologydrain)_ | Drain releases the sessions of routers and endpoints whose removal<br />cannot be observed otherwise, such as a router on a node that will<br />never report its retirement. |  |  |


#### FabricTopologyStatus



FabricTopologyStatus is what the generator did on its last pass.



_Appears in:_
- [FabricTopology](#fabrictopology)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the generation the status describes. |  |  |
| `members` _integer_ | Members counts the member routers. |  |  |
| `generated` _integer_ | Generated counts the peers the topology generates and holds as<br />generated. |  |  |
| `conflicting` _integer_ | Conflicting counts the sessions blocked by a conflict. |  |  |
| `missingEndpoints` _integer_ | MissingEndpoints counts the members with no usable endpoint in the<br />routing domain, and external sessions whose source endpoint is<br />missing. |  |  |
| `retained` _integer_ | Retained counts the generated peers the topology no longer generates<br />and keeps until an end is out of service. |  |  |
| `recordsDigest` _string_ | RecordsDigest is the SHA-256 of every FabricEndpoint of the routing<br />domain this cell holds, by name, labels and spec. Cells holding the same<br />records report the same digest. |  | Pattern: `^([0-9a-f]\{64\})?$` <br /> |
| `relationshipsDigest` _string_ | RelationshipsDigest is the SHA-256 of the routing domain and the<br />mesh, reflection and external relationships. Cells generating the two<br />ends of one session from the same relationships report the same<br />digest. |  | Pattern: `^([0-9a-f]\{64\})?$` <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are Accepted, ResolvedRefs, Conflicts, ReleaseHeld and<br />Ready. |  |  |


#### FabricUpdateSource

_Underlying type:_ _string_

FabricUpdateSource is where a generated session is sourced from.

_Validation:_
- Enum: [EndpointAddress None]

_Appears in:_
- [FabricExternalRelationship](#fabricexternalrelationship)
- [FabricMeshRelationship](#fabricmeshrelationship)
- [FabricReflectionRelationship](#fabricreflectionrelationship)

| Field | Description |
| --- | --- |
| `EndpointAddress` | FabricUpdateSourceEndpointAddress sources the session from the local<br />router's own endpoint address on the transport.<br /> |
| `None` | FabricUpdateSourceNone leaves the source to the router's route to the<br />peer, for directly connected links.<br /> |


#### LargeCommunityAction



LargeCommunityAction sets large communities on a route.



_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `operation` _[CommunityOperation](#communityoperation)_ | Operation is Add or Replace. |  | Enum: [Add Replace] <br /> |
| `values` _string array_ | Values are ASN:NN:NN large communities. |  | MaxItems: 32 <br />MinItems: 1 <br />items:MaxLength: 32 <br /> |


#### LocalObjectRef



LocalObjectRef references an object of the kind the field names, in the
referrer's namespace.



_Appears in:_
- [BGPPeerFamilySettings](#bgppeerfamilysettings)
- [BGPPeerSpec](#bgppeerspec)
- [BGPPolicyMatch](#bgppolicymatch)
- [BGPPolicySetActions](#bgppolicysetactions)
- [BGPRouterFRR](#bgprouterfrr)
- [BGPRouterFRRRetain](#bgprouterfrrretain)
- [FabricEndpointSpec](#fabricendpointspec)
- [FabricRecovery](#fabricrecovery)
- [FabricRolloutPolicySpec](#fabricrolloutpolicyspec)
- [FabricRouterDeploymentSpec](#fabricrouterdeploymentspec)
- [FabricSessionSettings](#fabricsessionsettings)
- [FabricTopologyDrain](#fabrictopologydrain)
- [FabricTopologyMembers](#fabrictopologymembers)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the referenced object's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |


#### LocalSecretRef



LocalSecretRef references a Secret within the same namespace.
Cross-namespace references are not supported.



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the Secret. |  | MinLength: 1 <br /> |


#### MaxPrefixShutdownAction

_Underlying type:_ _string_

MaxPrefixShutdownAction defines the action taken when a peer exceeds its
maximum-prefix limit.

_Validation:_
- Enum: [warning-only restart shutdown]

_Appears in:_
- [BGPMaximumPrefix](#bgpmaximumprefix)

| Field | Description |
| --- | --- |
| `warning-only` | MaxPrefixShutdownActionWarningOnly logs a warning but keeps the session up.<br /> |
| `restart` | MaxPrefixShutdownActionRestart resets the BGP session when the limit is exceeded.<br /> |
| `shutdown` | MaxPrefixShutdownActionShutdown tears down the BGP session when the limit is exceeded.<br /> |


#### NPTv6Spec



NPTv6Spec is one VRF's stateless RFC 6296 prefix-translation mapping.
ULAPrefix and PublicPrefix must share the same prefix length — RFC 6296
translation only ever rewrites the shared prefix, never the host bits.



_Appears in:_
- [BGPVRFInstanceSpec](#bgpvrfinstancespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ulaPrefix` _string_ | ULAPrefix is this VRF's tenant-facing IPv6 ULA prefix (e.g.<br />"fd20:60::/64"), as presented by backends inside the VRF. |  | Required: \{\} <br /> |
| `publicPrefix` _string_ | PublicPrefix is the externally-routable IPv6 prefix ULAPrefix<br />translates to/from, same prefix length as ULAPrefix. |  | Required: \{\} <br /> |


#### NextHopSet



NextHopSet defines next-hop attribute overrides.



_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `self` _boolean_ | Self sets the next-hop to the local router's BGP peer address. |  |  |
| `address` _string_ | Address sets the next-hop to a specific IP address.<br />Mutually exclusive with self. |  | MaxLength: 45 <br /> |


#### OriginType

_Underlying type:_ _string_

OriginType defines the BGP origin attribute values.

_Validation:_
- Enum: [igp egp incomplete]

_Appears in:_
- [BGPPeerSpec](#bgppeerspec)

| Field | Description |
| --- | --- |
| `igp` |  |
| `egp` |  |
| `incomplete` |  |


#### PortRange



PortRange is an inclusive transport port interval.



_Appears in:_
- [ServiceVIPBindingSpec](#servicevipbindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `start` _integer_ |  |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `end` _integer_ |  |  | Maximum: 65535 <br />Minimum: 1 <br /> |


#### Prefix

_Underlying type:_ _string_

Prefix is an IPv4 or IPv6 CIDR prefix.

_Validation:_
- MaxLength: 64

_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)



#### RedistributeSource

_Underlying type:_ _string_

RedistributeSource is a local routing table source to redistribute into BGP.

_Validation:_
- Enum: [static connected kernel]

_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)

| Field | Description |
| --- | --- |
| `static` | RedistributeSourceStatic redistributes statically configured routes.<br /> |
| `connected` | RedistributeSourceConnected redistributes directly connected interface routes.<br /> |
| `kernel` | RedistributeSourceKernel redistributes routes from the kernel routing table.<br /> |


#### ResolvedRouterConfig



ResolvedRouterConfig holds the configuration resolved and applied to a specific router.



_Appears in:_
- [RouterStatus](#routerstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerID` _string_ | RouterID resolved for this router. |  |  |
| `asNumber` _integer_ | ASNumber is the AS number configured. |  |  |
| `addressFamilies` _[AddressFamily](#addressfamily) array_ | AddressFamilies configured. |  |  |


#### RouteTarget



RouteTarget is a BGP extended community in "ASN:NN" or "IP:NN" format.



_Appears in:_
- [BGPVRFInstanceSpec](#bgpvrfinstancespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `value` _string_ | Value is the route target extended community string.<br />Format: "ASN:NN" (e.g. "65000:100") or "IP:NN" (e.g. "192.0.2.1:100"). |  | MaxLength: 21 <br />MinLength: 1 <br /> |


#### RouterRef



RouterRef is a direct reference to a single BGPRouter by name within the same namespace.



_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)
- [BGPPeerSpec](#bgppeerspec)
- [BGPPolicySpec](#bgppolicyspec)
- [BGPStaticRouteSpec](#bgpstaticroutespec)
- [BGPVRFInstanceSpec](#bgpvrfinstancespec)
- [RouterTarget](#routertarget)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the BGPRouter. |  | MinLength: 1 <br /> |


#### RouterSelector



RouterSelector selects one or more BGPRouter resources by label within the same namespace.



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)
- [BGPPolicySpec](#bgppolicyspec)
- [BGPVRFInstanceSpec](#bgpvrfinstancespec)
- [RouterTarget](#routertarget)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `matchLabels` _object (keys:string, values:string)_ | MatchLabels is a map of key/value label pairs to match. |  |  |
| `matchExpressions` _[LabelSelectorRequirement](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselectorrequirement-v1-meta) array_ | MatchExpressions is a list of label selector requirements. |  |  |


#### RouterStatus



RouterStatus holds per-router reconciliation status used by BGPVRFInstance.



_Appears in:_
- [BGPVRFInstanceStatus](#bgpvrfinstancestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerName` _string_ | RouterName is the name of the BGPRouter this entry describes. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are the per-router conditions. |  |  |
| `resolvedConfig` _[ResolvedRouterConfig](#resolvedrouterconfig)_ | ResolvedConfig holds the configuration that was actually applied. |  |  |


#### RouterTarget



RouterTarget is embedded by resources that bind to one or more BGPRouters.
Each embedding spec states how many of routerRef and routerSelector it
requires: BGPPeer and BGPVRFInstance need exactly one, and BGPPolicy at
most one, since an unbound policy is a reusable definition.



_Appears in:_
- [BGPPeerSpec](#bgppeerspec)
- [BGPPolicySpec](#bgppolicyspec)
- [BGPVRFInstanceSpec](#bgpvrfinstancespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `routerRef` _[RouterRef](#routerref)_ | RouterRef targets a single BGPRouter by name.<br />Mutually exclusive with routerSelector. |  |  |
| `routerSelector` _[RouterSelector](#routerselector)_ | RouterSelector targets one or more BGPRouters by label.<br />Mutually exclusive with routerRef. |  |  |


#### SAFI

_Underlying type:_ _string_

SAFI is the Subsequent Address Family Indicator for a BGP address family.

_Validation:_
- Enum: [unicast evpn]

_Appears in:_
- [AddressFamily](#addressfamily)
- [BGPPeerFamilySettings](#bgppeerfamilysettings)
- [BMPMonitor](#bmpmonitor)

| Field | Description |
| --- | --- |
| `unicast` |  |
| `evpn` |  |


#### SRv6Function

_Underlying type:_ _string_

SRv6Function is the RFC 8986 endpoint behavior applied to a decapsulated
SRv6 packet, addressed via the uSID Argument space per RFC 9800.

_Validation:_
- Enum: [End.DT4 End.DT6 End.DT46]

_Appears in:_
- [BGPAdvertisementSpec](#bgpadvertisementspec)

| Field | Description |
| --- | --- |
| `End.DT4` | SRv6FunctionEndDT4 decapsulates and looks up the packet in an IPv4 VRF.<br /> |
| `End.DT6` | SRv6FunctionEndDT6 decapsulates and looks up the packet in an IPv6 VRF.<br /> |
| `End.DT46` | SRv6FunctionEndDT46 decapsulates and looks up the packet in an IPv4 or<br />IPv6 VRF based on the inner packet's address family.<br /> |


#### SendCommunityType

_Underlying type:_ _string_

SendCommunityType controls which BGP community attributes are propagated
to a peer.

_Validation:_
- Enum: [standard extended large both]

_Appears in:_
- [BGPPeerFamilySettings](#bgppeerfamilysettings)
- [BGPPeerSpec](#bgppeerspec)

| Field | Description |
| --- | --- |
| `standard` | SendCommunityTypeStandard sends only standard communities (ASN:NN).<br /> |
| `extended` | SendCommunityTypeExtended sends only extended communities (Type:Length:Value).<br /> |
| `large` | SendCommunityTypeLarge sends only large communities (ASN:NN:NN).<br /> |
| `both` | SendCommunityTypeBoth sends standard and extended communities, not<br />large ones.<br /> |


#### ServiceEndpoint



ServiceEndpoint publishes a platform service that can be reached through a
VPC attachment. The object describes the service contract; the controller
that owns the service is responsible for its health and implementation.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `ServiceEndpoint` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ServiceEndpointSpec](#serviceendpointspec)_ |  |  |  |
| `status` _[ServiceEndpointStatus](#serviceendpointstatus)_ |  |  |  |


#### ServiceEndpointAttachmentReference



ServiceEndpointAttachmentReference identifies the private attachment that
backs a platform service endpoint.



_Appears in:_
- [ServiceEndpointSpec](#serviceendpointspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ | Namespace is the namespace containing the Cloud API VPCAttachment. |  | MinLength: 1 <br /> |
| `name` _string_ | Name is the Cloud API VPCAttachment name. |  | MinLength: 1 <br /> |


#### ServiceEndpointDeliveryMode

_Underlying type:_ _string_

ServiceEndpointDeliveryMode defines the placement contract for a service.

_Validation:_
- Enum: [NodeLocal PreferNodeLocal]

_Appears in:_
- [ServiceEndpointSpec](#serviceendpointspec)

| Field | Description |
| --- | --- |
| `NodeLocal` | ServiceEndpointDeliveryModeNodeLocal requires the endpoint's backing<br />attachment to be present on each node where selected consumers run.<br /> |
| `PreferNodeLocal` | ServiceEndpointDeliveryModePreferNodeLocal selects a backing attachment on<br />the consumer's node when possible and otherwise tunnels to a ready remote<br />attachment while preserving the consumer source address.<br /> |


#### ServiceEndpointDistribution

_Underlying type:_ _string_

ServiceEndpointDistribution selects how traffic spreads across the
producers on one node.



_Appears in:_
- [ServiceEndpointSpec](#serviceendpointspec)

| Field | Description |
| --- | --- |
| `Single` | ServiceEndpointDistributionSingle sends every consumer on a node to the<br />one ready producer there.<br /> |
| `Spread` | ServiceEndpointDistributionSpread spreads flows across the healthy<br />producers on the consumer's node.<br /> |


#### ServiceEndpointHealthCheck



ServiceEndpointHealthCheck configures the TCP health check of an endpoint's
producers. A probe opens a TCP connection to the producer attachment's first
IPv6 address, not the endpoint's address, on Port, through the producer's
host-side interface and from that interface's link-local address. A producer
with no IPv6 address is never probed and stays Unknown. A probe succeeds when the handshake completes within
TimeoutSeconds, and fails when the connection is refused, reset or times
out. A producer's decision changes after UnhealthyThreshold consecutive
failures or HealthyThreshold consecutive successes. A crashed producer
therefore stops receiving new flows within IntervalSeconds ×
UnhealthyThreshold, plus TimeoutSeconds.



_Appears in:_
- [ServiceEndpointSpec](#serviceendpointspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `port` _integer_ | Port is the TCP port probed on every producer, 1-65535. Unset, it is<br />the endpoint's port, which must then be a tcp port. A udp endpoint must<br />set it to a TCP port its producers listen on. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `intervalSeconds` _integer_ | IntervalSeconds is the time between two probes of one producer. | 5 | Maximum: 300 <br />Minimum: 1 <br /> |
| `timeoutSeconds` _integer_ | TimeoutSeconds is how long a probe waits for the handshake. It must not<br />exceed IntervalSeconds. | 2 | Maximum: 60 <br />Minimum: 1 <br /> |
| `unhealthyThreshold` _integer_ | UnhealthyThreshold is the number of consecutive failed probes that<br />make a producer Unhealthy. | 3 | Maximum: 10 <br />Minimum: 1 <br /> |
| `healthyThreshold` _integer_ | HealthyThreshold is the number of consecutive successful probes that<br />make a producer Healthy. | 3 | Maximum: 10 <br />Minimum: 1 <br /> |


#### ServiceEndpointProducerStatus



ServiceEndpointProducerStatus is one producer's health decision.



_Appears in:_
- [ServiceEndpointStatus](#serviceendpointstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ | Namespace is the producer VPCAttachment's namespace. |  | MinLength: 1 <br /> |
| `name` _string_ | Name is the producer VPCAttachment's name. |  | MinLength: 1 <br /> |
| `attachmentUID` _[UID](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#uid-types-pkg)_ | AttachmentUID is the UID of the VPCAttachment that was probed. |  | Required: \{\} <br /> |
| `node` _string_ | Node is the node that hosts the producer and probes it. |  | MinLength: 1 <br /> |
| `port` _integer_ | Port is the TCP port that was probed. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `state` _[BackendHealthState](#backendhealthstate)_ | State is the decision. Healthy and Unknown producers receive new<br />flows; Unhealthy ones do not, unless every producer on the node is<br />Unhealthy. |  | Enum: [Healthy Unhealthy Unknown] <br />Required: \{\} <br /> |
| `reason` _string_ | Reason is ProbeSucceeded, ProbeFailed, Pending or ProbeUnavailable. |  | MaxLength: 64 <br />Required: \{\} <br /> |
| `message` _string_ | Message is the last probe error, when there is one. |  | MaxLength: 1024 <br /> |
| `lastTransitionTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | LastTransitionTime is when State last changed. |  | Required: \{\} <br /> |


#### ServiceEndpointReference



ServiceEndpointReference identifies a ServiceEndpoint in the policy's
namespace.



_Appears in:_
- [ServiceRoutePolicySpec](#serviceroutepolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the ServiceEndpoint name. |  | MinLength: 1 <br /> |


#### ServiceEndpointSpec



ServiceEndpointSpec defines a platform service address and its scope.



_Appears in:_
- [ServiceEndpoint](#serviceendpoint)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `serviceClass` _string_ | ServiceClass identifies the platform capability implemented by this<br />endpoint, for example "ipv6-egress-dns". |  | MinLength: 1 <br />Required: \{\} <br /> |
| `address` _string_ | Address is the stable address that consumers use to reach the service. |  | Required: \{\} <br /> |
| `port` _integer_ | Port is the service port. |  | Maximum: 65535 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `deliveryMode` _[ServiceEndpointDeliveryMode](#serviceendpointdeliverymode)_ | DeliveryMode defines how a backing attachment is selected relative to a<br />consumer. PreferNodeLocal uses a ready attachment on the consumer's node<br />when one exists and otherwise falls back to a ready remote attachment.<br />The dataplane preserves the consumer source address. If consumers with<br />overlapping address space present an identical TCP or UDP five-tuple to the<br />same replica, it rejects the later ambiguous flow fail-closed rather than<br />translate the source or risk returning traffic to the wrong VPC. |  | Enum: [NodeLocal PreferNodeLocal] <br />Required: \{\} <br /> |
| `attachmentRef` _[ServiceEndpointAttachmentReference](#serviceendpointattachmentreference)_ | AttachmentRef identifies the Cloud API VPCAttachment that hosts this<br />endpoint when the service is delivered through a private VPC path.<br />The network API keeps this reference opaque; the consuming controller<br />resolves it against the Cloud API. |  |  |
| `attachmentSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | AttachmentSelector selects the Cloud API VPCAttachments that host replicas<br />of this endpoint. Labels used here must be assigned by the platform service<br />controller, not by tenants. The dataplane selects ready replicas for each<br />consumer according to DeliveryMode and Distribution. |  |  |
| `region` _string_ | Region limits endpoint selection to a region. An empty value means the<br />endpoint is not region-scoped. |  |  |
| `distribution` _[ServiceEndpointDistribution](#serviceendpointdistribution)_ | Distribution says how a consumer's traffic reaches the producers on<br />its own node. Single, the default, allows one ready producer per node<br />and VPC and sends every consumer on that node to it; an endpoint that<br />selects more is refused. Spread sends new flows to any producer on the<br />consumer's node that its health check has not found Unhealthy: each<br />TCP connection stays with the producer that received its first packet,<br />and each UDP datagram picks a producer of its own, which suits<br />request/response protocols such as DNS but not ones that need a UDP<br />flow to stay on one producer. An Unhealthy producer keeps its existing<br />TCP connections and replies, and gets new flows again once it is<br />Healthy. When every producer on a node is Unhealthy, all of them stay<br />eligible. A node may hold at most 16 producers of a Spread endpoint. |  | Enum: [Single Spread] <br /> |
| `healthCheck` _[ServiceEndpointHealthCheck](#serviceendpointhealthcheck)_ | HealthCheck configures the TCP health check of a Spread endpoint's<br />producers. Each producer's own node probes it and publishes the<br />decision in status.producers. Required when Distribution is Spread and<br />refused otherwise.<br />Where interface traffic policy is enforced, the producer's policy must<br />allow TCP from fe80::/10 to the health check port on the Private path,<br />and the replies back. |  |  |


#### ServiceEndpointStatus



ServiceEndpointStatus reports what the nodes observe of an endpoint.



_Appears in:_
- [ServiceEndpoint](#serviceendpoint)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `producers` _[ServiceEndpointProducerStatus](#serviceendpointproducerstatus) array_ | Producers holds the health decision of every producer of a Spread<br />endpoint. Each node writes the entries of the producers on that node,<br />under its own field manager, and removes them when the producer stops<br />being selected. An entry whose attachmentUID no longer matches the<br />attachment of that name describes an earlier attachment and is ignored. |  | MaxItems: 4096 <br /> |


#### ServiceRouteAuthorization



ServiceRouteAuthorization defines persistent or time-bounded access.



_Appears in:_
- [ServiceRoutePolicySpec](#serviceroutepolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `persistent` _boolean_ | Persistent retains access until policy withdrawal or VPC lifetime replacement. |  |  |
| `validUntil` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | ValidUntil is the absolute UTC deadline for requests and existing replies.<br />Node controllers reject deadlines more than two minutes in the future. |  |  |


#### ServiceRouteFrontend



ServiceRouteFrontend declares the consumer-facing service address.



_Appears in:_
- [ServiceRoutePolicySpec](#serviceroutepolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `address` _string_ | Address is translated to the ServiceEndpoint address for requests and is<br />restored as the source address for replies. |  |  |


#### ServiceRouteNodeStatus



ServiceRouteNodeStatus acknowledges one node's current programmed path.



_Appears in:_
- [ServiceRoutePolicyStatus](#serviceroutepolicystatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `nodeName` _string_ |  |  |  |
| `policyUID` _string_ |  |  |  |
| `observedGeneration` _integer_ |  |  |  |
| `inputDigest` _string_ |  |  |  |
| `ready` _boolean_ |  |  |  |
| `validUntil` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ |  |  |  |


#### ServiceRoutePolicy



ServiceRoutePolicy selects VPC attachments that should receive a route to a
platform ServiceEndpoint. The selector is evaluated by the network control
plane; Galactic compiles the selected attachments into dataplane state.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `ServiceRoutePolicy` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ServiceRoutePolicySpec](#serviceroutepolicyspec)_ |  |  |  |
| `status` _[ServiceRoutePolicyStatus](#serviceroutepolicystatus)_ |  |  |  |


#### ServiceRoutePolicySpec



ServiceRoutePolicySpec defines service selection and attachment eligibility.



_Appears in:_
- [ServiceRoutePolicy](#serviceroutepolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `serviceRef` _[ServiceEndpointReference](#serviceendpointreference)_ | ServiceRef identifies the ServiceEndpoint in this namespace. |  | Required: \{\} <br /> |
| `consumerVPCRef` _[ServiceRouteVPCReference](#serviceroutevpcreference)_ | ConsumerVPCRef pins authorization to the immutable lifetime of the VPC<br />selected by AttachmentSelector. Galactic resolves the name through the<br />Cloud API and requires both the live name and UID to match. |  |  |
| `frontend` _[ServiceRouteFrontend](#serviceroutefrontend)_ | Frontend is the address presented inside the consumer VPC. When set,<br />Galactic translates it to the ServiceEndpoint address and restores it on<br />replies. |  |  |
| `authorization` _[ServiceRouteAuthorization](#servicerouteauthorization)_ | Authorization defines the lifetime of translated service access. |  |  |
| `attachmentSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | AttachmentSelector selects eligible VPC attachments by authoritative<br />labels. Labels that grant access to platform services must be assigned by<br />the network control plane, not by tenants. |  | Required: \{\} <br /> |
| `protocolPorts` _[ServiceRouteProtocolPort](#servicerouteprotocolport) array_ | ProtocolPorts limits the traffic that the route is intended to carry.<br />An empty list means the endpoint's declared port and protocol are used. |  |  |
| `region` _string_ | Region limits selected attachments to a region. An empty value means the<br />policy applies in every region where the endpoint is available. |  |  |


#### ServiceRoutePolicyStatus



ServiceRoutePolicyStatus contains policy conditions and fenced node reports.



_Appears in:_
- [ServiceRoutePolicy](#serviceroutepolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains durable acceptance and service-availability state. |  |  |
| `nodes` _[ServiceRouteNodeStatus](#serviceroutenodestatus) array_ | Nodes contains short-lived acknowledgments written by trusted node controllers.<br />Consumers require current UID, generation, input digest, and unexpired reports. |  |  |


#### ServiceRouteProtocolPort



ServiceRouteProtocolPort identifies an allowed transport protocol and port.



_Appears in:_
- [ServiceRoutePolicySpec](#serviceroutepolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `port` _integer_ | Port is the transport port. |  | Maximum: 65535 <br />Minimum: 1 <br />Required: \{\} <br /> |


#### ServiceRouteVPCReference



ServiceRouteVPCReference identifies one immutable Cloud API VPC lifetime.



_Appears in:_
- [ServiceRoutePolicySpec](#serviceroutepolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the VPC name in the policy namespace. |  | MinLength: 1 <br /> |
| `uid` _string_ | UID is the Kubernetes UID of that VPC lifetime. |  | MinLength: 1 <br /> |


#### ServiceVIPBinding



ServiceVIPBinding drives one worker node's backend-side half of the
DSR/Maglev load-balancer datapath: it tells the node which service VIP a
specific local backend must be reachable on, so the backend can reply to
clients directly (the "Direct Server Return" this design depends on —
see NetworkGateway's doc comment). Generated, never written by users:
galactic-router on each worker node writes one object per (service, VIP,
backend) for every backend a NetworkService's BackendSelector places on that
node, owned by the service, and the same process's per-node reconciler
consumes it.

EgressKind decides which of two backend mechanisms this object drives,
mirroring the same veth/tap fork the SRv6 uSID decap datapath already
has (internal/plumbing/ebpf/usidmap's egress_kind field). Both mechanisms
now converge on the same VIP-boundary substitution
(BackendAddress:BackendPort for VIPAddress:Port at the SRv6 uSID TC-BPF
boundary, usid_ingress's inbound half / usid_egress's outbound half) —
required for both, not just tap, since a decapsulated ingress packet is
delivered into the owning tenant's own VRF routing table, which has no
route to an address bound outside that VRF (found live: see galactic's
ServiceVIPBindingReconciler doc comment):

  - veth (container backend): the node ALSO binds VIPAddress on its own
    galactic-vip0 dummy interface (internal/plumbing/vip's
    Bind/Unbind/Verify in galactic) — this alone does not deliver
    anything to the backend pod (galactic-vip0 lives in the node's root
    namespace, not the tenant's VRF), but still lets the node itself
    verifiably answer on the VIP.
  - tap (VM backend): there is no guest-side configuration capability in
    this repo by design (internal/cnitap's own doc comment), so the
    substitution above is this kind's *only* delivery mechanism — the
    guest OS never needs to know the VIP exists at all.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `ServiceVIPBinding` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[ServiceVIPBindingSpec](#servicevipbindingspec)_ |  |  |  |
| `status` _[ServiceVIPBindingStatus](#servicevipbindingstatus)_ |  |  |  |


#### ServiceVIPBindingEgressKind

_Underlying type:_ _string_

ServiceVIPBindingEgressKind mirrors usidmap's EgressKindVeth/EgressKindTap
constants at the API layer — see ServiceVIPBinding's doc comment.

_Validation:_
- Enum: [veth tap]

_Appears in:_
- [ServiceVIPBindingSpec](#servicevipbindingspec)

| Field | Description |
| --- | --- |
| `veth` | ServiceVIPBindingEgressKindVeth selects the netns-bind mechanism.<br /> |
| `tap` | ServiceVIPBindingEgressKindTap selects the transparent tap-boundary<br />translation mechanism.<br /> |


#### ServiceVIPBindingHealth



ServiceVIPBindingHealth is the health decision for a binding's backend. A
decision describes one backend: the VPCAttachment with AttachmentUID, probed
on Port. A reader treats a decision whose attachment UID or port does not
match the backend it is checking as Unknown.



_Appears in:_
- [ServiceVIPBindingStatus](#servicevipbindingstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `lastProbeTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | LastProbeTime is refreshed after every probe for FailClosed services. |  |  |
| `observedGeneration` _integer_ | ObservedGeneration identifies the NetworkService configuration probed. |  |  |
| `state` _[BackendHealthState](#backendhealthstate)_ | State is the decision. |  | Enum: [Healthy Unhealthy Unknown] <br />Required: \{\} <br /> |
| `reason` _string_ | Reason is ProbeSucceeded, ProbeFailed, Pending or ProbeUnavailable. |  | MaxLength: 64 <br />Required: \{\} <br /> |
| `message` _string_ | Message is the last probe error, when there is one. |  | MaxLength: 1024 <br /> |
| `attachmentUID` _[UID](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#uid-types-pkg)_ | AttachmentUID is the UID of the VPCAttachment that held the backend's<br />address when the decision was made. |  | Required: \{\} <br /> |
| `port` _integer_ | Port is the TCP port that was probed. |  | Maximum: 65535 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `lastTransitionTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | LastTransitionTime is when State last changed. |  | Required: \{\} <br /> |


#### ServiceVIPBindingSourceReference



ServiceVIPBindingSourceReference is immutable authority for a coordinated translation.



_Appears in:_
- [ServiceVIPBindingSpec](#servicevipbindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ |  |  | MinLength: 1 <br /> |
| `name` _string_ |  |  | MinLength: 1 <br /> |
| `uid` _[UID](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#uid-types-pkg)_ |  |  | MinLength: 1 <br />Type: string <br /> |
| `allocationUID` _string_ |  |  | MinLength: 1 <br /> |


#### ServiceVIPBindingSpec



ServiceVIPBindingSpec defines the desired VIP binding/translation state.



_Appears in:_
- [ServiceVIPBinding](#servicevipbinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `sourceRef` _[ServiceVIPBindingSourceReference](#servicevipbindingsourcereference)_ | SourceRef binds generated coordinated translations to one source allocation. |  |  |
| `targetRef` _[TargetRef](#targetref)_ | TargetRef identifies the Node this binding applies to. |  | Required: \{\} <br /> |
| `vpcRef` _string_ | VPCRef is the opaque identifier of the VPC the backend belongs to,<br />copied from the owning NetworkService. It names the tenant VRF the<br />binding's translation rows are written for, so two tenants using the<br />same backend address on one node never share a row. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `vipAddress` _string_ | VIPAddress is the service VIP the backend must be reachable on. |  | Required: \{\} <br /> |
| `port` _integer_ | Port is the VIP-facing port traffic arrives on. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `portRange` _[PortRange](#portrange)_ | PortRange translates an inclusive IPv6 UDP interval without changing ports.<br />It replaces Port and requires BackendPort to be omitted. |  |  |
| `backendAddress` _string_ | BackendAddress is the backend's own real address (its pod-netns<br />address for a veth backend, or its actual guest-facing address for a<br />tap backend) — the VIP-boundary substitution target for both kinds<br />now (see EgressKind's own doc comment for why veth needs this too,<br />not just tap). +optional at the API level for the same reason<br />EgressKind itself carries no matching CEL requirement; the<br />reconciler validates it's set for either kind before doing anything. |  |  |
| `backendPort` _integer_ | BackendPort is the backend's own real port, paired with<br />BackendAddress — required for both kinds, see that field's doc<br />comment. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `egressKind` _[ServiceVIPBindingEgressKind](#servicevipbindingegresskind)_ | EgressKind selects which backend mechanism this binding drives. |  | Enum: [veth tap] <br />Required: \{\} <br /> |


#### ServiceVIPBindingStatus



ServiceVIPBindingStatus defines the observed state of a ServiceVIPBinding.



_Appears in:_
- [ServiceVIPBinding](#servicevipbinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `sourceAuthorityEnforced` _boolean_ | SourceAuthorityEnforced confirms terminal source-allocation checks before map writes. |  |  |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource,<br />including Bound (set True once internal/plumbing/vip.Verify or the<br />equivalent tap-translation-table check confirms the backend is<br />actually reachable on VIPAddress, not merely that the bind/table-write<br />call itself returned nil). |  |  |
| `health` _[ServiceVIPBindingHealth](#servicevipbindinghealth)_ | Health is the health decision for this binding's backend, set by<br />galactic-router on the backend's node while the owning NetworkService<br />has a healthCheck, and cleared once it has none. Every binding of one<br />backend carries the same decision. |  |  |


#### StandardCommunityAction



StandardCommunityAction sets standard communities on a route.



_Appears in:_
- [BGPPolicySetActions](#bgppolicysetactions)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `operation` _[CommunityOperation](#communityoperation)_ | Operation is Add or Replace. |  | Enum: [Add Replace] <br /> |
| `values` _string array_ | Values are ASN:NN communities or FRR's well-known names. A<br />BGPCommunitySet matches fewer well-known names than an action can set. |  | MaxItems: 32 <br />MinItems: 1 <br />items:MaxLength: 21 <br /> |


#### TargetRef



TargetRef identifies the execution target for a BGPRouter.
Supported values for kind: Node.



_Appears in:_
- [BGPRouterSpec](#bgprouterspec)
- [EgressShardSpec](#egressshardspec)
- [ServiceVIPBindingSpec](#servicevipbindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `kind` _string_ | Kind is the target resource kind (e.g. Node). |  | MinLength: 1 <br /> |
| `name` _string_ | Name is the name of the target resource. |  | MinLength: 1 <br /> |
