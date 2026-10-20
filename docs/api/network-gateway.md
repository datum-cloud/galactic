# API Reference

## Packages
- [galactic.datumapis.com/v1alpha1](#galacticdatumapiscomv1alpha1)


## galactic.datumapis.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the galactic.datumapis.com/v1alpha1 API group.

### Resource Types
- [EgressShard](#egressshard)
- [NetworkEgressPolicy](#networkegresspolicy)
- [NetworkGateway](#networkgateway)
- [NetworkService](#networkservice)
- [ServiceEndpoint](#serviceendpoint)
- [ServiceRoutePolicy](#serviceroutepolicy)
- [ServiceVIPBinding](#servicevipbinding)



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

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroup` _string_ | APIGroup is the group of the claim resource. | ipam.miloapis.com | MinLength: 1 <br /> |
| `kind` _string_ | Kind is the kind of the claim resource. | IPClaim | MinLength: 1 <br /> |
| `project` _string_ | Project is the project whose control plane serves the claim. Required:<br />a claim is namespaced within a project, and this reference is read from<br />outside every project. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `namespace` _string_ | Namespace is the namespace holding the claim within Project. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `name` _string_ | Name is the name of the claim. The addressing service derives it from<br />the thing being addressed, so it is stable across a shard's lifetime and<br />is what a replacement finds again. |  | MinLength: 1 <br />Required: \{\} <br /> |








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






#### NetworkEgressPolicy



NetworkEgressPolicy enables internet egress for a single tenant
VPC/VPCAttachment, served by the sharded, stateful galactic-nat tier
(see EgressShard). Unlike NetworkService, it carries no VIP/backend/port:
egress is on or off for a (vpcRef, vpcAttachmentRef) pair,
existence-implies-enabled, not a per-flow rule — because the destination
of an egress flow is an arbitrary internet address, not a pre-configured
backend list.

It is namespaced (deployed to galactic-system) and tenant-writable; like
NetworkService's vpcRef, vpcRef/vpcAttachmentRef are opaque string identifiers
because this kind carries identifiers from the VPC API in
api/cloud/v1alpha1 without a Kubernetes object reference. An admission webhook (implemented by the consuming controller) must
verify the requester is authorized for vpcRef/vpcAttachmentRef before a
policy is accepted — see the Accepted condition.

Presence of an accepted NetworkEgressPolicy resolves only *enablement*
(should this tenant's VRF get an egress route toward the shared
translation tier at all) — unlike this type's original design (superseded), there is
no single "assigned gateway node" to compute or pin: any EgressShard may
serve any tenant's flow, chosen by the shard-placement consistent-hash
ring (internal/maglev, keyed on (tenant VRFID, backend, destination) —
see EgressShard's doc comment), not by a per-tenant node assignment stored
here. *Isolation* (preventing two tenants with colliding ULA source
addresses from colliding in the egress connection table) is a separate,
datapath-level concern resolved by tagging each flow with the VRFID
carried in the tenant's own SRv6 Argument, not by anything in this spec.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `NetworkEgressPolicy` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkEgressPolicySpec](#networkegresspolicyspec)_ |  |  |  |
| `status` _[NetworkEgressPolicyStatus](#networkegresspolicystatus)_ |  |  |  |


#### NetworkEgressPolicySpec



NetworkEgressPolicySpec defines the desired egress-enablement state for a
tenant VPC/VPCAttachment.



_Appears in:_
- [NetworkEgressPolicy](#networkegresspolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpcRef` _string_ | VPCRef is the opaque identifier of the target VPC this policy applies<br />to. This repo does not own the VPC API and does not validate the<br />identifier beyond non-emptiness; the admission webhook of the<br />consuming controller is responsible for verifying the requester is<br />authorized for this VPC before the policy is accepted. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `vpcAttachmentRef` _string_ | VPCAttachmentRef is the opaque identifier of the target<br />VPCAttachment this policy applies to. Like VPCRef, this is an opaque<br />string reference validated by the admission webhook, not by this API. |  | MinLength: 1 <br />Required: \{\} <br /> |


#### NetworkEgressPolicyStatus



NetworkEgressPolicyStatus defines the observed state of a
NetworkEgressPolicy.



_Appears in:_
- [NetworkEgressPolicy](#networkegresspolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource,<br />including Accepted (see AcceptedReasonOwnershipVerified /<br />AcceptedReasonOwnershipDenied in rule_types.go, reused as-is here). |  |  |


#### NetworkGateway



NetworkGateway marks a single dedicated gateway-role node as running the
Maglev/DSR consistent-hash L4 load-balancer engine. Exactly one
NetworkGateway exists per gateway node (spec.targetRef.name is the
Kubernetes node name), mirroring the BGPRouter node-scoped root object
pattern. NetworkService resources are served by every NetworkGateway in the
namespace equally (anycast — see NetworkServiceStatus's doc comment); this
object's only job is to identify which nodes participate at all and
surface each node's engine health via Conditions.

This design does no address rewriting on the load-balancing path at all
(DSR — Direct Server Return): the gateway's XDP program picks a backend
via consistent hashing on the flow's 5-tuple and pushes an SRv6 uSID outer
header addressed to the backend's worker node directly, untouched
otherwise. The backend node answers the client directly (see
ServiceVIPBinding) — reply traffic never re-enters this gateway node, so
unlike the Full-NAT design this type originally described, a gateway node
has no SNAT source address of its own to publish and nothing analogous to
sRv6Address/egressAddress/egressSID belongs on this status anymore.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `NetworkGateway` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkGatewaySpec](#networkgatewayspec)_ |  |  |  |
| `status` _[NetworkGatewayStatus](#networkgatewaystatus)_ |  |  |  |


#### NetworkGatewaySpec



NetworkGatewaySpec defines the desired state of a NetworkGateway.



_Appears in:_
- [NetworkGateway](#networkgateway)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRef` _[TargetRef](#targetref)_ | TargetRef identifies the Node this gateway engine executes on. |  | Required: \{\} <br /> |


#### NetworkGatewayStatus



NetworkGatewayStatus defines the observed state of a NetworkGateway.



_Appears in:_
- [NetworkGateway](#networkgateway)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


#### NetworkService



NetworkService defines ingress load-balancing for a single tenant VPC, served
by every NetworkGateway node identically (anycast Direct Server Return —
see NetworkGateway's doc comment). It is namespaced (deployed to
galactic-system) and tenant-writable; vpcRef is an opaque string identifier
because this kind carries identifiers from the VPC API in
api/cloud/v1alpha1 without a Kubernetes object reference. An admission webhook (implemented by the consuming controller) must
verify the requester is authorized for vpcRef before a service is accepted —
see the Accepted condition.

Unlike the earlier Full-NAT design this type originally described, there
is no primary/secondary gateway node for a service: every NetworkGateway
advertises every accepted service's vipAddresses at equal BGP preference,
consistent-hashes the same backend list to the same backend for the same
flow (internal/maglev), and forwards without rewriting anything —
backend selection never needs a single "owning" node the way Full-NAT's
SNAT-source model did.

Backends are not listed. BackendSelector picks the VPCAttachments that
serve the service, so the backend set follows attachments as they are
created, deleted or moved to another node, and galactic-router on each
node generates the ServiceVIPBinding its backends need from the same
selection.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `NetworkService` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkServiceSpec](#networkservicespec)_ |  |  |  |
| `status` _[NetworkServiceStatus](#networkservicestatus)_ |  |  |  |


#### NetworkServiceProtocol

_Underlying type:_ _string_

NetworkServiceProtocol is the IP protocol a VIP or endpoint matches.

The set of values is open-ended. A client reading an object that carries
this type must accept a value it does not recognise, preserve it when it
writes the object back, and treat it as a protocol it cannot act on, never
as tcp or udp. Each field of this type admits only the values it lists, and
the API server refuses any other.



_Appears in:_
- [NetworkServiceSpec](#networkservicespec)
- [ServiceEndpointSpec](#serviceendpointspec)
- [ServiceRouteProtocolPort](#servicerouteprotocolport)
- [ServiceVIPBindingSpec](#servicevipbindingspec)

| Field | Description |
| --- | --- |
| `tcp` | NetworkServiceProtocolTCP matches TCP traffic.<br /> |
| `udp` | NetworkServiceProtocolUDP matches UDP traffic.<br /> |
| `sctp` | NetworkServiceProtocolSCTP matches SCTP traffic (IP protocol 132), which<br />has ports. It is declared but not served yet.<br /> |
| `esp` | NetworkServiceProtocolESP matches IPsec Encapsulating Security Payload<br />traffic (IP protocol 50), which has no ports. It is declared but not<br />served yet.<br /> |
| `gre` | NetworkServiceProtocolGRE matches Generic Routing Encapsulation traffic<br />(IP protocol 47), which has no ports. It is declared but not served yet.<br /> |
| `icmp` | NetworkServiceProtocolICMP matches ICMP traffic: ICMPv6 (IP protocol 58)<br />on an IPv6 VIP and ICMP (IP protocol 1) on an IPv4 VIP. It has no ports.<br />It is declared but not served yet.<br /> |


#### NetworkServiceSpec



NetworkServiceSpec defines the desired ingress load-balancing state for a
tenant VPC.



_Appears in:_
- [NetworkService](#networkservice)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpcRef` _string_ | VPCRef is the opaque identifier of the target VPC this service applies<br />to. This repo does not own the VPC API and does not validate the<br />identifier beyond non-emptiness; the admission webhook of the<br />consuming controller is responsible for verifying the requester is<br />authorized for this VPC before the service is accepted. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `vipAddresses` _string array_ | VIPAddresses is the list of ingress VIP addresses this service provisions<br />on the assigned gateway node(s).<br />Only IPv6 addresses are admitted until the gateway datapath serves IPv4<br />VIPs (datum-cloud/galactic#705). A service created with an IPv4 VIP before<br />this restriction keeps it while the list is unchanged, since the API<br />server ratchets validation of an unchanged field on Kubernetes 1.30 and<br />later; any edit to the list must drop it, and on an older API server any<br />update to such a service is refused. The gateways do not load or advertise<br />an IPv4 VIP. |  | MaxItems: 8 <br />MinItems: 1 <br />Required: \{\} <br />items:MaxLength: 45 <br /> |
| `protocol` _[NetworkServiceProtocol](#networkserviceprotocol)_ | Protocol is the IP protocol this service load-balances on VIPAddresses.<br />The API admits tcp, udp, sctp, esp, gre and icmp, and the gateway<br />datapath serves tcp and udp. A service with any other admitted value is<br />refused with a message saying its protocol is not served yet. sctp has<br />ports and needs Port and BackendPort. esp, gre and icmp have no ports<br />and must set neither; a backend for them is chosen from the client and<br />VIP addresses alone. The set of values is open-ended, so a client must<br />accept and preserve a value it does not recognise, as<br />NetworkServiceProtocol describes. |  | Enum: [tcp udp sctp esp gre icmp] <br />Required: \{\} <br /> |
| `port` _integer_ | Port is the ingress port on VIPAddresses that this service load-balances,<br />1-65535. It is required for a protocol with ports (tcp, udp and sctp)<br />and must be unset for one without (esp, gre and icmp). Zero means unset<br />and is omitted when encoding, and an explicit 0 is refused. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `backendSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | BackendSelector selects the VPCAttachments (galactic.datumapis.com/v1alpha1,<br />in any namespace) that serve this service, matched against each<br />VPCAttachment object's own labels. Only attachments whose status.vpc<br />equals VPCRef are candidates, whatever their labels, so a selector cannot<br />reach into another tenant's VPC. Each selected attachment contributes the<br />IPv6 addresses in its spec.interface.addresses as backends, on<br />BackendPort; the DSR datapath carries IPv6 backends only. An attachment<br />with no status.node or no IPv6 address is not a backend until it has<br />both. An empty selector is rejected rather than read as "every attachment<br />in the VPC". |  | Required: \{\} <br /> |
| `backendPort` _integer_ | BackendPort is the destination port on every selected backend, 1-65535.<br />Like Port, it is required for tcp, udp and sctp and must be unset for<br />esp, gre and icmp. Zero means unset and is omitted when encoding, and an<br />explicit 0 is refused. |  | Maximum: 65535 <br />Minimum: 1 <br /> |


#### NetworkServiceStatus



NetworkServiceStatus defines the observed state of a NetworkService.



_Appears in:_
- [NetworkService](#networkservice)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource. |  |  |


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
| `protocol` _[NetworkServiceProtocol](#networkserviceprotocol)_ | Protocol is the transport protocol accepted by the endpoint. |  | Enum: [tcp udp] <br />Required: \{\} <br /> |
| `deliveryMode` _[ServiceEndpointDeliveryMode](#serviceendpointdeliverymode)_ | DeliveryMode defines how a backing attachment is selected relative to a<br />consumer. PreferNodeLocal uses a ready attachment on the consumer's node<br />when one exists and otherwise falls back to a ready remote attachment.<br />The dataplane preserves the consumer source address. If consumers with<br />overlapping address space present an identical TCP or UDP five-tuple to the<br />same replica, it rejects the later ambiguous flow fail-closed rather than<br />translate the source or risk returning traffic to the wrong VPC. |  | Enum: [NodeLocal PreferNodeLocal] <br />Required: \{\} <br /> |
| `attachmentRef` _[ServiceEndpointAttachmentReference](#serviceendpointattachmentreference)_ | AttachmentRef identifies the Cloud API VPCAttachment that hosts this<br />endpoint when the service is delivered through a private VPC path.<br />The network API keeps this reference opaque; the consuming controller<br />resolves it against the Cloud API. |  |  |
| `attachmentSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#labelselector-v1-meta)_ | AttachmentSelector selects the Cloud API VPCAttachments that host replicas<br />of this endpoint. Labels used here must be assigned by the platform service<br />controller, not by tenants. The dataplane selects one ready replica for<br />each consumer according to DeliveryMode. |  |  |
| `region` _string_ | Region limits endpoint selection to a region. An empty value means the<br />endpoint is not region-scoped. |  |  |


#### ServiceRouteAuthorization



ServiceRouteAuthorization bounds one network authorization episode.



_Appears in:_
- [ServiceRoutePolicySpec](#serviceroutepolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
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
| `authorization` _[ServiceRouteAuthorization](#servicerouteauthorization)_ | Authorization bounds translated access independently of application leases.<br />Only trusted networking integration may renew this deadline. |  |  |
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
| `protocol` _[NetworkServiceProtocol](#networkserviceprotocol)_ | Protocol is the transport protocol. |  | Enum: [tcp udp] <br />Required: \{\} <br /> |
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


#### ServiceVIPBindingSpec



ServiceVIPBindingSpec defines the desired VIP binding/translation state.



_Appears in:_
- [ServiceVIPBinding](#servicevipbinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRef` _[TargetRef](#targetref)_ | TargetRef identifies the Node this binding applies to. |  | Required: \{\} <br /> |
| `vpcRef` _string_ | VPCRef is the opaque identifier of the VPC the backend belongs to,<br />copied from the owning NetworkService. It names the tenant VRF the<br />binding's translation rows are written for, so two tenants using the<br />same backend address on one node never share a row. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `vipAddress` _string_ | VIPAddress is the service VIP the backend must be reachable on. |  | Required: \{\} <br /> |
| `port` _integer_ | Port is the VIP-facing port traffic arrives on. |  | Maximum: 65535 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `protocol` _[NetworkServiceProtocol](#networkserviceprotocol)_ | Protocol is the transport protocol this binding applies to. |  | Enum: [tcp udp] <br />Required: \{\} <br /> |
| `backendAddress` _string_ | BackendAddress is the backend's own real address (its pod-netns<br />address for a veth backend, or its actual guest-facing address for a<br />tap backend) — the VIP-boundary substitution target for both kinds<br />now (see EgressKind's own doc comment for why veth needs this too,<br />not just tap). +optional at the API level for the same reason<br />EgressKind itself carries no matching CEL requirement; the<br />reconciler validates it's set for either kind before doing anything. |  |  |
| `backendPort` _integer_ | BackendPort is the backend's own real port, paired with<br />BackendAddress — required for both kinds, see that field's doc<br />comment. |  | Maximum: 65535 <br />Minimum: 1 <br /> |
| `egressKind` _[ServiceVIPBindingEgressKind](#servicevipbindingegresskind)_ | EgressKind selects which backend mechanism this binding drives. |  | Enum: [veth tap] <br />Required: \{\} <br /> |


#### ServiceVIPBindingStatus



ServiceVIPBindingStatus defines the observed state of a ServiceVIPBinding.



_Appears in:_
- [ServiceVIPBinding](#servicevipbinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the .metadata.generation this status was computed from. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions contains the standard conditions for this resource,<br />including Bound (set True once internal/plumbing/vip.Verify or the<br />equivalent tap-translation-table check confirms the backend is<br />actually reachable on VIPAddress, not merely that the bind/table-write<br />call itself returned nil). |  |  |


#### TargetRef



TargetRef identifies the execution target for a BGPRouter.
Supported values for kind: Node.



_Appears in:_
- [EgressShardSpec](#egressshardspec)
- [NetworkGatewaySpec](#networkgatewayspec)
- [ServiceVIPBindingSpec](#servicevipbindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `kind` _string_ | Kind is the target resource kind (e.g. Node). |  | MinLength: 1 <br /> |
| `name` _string_ | Name is the name of the target resource. |  | MinLength: 1 <br /> |
