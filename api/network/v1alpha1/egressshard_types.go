package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EgressShard marks a single node as a member of the sharded, stateful egress
// translation tier (galactic-nat) — a component deliberately kept off the
// ingress load-balancer's own consistent-hash ring (see NetworkGateway):
// tenant egress traffic (backend -> arbitrary internet destination) is a
// different traffic pattern from ingress (fixed VIP, fixed backend pool)
// and needs its own placement ring, own per-flow state, and its own
// self-routing return path, entirely independent of any NetworkGateway node.
//
// A shard serves one or both address families. NAT66 (IPv6 -> IPv6) and NAT64
// (IPv6 -> IPv4, RFC 6146) are the same function — stateful egress PAT with a
// VRF-scoped session table — over different families, so one shard object
// describes both rather than there being a second, near-duplicate kind.
// Spec.ShardAddressIPv6 and Spec.ShardAddressIPv4 are each assigned only for
// the family this shard translates; a shard with no IPv4 address performs no
// NAT64.
//
// Every shard owns a dedicated, publicly-routable address per family it
// serves, and a flow's allocated masquerade port lives within it — so a reply
// is delivered to the correct shard by ordinary unicast routing alone, with
// no hashing or cross-shard lookup on the return path at all (the "any node
// can determine the owning shard from the tuple alone" property, satisfied by
// construction rather than by a replicated hash table).
//
// A shard is told which addresses to translate to; it does not choose them.
// The controller that owns a cell claims one address per family from the
// addressing service and writes it into this spec, which keeps the
// addressing-service credential off every translating node and keeps the
// allocation request out of the path that attaches a workload. Status reports
// what the node's datapath is actually programmed with, so an unclaimed
// address, a stale datapath, and a divergence between the two are each
// distinguishable.
//
// A shard names nothing that selects it. Which shards serve which consumer
// intent is decided entirely by label selectors evaluated on the selecting
// side (see the LabelEgressShard* keys), so no consumer-facing API appears in
// this group and no reference points from a datapath resource back at the
// resource that placed traffic on it.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=egressshard
// +kubebuilder:printcolumn:name="TARGET",type="string",JSONPath=".spec.targetRef.name"
// +kubebuilder:printcolumn:name="SHARD-SID",type="string",JSONPath=".status.shardSID"
// +kubebuilder:printcolumn:name="IPV6",type="string",JSONPath=".status.shardAddressIPv6"
// +kubebuilder:printcolumn:name="IPV4",type="string",JSONPath=".status.shardAddressIPv4"
// +kubebuilder:printcolumn:name="DRAIN",type="boolean",JSONPath=".spec.drain"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
type EgressShard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressShardSpec   `json:"spec,omitempty"`
	Status EgressShardStatus `json:"status,omitempty"`
}

// Label keys that select the EgressShards serving a given kind of egress.
// They are matched by an ordinary label selector held on the selecting side,
// which is what lets a consumer-facing API in another group place traffic on
// these shards without this group referencing, importing, or depending on
// that API. A shard carrying none of them is selected by nothing and serves
// no traffic.
//
// The pool and cell labels are operator-set placement facts. The family
// labels restate what this spec already assigns, because a selector matches
// labels and cannot read a spec field; whoever writes the addresses writes
// them.
const (
	// LabelEgressShardPool names the operator-defined pool this shard belongs
	// to — the unit a selector picks, not an individual shard. Pools exist so
	// that adding or draining a node changes no selector.
	LabelEgressShardPool string = "galactic.datumapis.com/egress-pool"

	// LabelEgressShardCell names the cell this shard translates in. Egress is
	// realized per cell, so a selector that omits it selects shards in every
	// cell and sends a consumer's traffic out of an arbitrary one.
	LabelEgressShardCell string = "galactic.datumapis.com/egress-cell"

	// LabelEgressShardIPv6 marks a shard that translates to IPv6, set to
	// LabelValueEgressFamilyServed whenever Spec.ShardAddressIPv6 is assigned.
	LabelEgressShardIPv6 string = "galactic.datumapis.com/egress-ipv6"

	// LabelEgressShardIPv4 marks a shard that translates to IPv4, set to
	// LabelValueEgressFamilyServed whenever Spec.ShardAddressIPv4 is assigned.
	LabelEgressShardIPv4 string = "galactic.datumapis.com/egress-ipv4"

	// LabelValueEgressFamilyServed is the only value the family labels carry.
	// Absence, not a false value, means the family is not served: a selector
	// requiring a family must match on presence so that a shard predating
	// these labels never reads as serving one it does not.
	LabelValueEgressFamilyServed string = "true"
)

// ConditionTypeProgrammed indicates whether this node's datapath is
// translating with the addresses this spec assigns. It is distinct from
// Ready, which reports only that the datapath is attached: an attached
// datapath holding no assigned address, or a superseded one, drops or
// mis-sources every flow while reporting Ready.
const ConditionTypeProgrammed string = "Programmed"

// Programmed sub-reasons — used as Programmed.Reason.
const (
	// ProgrammedReasonAddressesProgrammed indicates the datapath is
	// translating with every address this spec assigns.
	ProgrammedReasonAddressesProgrammed string = "AddressesProgrammed"

	// ProgrammedReasonAddressUnassigned indicates this spec assigns no
	// address for any family, so the shard has nothing to translate to and
	// claims no packet.
	ProgrammedReasonAddressUnassigned string = "AddressUnassigned"

	// ProgrammedReasonProgrammingFailed indicates the shard could not program
	// an assigned address into its datapath.
	ProgrammedReasonProgrammingFailed string = "ProgrammingFailed"
)

// AddressClaimRef names the addressing-service claim an assigned address came
// from. It is a record, not a lookup: the addressing service is an aggregated
// API served on a project control-plane path and defines no CustomResourceDefinition,
// so no claim object exists in the cluster a shard runs in and nothing here
// resolves one. Reading it means addressing that project's control plane
// directly, with a credential a translating node is deliberately not given.
//
// Every field is a plain string and this group depends on no addressing-service
// type. The shape matches that service's own opaque cross-API reference, plus
// the project, because a claim is namespaced within a project and a namespace
// name alone does not identify one from outside.
//
// Populate it with the coordinates of the claim whose allocation produced the
// address written alongside it:
//
//	shardAddressIPv6: 2001:db8:f00d::100
//	shardAddressIPv6ClaimRef:
//	  project: datum-network-edge
//	  namespace: egress
//	  name: egress-shard-node-a-ipv6
//
// The claim cannot record this relationship itself. The addressing service
// overwrites a claim's spec.ownerRef on create with the identity that requested
// it, so a claim made by a cell controller is attributed to that controller's
// project rather than to the shard it was made for. Attribution therefore runs
// in this direction only, and an operator asking which claim holds a shard's
// address has this field or nothing.
type AddressClaimRef struct {
	// APIGroup is the group of the claim resource.
	// +optional
	// +kubebuilder:default="ipam.miloapis.com"
	// +kubebuilder:validation:MinLength=1
	APIGroup string `json:"apiGroup,omitempty"`

	// Kind is the kind of the claim resource.
	// +optional
	// +kubebuilder:default="IPClaim"
	// +kubebuilder:validation:MinLength=1
	Kind string `json:"kind,omitempty"`

	// Project is the project whose control plane serves the claim. Required:
	// a claim is namespaced within a project, and this reference is read from
	// outside every project.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Project string `json:"project"`

	// Namespace is the namespace holding the claim within Project.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// Name is the name of the claim. The addressing service derives it from
	// the thing being addressed, so it is stable across a shard's lifetime and
	// is what a replacement finds again.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// EgressShardSpec defines the desired state of an EgressShard.
//
// The address fields are written by the controller that owns the cell, not by
// the shard and not by a consumer. Each is optional: an address the addressing
// service has not yet handed out is absent rather than blank-but-required, so
// a shard object exists from the moment its node is labelled and gains its
// identity afterwards.
//
// Each is also write-once, and cannot be unassigned once assigned. The
// datapath claims a reply by exact match against the address it translates to,
// so reassigning one strands the return traffic of every flow already
// established through it, with no drain and no dual-address grace period
// available to cover the change. A shard holding the wrong address is deleted
// and recreated instead, which breaks those flows at a moment someone chose.
//
// A claim reference alongside an address records where that address came from,
// and is write-once on the same terms. It is deliberately not required with an
// address, in either direction. Requiring an address before a claim reference
// would forbid recording a claim whose allocation has not resolved yet, which
// is the window a restarting controller most needs to see so that it finds the
// claim it already made instead of making a second one. Requiring a claim
// reference before an address would forbid an address allocated by hand, and
// whether such an address may be recorded here at all is an open migration
// question this validation would answer by fiat. An address with no reference
// is therefore accepted and is unattributable, which is a fact about the
// allocation rather than something a schema can repair.
//
// +kubebuilder:validation:XValidation:rule="!(has(oldSelf.shardSID) && size(oldSelf.shardSID) > 0) || (has(self.shardSID) && size(self.shardSID) > 0)",message="shardSID cannot be unassigned once assigned"
// +kubebuilder:validation:XValidation:rule="(has(self.shardAddressIPv4) && size(self.shardAddressIPv4) > 0) == (has(self.nat64Prefix) && size(self.nat64Prefix) > 0)",message="shardAddressIPv4 and nat64Prefix must be set together"
// +kubebuilder:validation:XValidation:rule="!(has(oldSelf.shardAddressIPv6) && size(oldSelf.shardAddressIPv6) > 0) || (has(self.shardAddressIPv6) && size(self.shardAddressIPv6) > 0)",message="shardAddressIPv6 cannot be unassigned once assigned"
// +kubebuilder:validation:XValidation:rule="!(has(oldSelf.shardAddressIPv4) && size(oldSelf.shardAddressIPv4) > 0) || (has(self.shardAddressIPv4) && size(self.shardAddressIPv4) > 0)",message="shardAddressIPv4 cannot be unassigned once assigned"
// +kubebuilder:validation:XValidation:rule="!(has(oldSelf.nat64Prefix) && size(oldSelf.nat64Prefix) > 0) || (has(self.nat64Prefix) && size(self.nat64Prefix) > 0)",message="nat64Prefix cannot be unassigned once assigned"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.shardAddressIPv6ClaimRef) || has(self.shardAddressIPv6ClaimRef)",message="shardAddressIPv6ClaimRef cannot be unassigned once assigned"
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.shardAddressIPv4ClaimRef) || has(self.shardAddressIPv4ClaimRef)",message="shardAddressIPv4ClaimRef cannot be unassigned once assigned"
// +kubebuilder:validation:XValidation:rule="!(has(self.translateWellKnownPrefix) && self.translateWellKnownPrefix) || (has(self.nat64Prefix) && size(self.nat64Prefix) > 0)",message="translateWellKnownPrefix requires nat64Prefix"
type EgressShardSpec struct {
	// TargetRef identifies the Node this shard executes on.
	// +kubebuilder:validation:Required
	TargetRef TargetRef `json:"targetRef"`

	// ShardSID is this shard's own SRv6 uSID, the outer destination a tenant
	// VRF's egress route encapsulates toward. The shard claims a packet by its
	// Block and Node-ID alone, the Argument carrying the tenant, so those 64
	// bits must be reserved for this shard and disjoint from every BGPRouter
	// locator: a value another node already uses silently diverts that node's
	// traffic.
	//
	// Write-once for the same reason the addresses are: every established
	// flow's reply is re-encapsulated from this SID, so changing it strands
	// them. Operator-chosen until the addressing service hands out identifiers
	// of this kind.
	//
	// Empty means no SID is assigned yet, and the shard claims no packet.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || (isIP(self) && ip(self).family() == 6)",message="shardSID must be a valid IPv6 address"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf || oldSelf == ''",message="shardSID is immutable once assigned"
	ShardSID string `json:"shardSID,omitempty"`

	// ShardAddressIPv6 is the dedicated, publicly-routable IPv6 address this
	// shard translates to — every NAT66 masquerade port it allocates lives
	// within this address, so any node can route a reply to the owning shard
	// using ordinary unicast routing on it alone, with no per-flow state
	// lookup anywhere but that shard.
	//
	// Empty means no IPv6 address is assigned to this shard.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || (isIP(self) && ip(self).family() == 6)",message="shardAddressIPv6 must be a valid IPv6 address"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf || oldSelf == ''",message="shardAddressIPv6 is immutable once assigned"
	ShardAddressIPv6 string `json:"shardAddressIPv6,omitempty"`

	// ShardAddressIPv6ClaimRef records the addressing-service claim
	// ShardAddressIPv6 came from — see AddressClaimRef. Set it in the same
	// write as the address whenever that address came from a claim.
	//
	// Nothing here resolves it and no component reads it to program anything;
	// it is the only trail from a translating address back to the allocation
	// accountable for it.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="shardAddressIPv6ClaimRef is immutable once assigned"
	ShardAddressIPv6ClaimRef *AddressClaimRef `json:"shardAddressIPv6ClaimRef,omitempty"`

	// ShardAddressIPv4 is the dedicated, publicly-routable IPv4 address this
	// shard translates to, and the source an IPv4-only destination sees.
	// Unlike ShardAddressIPv6, reachability for it is not established by a
	// BGPAdvertisement into the EVPN fabric: an IPv4 reply arrives from the
	// internet, so the underlay or an upstream announcement must attract this
	// address to this node.
	//
	// Empty means no IPv4 address is assigned to this shard.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || (isIP(self) && ip(self).family() == 4)",message="shardAddressIPv4 must be a valid IPv4 address"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf || oldSelf == ''",message="shardAddressIPv4 is immutable once assigned"
	ShardAddressIPv4 string `json:"shardAddressIPv4,omitempty"`

	// ShardAddressIPv4ClaimRef records the addressing-service claim
	// ShardAddressIPv4 came from — see AddressClaimRef. Set it in the same
	// write as the address whenever that address came from a claim.
	//
	// Nothing here resolves it and no component reads it to program anything;
	// it is the only trail from a translating address back to the allocation
	// accountable for it.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="shardAddressIPv4ClaimRef is immutable once assigned"
	ShardAddressIPv4ClaimRef *AddressClaimRef `json:"shardAddressIPv4ClaimRef,omitempty"`

	// NAT64Prefix is the IPv6 prefix whose synthesized addresses this shard
	// translates to IPv4 — a Datum-operated Network-Specific Prefix, shared
	// fabric-wide, never per-tenant. TranslateWellKnownPrefix adds the RFC 6052
	// Well-Known Prefix alongside it. It must be the prefix the resolver
	// synthesizes into; a shard translating for a different one is a
	// blackhole with no symptom on either side.
	//
	// Set together with ShardAddressIPv4 or not at all: an address with no
	// prefix has nothing to translate for, and a prefix with no address has
	// nothing to translate into. Write-once for the same reason the addresses
	// are: a shard that starts translating a different prefix blackholes every
	// destination the resolver already synthesized into the old one.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || isCIDR(self)",message="nat64Prefix must be a valid CIDR"
	// +kubebuilder:validation:XValidation:rule="self == oldSelf || oldSelf == ''",message="nat64Prefix is immutable once assigned"
	NAT64Prefix string `json:"nat64Prefix,omitempty"`

	// TranslateWellKnownPrefix additionally translates destinations inside the
	// RFC 6052 Well-Known Prefix 64:ff9b::/96 to IPv4 from ShardAddressIPv4, so
	// clients using a public DNS64 resolver reach IPv4 destinations. Requires
	// NAT64Prefix.
	//
	// RFC 6052 §3.1 forbids the Well-Known Prefix from representing non-global
	// IPv4 addresses; the implementation must refuse such destinations.
	//
	// Mutable, unlike NAT64Prefix. Disabling it blackholes every destination
	// clients already resolved into the Well-Known Prefix until their DNS TTLs
	// expire.
	// +optional
	TranslateWellKnownPrefix bool `json:"translateWellKnownPrefix,omitempty"`

	// Drain stops this shard from taking new tenants while it keeps serving
	// the ones it has. Compute nodes that spread egress across a cluster's
	// shards give a draining shard no share of new tenant addresses, but keep
	// sending it every flow already pinned to it until that flow goes idle, so
	// established sessions finish where their translation state lives.
	//
	// It changes nothing on the shard itself: the shard keeps translating,
	// advertising its SID and receiving replies. A shard is safe to remove
	// once its session count has fallen to zero. Clearing it puts the shard
	// back into rotation.
	//
	// Compute nodes that send each tenant to a single configured shard ignore
	// it.
	// +optional
	Drain bool `json:"drain,omitempty"`
}

// EgressShardStatus defines the observed state of an EgressShard.
//
// The address and prefix fields report what this node's datapath is programmed
// with, not what it was asked for. A value here that disagrees with the spec is
// a shard that has not converged; a value here with no counterpart in the spec
// is a shard still translating to an address nothing assigns any more.
type EgressShardStatus struct {
	// ObservedGeneration is the .metadata.generation this status was computed from.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ShardSID is this shard's own uSID locator — a real SRv6 uSID (unlike
	// the ShardAddress fields, which are plain routable addresses),
	// advertised into BGP the same way any other node-reachability route is
	// (a /128 BGPAdvertisement, no VRFID/Function) so every other node learns
	// a kernel SEG6 route toward it before installing a tenant VRF's egress
	// route against it. One SID serves both families: which translation a
	// packet gets is decided from the inner destination, not from a second
	// SID.
	//
	// Reports the SID this node's datapath is programmed with, from
	// Spec.ShardSID.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || (isIP(self) && ip(self).family() == 6)",message="shardSID must be a valid IPv6 address"
	ShardSID string `json:"shardSID,omitempty"`

	// ShardAddressIPv6 is the IPv6 masquerade source this shard's datapath is
	// programmed with. Empty means it translates no IPv6 flow.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || (isIP(self) && ip(self).family() == 6)",message="shardAddressIPv6 must be a valid IPv6 address"
	ShardAddressIPv6 string `json:"shardAddressIPv6,omitempty"`

	// ShardAddressIPv4 is the IPv4 masquerade source this shard's datapath is
	// programmed with. Empty means it performs no NAT64. Publishing it is also
	// what makes the underlay reachability prerequisite in
	// Spec.ShardAddressIPv4 checkable.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || (isIP(self) && ip(self).family() == 4)",message="shardAddressIPv4 must be a valid IPv4 address"
	ShardAddressIPv4 string `json:"shardAddressIPv4,omitempty"`

	// NAT64Prefix is the prefix this shard's datapath is programmed to
	// translate. Empty whenever ShardAddressIPv4 is empty.
	// +optional
	// +kubebuilder:validation:XValidation:rule="self == '' || isCIDR(self)",message="nat64Prefix must be a valid CIDR"
	NAT64Prefix string `json:"nat64Prefix,omitempty"`

	// TranslatesWellKnownPrefix reports whether this shard's datapath is
	// programmed to translate the RFC 6052 Well-Known Prefix 64:ff9b::/96, from
	// Spec.TranslateWellKnownPrefix. False whenever ShardAddressIPv4 is empty.
	// +optional
	TranslatesWellKnownPrefix bool `json:"translatesWellKnownPrefix,omitempty"`

	// Conditions contains the standard conditions for this resource,
	// including Programmed (see ConditionTypeProgrammed).
	//
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EgressShardList is a list of EgressShard resources.
// +kubebuilder:object:root=true
type EgressShardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressShard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EgressShard{}, &EgressShardList{})
}
