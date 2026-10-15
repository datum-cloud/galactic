# API Reference

## Packages
- [galactic.datumapis.com/v1alpha1](#galacticdatumapiscomv1alpha1)


## galactic.datumapis.com/v1alpha1

Package v1alpha1 contains Galactic's own API, galactic.datumapis.com/v1alpha1:
TrafficPolicy and TrafficPolicyBinding, the per-interface ingress and
egress policy the CNI datapath enforces. See
docs/enhancements/networking/interface-traffic-policy for the design.

### Resource Types
- [TrafficPolicy](#trafficpolicy)
- [TrafficPolicyBinding](#trafficpolicybinding)



#### AppliedPolicy



AppliedPolicy is what one node has installed for one direction.



_Appears in:_
- [NodeBindingStatus](#nodebindingstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policy` _[PolicyIdentity](#policyidentity)_ | Policy is the installed policy's identity, absent when nothing is<br />installed and the direction denies as policy_unavailable. |  |  |
| `state` _[AppliedState](#appliedstate)_ | State is Applied when Policy is installed and matches the desired<br />policy, Pending while it is not yet, and Failed when installation<br />failed. A Failed direction keeps enforcing Policy, its last good<br />snapshot, or denies when there is none. |  | Enum: [Applied Pending Failed] <br /> |
| `observedGeneration` _integer_ | ObservedGeneration is the binding generation this entry reflects. |  |  |
| `message` _string_ | Message explains a Pending or Failed state. |  | MaxLength: 1024 <br /> |
| `lastTransitionTime` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | LastTransitionTime is when Policy last changed. |  |  |


#### AppliedState

_Underlying type:_ _string_

AppliedState is how far one node's installation of a direction has got.

_Validation:_
- Enum: [Applied Pending Failed]

_Appears in:_
- [AppliedPolicy](#appliedpolicy)

| Field | Description |
| --- | --- |
| `Applied` | StateApplied means the desired policy is installed.<br /> |
| `Pending` | StatePending means the desired policy is not installed yet.<br /> |
| `Failed` | StateFailed means installing the desired policy failed.<br /> |




#### DirectionStatus



DirectionStatus reports what one direction's reference resolved to.



_Appears in:_
- [TrafficPolicyBindingStatus](#trafficpolicybindingstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policy` _[PolicyIdentity](#policyidentity)_ | Policy is the resolved policy, absent while the reference is<br />unresolved. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions include Resolved. |  | MaxItems: 8 <br /> |


#### ForwardingPath

_Underlying type:_ _string_

ForwardingPath is the trusted forwarding context of a packet. In egress it
is where the workload's packet is going; in ingress, where the delivered
packet came from.

_Validation:_
- Enum: [Private PublicNAT PublicService]

_Appears in:_
- [TrafficRuleMatch](#trafficrulematch)

| Field | Description |
| --- | --- |
| `Private` | PathPrivate is private VPC routing, same-node delivery and private<br />services.<br /> |
| `PublicNAT` | PathPublicNAT is traffic sent toward, or returned from, a NAT shard.<br /> |
| `PublicService` | PathPublicService is public service delivery through a gateway VIP, and<br />the replies sent from that VIP.<br /> |


#### ICMPMatch



ICMPMatch matches an ICMP or ICMPv6 message type, and optionally its code.



_Appears in:_
- [TrafficRuleMatch](#trafficrulematch)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `type` _integer_ | Type is the ICMP or ICMPv6 message type. |  | Maximum: 255 <br />Minimum: 0 <br /> |
| `code` _integer_ | Code is the message code. Omitted, any code matches. |  | Maximum: 255 <br />Minimum: 0 <br /> |


#### IPFamily

_Underlying type:_ _string_

IPFamily is an IP address family.

_Validation:_
- Enum: [IPv4 IPv6]

_Appears in:_
- [TrafficRuleMatch](#trafficrulematch)

| Field | Description |
| --- | --- |
| `IPv4` | IPv4 is IP version 4.<br /> |
| `IPv6` | IPv6 is IP version 6.<br /> |


#### LocalPolicyReference



LocalPolicyReference names a TrafficPolicy in the binding's own namespace.
There is no namespace field, so a binding can never refer to another
tenant's policy.



_Appears in:_
- [TrafficPolicyBindingSpec](#trafficpolicybindingspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the TrafficPolicy's name. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$` <br /> |


#### NodeBindingStatus



NodeBindingStatus is what one node enforces for the interface. Each node
writes only its own entry, and removes it once the interface has left the
node.



_Appears in:_
- [TrafficPolicyBindingStatus](#trafficpolicybindingstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `node` _string_ | Node is the node's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `ingress` _[AppliedPolicy](#appliedpolicy)_ | Ingress is the node's installed ingress policy. |  |  |
| `egress` _[AppliedPolicy](#appliedpolicy)_ | Egress is the node's installed egress policy. |  |  |


#### PolicyIdentity



PolicyIdentity identifies the policy a direction resolved to. UID is the
policy's API UID, or DefaultPolicyUID when the reference is omitted.



_Appears in:_
- [AppliedPolicy](#appliedpolicy)
- [DirectionStatus](#directionstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the policy's name. |  |  |
| `uid` _string_ | UID is the policy's API UID, or DefaultPolicyUID for the built-in<br />default. |  |  |
| `generation` _integer_ | Generation is the policy's metadata.generation, 0 for the built-in<br />default. |  |  |


#### PortRange



PortRange is an inclusive range of transport ports. A single port has equal
endpoints. Port 0 is representable so a rule can match it.



_Appears in:_
- [TrafficRuleMatch](#trafficrulematch)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `start` _integer_ | Start is the first port in the range. |  | Maximum: 65535 <br />Minimum: 0 <br /> |
| `end` _integer_ | End is the last port in the range. |  | Maximum: 65535 <br />Minimum: 0 <br /> |


#### Protocol

_Underlying type:_ _string_

Protocol is an IP protocol a rule can match.

_Validation:_
- Enum: [TCP UDP ICMP ICMPv6]

_Appears in:_
- [TrafficRuleMatch](#trafficrulematch)

| Field | Description |
| --- | --- |
| `TCP` | ProtocolTCP is TCP.<br /> |
| `UDP` | ProtocolUDP is UDP.<br /> |
| `ICMP` | ProtocolICMP is ICMP for IPv4.<br /> |
| `ICMPv6` | ProtocolICMPv6 is ICMP for IPv6.<br /> |


#### RuleAction

_Underlying type:_ _string_

RuleAction is what a rule does with a packet it matches.

_Validation:_
- Enum: [Allow Deny]

_Appears in:_
- [TrafficRule](#trafficrule)

| Field | Description |
| --- | --- |
| `Allow` | ActionAllow forwards the packet.<br /> |
| `Deny` | ActionDeny drops the packet. No ICMP error is sent.<br /> |


#### TrafficPolicy



TrafficPolicy is an ordered list of Allow and Deny rules that a
TrafficPolicyBinding applies to one direction of one VPC interface.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `TrafficPolicy` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[TrafficPolicySpec](#trafficpolicyspec)_ |  |  |  |
| `status` _[TrafficPolicyStatus](#trafficpolicystatus)_ |  |  |  |


#### TrafficPolicyBinding



TrafficPolicyBinding binds an ingress and an egress TrafficPolicy to one
VPC interface. It has no attachment field: it applies to the VPCAttachment
with the same namespace and name, so an interface can never have two
bindings.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `TrafficPolicyBinding` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[TrafficPolicyBindingSpec](#trafficpolicybindingspec)_ |  |  |  |
| `status` _[TrafficPolicyBindingStatus](#trafficpolicybindingstatus)_ |  |  |  |


#### TrafficPolicyBindingSpec



TrafficPolicyBindingSpec names the policy for each direction of one
interface. An omitted reference selects the built-in default, whose only
rule denies everything, for that direction alone.



_Appears in:_
- [TrafficPolicyBinding](#trafficpolicybinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `ingressPolicyRef` _[LocalPolicyReference](#localpolicyreference)_ | IngressPolicyRef is the policy for traffic delivered to the workload. |  |  |
| `egressPolicyRef` _[LocalPolicyReference](#localpolicyreference)_ | EgressPolicyRef is the policy for traffic the workload sends. |  |  |


#### TrafficPolicyBindingStatus



TrafficPolicyBindingStatus separates what the API asked for from what each
node enforces. Admission success is never reported as convergence.



_Appears in:_
- [TrafficPolicyBinding](#trafficpolicybinding)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the generation Ingress and Egress describe. |  |  |
| `ingress` _[DirectionStatus](#directionstatus)_ | Ingress is the resolved ingress reference. |  |  |
| `egress` _[DirectionStatus](#directionstatus)_ | Egress is the resolved egress reference. |  |  |
| `nodes` _[NodeBindingStatus](#nodebindingstatus) array_ | Nodes lists what each node with the interface enforces. |  | MaxItems: 64 <br /> |


#### TrafficPolicySpec



TrafficPolicySpec is an ordered rule list. The first matching rule decides
a packet, and a packet no rule matches is denied.



_Appears in:_
- [TrafficPolicy](#trafficpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `rules` _[TrafficRule](#trafficrule) array_ | Rules are evaluated in order. |  | MaxItems: 64 <br />MinItems: 1 <br /> |


#### TrafficPolicyStatus



TrafficPolicyStatus reports whether the policy is valid and compiles.



_Appears in:_
- [TrafficPolicy](#trafficpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the generation the conditions describe. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions include Accepted, false when the policy fails validation or<br />exceeds the compiled entry limit. |  | MaxItems: 8 <br /> |


#### TrafficRule



TrafficRule is one ordered rule of a TrafficPolicy.



_Appears in:_
- [TrafficPolicySpec](#trafficpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name identifies the rule in status and metrics. It is unique within the<br />policy. Renaming a rule starts a new counter series. |  | MaxLength: 63 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br /> |
| `action` _[RuleAction](#ruleaction)_ | Action is what happens to a packet this rule matches first. |  | Enum: [Allow Deny] <br /> |
| `match` _[TrafficRuleMatch](#trafficrulematch)_ | Match selects packets. Omitted, the rule matches every packet. |  |  |


#### TrafficRuleMatch



TrafficRuleMatch selects packets. Every field that is present must match,
and an omitted field matches anything. Within one list the entries are
alternatives.

Explicit null and empty lists are invalid: omission is the only wildcard.
The fields are nullable so a null reaches admission, where the validating
webhook rejects it.



_Appears in:_
- [TrafficRule](#trafficrule)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `path` _[ForwardingPath](#forwardingpath)_ | Path is the forwarding path. Omitted, any path in the bound direction<br />matches. |  | Enum: [Private PublicNAT PublicService] <br /> |
| `ipFamily` _[IPFamily](#ipfamily)_ | IPFamily restricts the rule to one address family. Omitted, both match,<br />and a packet can only match list entries of its own family. |  | Enum: [IPv4 IPv6] <br /> |
| `protocol` _[Protocol](#protocol)_ | Protocol is the IP protocol. Omitted, any protocol matches, and the rule<br />cannot carry ports or ICMP fields. |  | Enum: [TCP UDP ICMP ICMPv6] <br /> |
| `sourceIPs` _string array_ | SourceIPs are exact source addresses, IPv4 or IPv6. IPv4-mapped IPv6<br />literals and zone identifiers are rejected. Mutually exclusive with<br />SourceCIDRs. |  | MaxItems: 64 <br />MinItems: 1 <br />items:MaxLength: 39 <br />items:XValidation: \{isIP(self) must be an IPv4 or IPv6 address    <nil>\} <br /> |
| `destinationIPs` _string array_ | DestinationIPs are exact destination addresses, IPv4 or IPv6. Mutually<br />exclusive with DestinationCIDRs. |  | MaxItems: 64 <br />MinItems: 1 <br />items:MaxLength: 39 <br />items:XValidation: \{isIP(self) must be an IPv4 or IPv6 address    <nil>\} <br /> |
| `sourceCIDRs` _string array_ | SourceCIDRs are source prefixes. A prefix must have no host bits set.<br />Mutually exclusive with SourceIPs. |  | MaxItems: 64 <br />MinItems: 1 <br />items:MaxLength: 43 <br />items:XValidation: \{isCIDR(self) && cidr(self).ip() == cidr(self).masked().ip() must be a prefix with no host bits set    <nil>\} <br /> |
| `destinationCIDRs` _string array_ | DestinationCIDRs are destination prefixes. A prefix must have no host<br />bits set. Mutually exclusive with DestinationIPs. |  | MaxItems: 64 <br />MinItems: 1 <br />items:MaxLength: 43 <br />items:XValidation: \{isCIDR(self) && cidr(self).ip() == cidr(self).masked().ip() must be a prefix with no host bits set    <nil>\} <br /> |
| `sourcePorts` _[PortRange](#portrange) array_ | SourcePorts are source port ranges. They require protocol TCP or UDP,<br />and ranges must not overlap. |  | MaxItems: 16 <br />MinItems: 1 <br /> |
| `destinationPorts` _[PortRange](#portrange) array_ | DestinationPorts are destination port ranges. They require protocol TCP<br />or UDP, and ranges must not overlap. |  | MaxItems: 16 <br />MinItems: 1 <br /> |
| `icmp` _[ICMPMatch](#icmpmatch)_ | ICMP matches a message type and code. It requires protocol ICMP or<br />ICMPv6. |  |  |


