// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Bounds on a TrafficPolicy. The compiler enforces the same values, so a
// policy the API admits never has to be truncated to fit the datapath.
const (
	// MaxRules is the most rules a TrafficPolicy can hold.
	MaxRules = 64
	// MaxAddresses is the most entries an address or prefix list can hold.
	MaxAddresses = 64
	// MaxPortRanges is the most ranges a port list can hold.
	MaxPortRanges = 16
	// MaxCompiledEntries is the most datapath entries a policy compiles to.
	// A rule compiles to the product of its source, destination and port
	// alternatives.
	MaxCompiledEntries = 256
)

// DefaultPolicyName is the reserved name of the built-in default policy and
// of the representation the controller provisions in each tenant namespace.
const DefaultPolicyName = "default-deny-all"

// DefaultPolicyUID is the synthetic policy UID reported for every direction
// that omits its reference. It is never a Kubernetes UID.
const DefaultPolicyUID = "builtin:default-deny-all:v1"

// DefaultRuleName is the name of the default policy's only rule.
const DefaultRuleName = "deny-all"

// RuleAction is what a rule does with a packet it matches.
// +kubebuilder:validation:Enum=Allow;Deny
type RuleAction string

const (
	// ActionAllow forwards the packet.
	ActionAllow RuleAction = "Allow"
	// ActionDeny drops the packet. No ICMP error is sent.
	ActionDeny RuleAction = "Deny"
)

// ForwardingPath is the trusted forwarding context of a packet. In egress it
// is where the workload's packet is going; in ingress, where the delivered
// packet came from.
// +kubebuilder:validation:Enum=Private;PublicNAT;PublicService
type ForwardingPath string

const (
	// PathPrivate is private VPC routing, same-node delivery and private
	// services.
	PathPrivate ForwardingPath = "Private"
	// PathPublicNAT is traffic sent toward, or returned from, a NAT shard.
	PathPublicNAT ForwardingPath = "PublicNAT"
	// PathPublicService is public service delivery through a gateway VIP, and
	// the replies sent from that VIP.
	PathPublicService ForwardingPath = "PublicService"
)

// IPFamily is an IP address family.
// +kubebuilder:validation:Enum=IPv4;IPv6
type IPFamily string

const (
	// IPv4 is IP version 4.
	IPv4 IPFamily = "IPv4"
	// IPv6 is IP version 6.
	IPv6 IPFamily = "IPv6"
)

// Protocol is an IP protocol a rule can match.
// +kubebuilder:validation:Enum=TCP;UDP;ICMP;ICMPv6
type Protocol string

const (
	// ProtocolTCP is TCP.
	ProtocolTCP Protocol = "TCP"
	// ProtocolUDP is UDP.
	ProtocolUDP Protocol = "UDP"
	// ProtocolICMP is ICMP for IPv4.
	ProtocolICMP Protocol = "ICMP"
	// ProtocolICMPv6 is ICMP for IPv6.
	ProtocolICMPv6 Protocol = "ICMPv6"
)

// PortRange is an inclusive range of transport ports. A single port has equal
// endpoints. Port 0 is representable so a rule can match it.
// +kubebuilder:validation:XValidation:rule="self.start <= self.end",message="start must not exceed end"
type PortRange struct {
	// Start is the first port in the range.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Start int32 `json:"start"`

	// End is the last port in the range.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	End int32 `json:"end"`
}

// ICMPMatch matches an ICMP or ICMPv6 message type, and optionally its code.
type ICMPMatch struct {
	// Type is the ICMP or ICMPv6 message type.
	// +required
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=255
	Type int32 `json:"type"`

	// Code is the message code. Omitted, any code matches.
	// +optional
	// +nullable
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=255
	Code *int32 `json:"code,omitempty"`
}

// TrafficRuleMatch selects packets. Every field that is present must match,
// and an omitted field matches anything. Within one list the entries are
// alternatives.
//
// Explicit null and empty lists are invalid: omission is the only wildcard.
// The fields are nullable so a null reaches admission, where the validating
// webhook rejects it.
//
// +kubebuilder:validation:XValidation:rule="!(has(self.sourceIPs) && has(self.sourceCIDRs))",message="sourceIPs and sourceCIDRs are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="!(has(self.destinationIPs) && has(self.destinationCIDRs))",message="destinationIPs and destinationCIDRs are mutually exclusive"
// +kubebuilder:validation:XValidation:rule="!(has(self.sourcePorts) || has(self.destinationPorts)) || (has(self.protocol) && (self.protocol == 'TCP' || self.protocol == 'UDP'))",message="ports require protocol TCP or UDP"
// +kubebuilder:validation:XValidation:rule="!has(self.icmp) || (has(self.protocol) && (self.protocol == 'ICMP' || self.protocol == 'ICMPv6'))",message="icmp requires protocol ICMP or ICMPv6"
// +kubebuilder:validation:XValidation:rule="!has(self.protocol) || self.protocol != 'ICMP' || !has(self.ipFamily) || self.ipFamily == 'IPv4'",message="protocol ICMP requires ipFamily IPv4"
// +kubebuilder:validation:XValidation:rule="!has(self.protocol) || self.protocol != 'ICMPv6' || !has(self.ipFamily) || self.ipFamily == 'IPv6'",message="protocol ICMPv6 requires ipFamily IPv6"
// +kubebuilder:validation:XValidation:rule="!has(self.sourceIPs) || ((!has(self.ipFamily) || self.sourceIPs.all(a, ip(a).family() == (self.ipFamily == 'IPv4' ? 4 : 6))) && (!has(self.protocol) || self.protocol != 'ICMP' || self.sourceIPs.all(a, ip(a).family() == 4)) && (!has(self.protocol) || self.protocol != 'ICMPv6' || self.sourceIPs.all(a, ip(a).family() == 6)))",message="every sourceIPs entry must match the rule's address family"
// +kubebuilder:validation:XValidation:rule="!has(self.destinationIPs) || ((!has(self.ipFamily) || self.destinationIPs.all(a, ip(a).family() == (self.ipFamily == 'IPv4' ? 4 : 6))) && (!has(self.protocol) || self.protocol != 'ICMP' || self.destinationIPs.all(a, ip(a).family() == 4)) && (!has(self.protocol) || self.protocol != 'ICMPv6' || self.destinationIPs.all(a, ip(a).family() == 6)))",message="every destinationIPs entry must match the rule's address family"
// +kubebuilder:validation:XValidation:rule="!has(self.sourceCIDRs) || ((!has(self.ipFamily) || self.sourceCIDRs.all(c, cidr(c).ip().family() == (self.ipFamily == 'IPv4' ? 4 : 6))) && (!has(self.protocol) || self.protocol != 'ICMP' || self.sourceCIDRs.all(c, cidr(c).ip().family() == 4)) && (!has(self.protocol) || self.protocol != 'ICMPv6' || self.sourceCIDRs.all(c, cidr(c).ip().family() == 6)))",message="every sourceCIDRs entry must match the rule's address family"
// +kubebuilder:validation:XValidation:rule="!has(self.destinationCIDRs) || ((!has(self.ipFamily) || self.destinationCIDRs.all(c, cidr(c).ip().family() == (self.ipFamily == 'IPv4' ? 4 : 6))) && (!has(self.protocol) || self.protocol != 'ICMP' || self.destinationCIDRs.all(c, cidr(c).ip().family() == 4)) && (!has(self.protocol) || self.protocol != 'ICMPv6' || self.destinationCIDRs.all(c, cidr(c).ip().family() == 6)))",message="every destinationCIDRs entry must match the rule's address family"
type TrafficRuleMatch struct {
	// Path is the forwarding path. Omitted, any path in the bound direction
	// matches.
	// +optional
	// +nullable
	Path *ForwardingPath `json:"path,omitempty"`

	// IPFamily restricts the rule to one address family. Omitted, both match,
	// and a packet can only match list entries of its own family.
	// +optional
	// +nullable
	IPFamily *IPFamily `json:"ipFamily,omitempty"`

	// Protocol is the IP protocol. Omitted, any protocol matches, and the rule
	// cannot carry ports or ICMP fields.
	// +optional
	// +nullable
	Protocol *Protocol `json:"protocol,omitempty"`

	// SourceIPs are exact source addresses, IPv4 or IPv6. IPv4-mapped IPv6
	// literals and zone identifiers are rejected. Mutually exclusive with
	// SourceCIDRs.
	// +optional
	// +nullable
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=39
	// +kubebuilder:validation:items:XValidation:rule="isIP(self)",message="must be an IPv4 or IPv6 address"
	SourceIPs []string `json:"sourceIPs,omitempty"`

	// DestinationIPs are exact destination addresses, IPv4 or IPv6. Mutually
	// exclusive with DestinationCIDRs.
	// +optional
	// +nullable
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=39
	// +kubebuilder:validation:items:XValidation:rule="isIP(self)",message="must be an IPv4 or IPv6 address"
	DestinationIPs []string `json:"destinationIPs,omitempty"`

	// SourceCIDRs are source prefixes. A prefix must have no host bits set.
	// Mutually exclusive with SourceIPs.
	// +optional
	// +nullable
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:items:XValidation:rule="isCIDR(self) && cidr(self).ip() == cidr(self).masked().ip()",message="must be a prefix with no host bits set"
	SourceCIDRs []string `json:"sourceCIDRs,omitempty"`

	// DestinationCIDRs are destination prefixes. A prefix must have no host
	// bits set. Mutually exclusive with DestinationIPs.
	// +optional
	// +nullable
	// +listType=set
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=43
	// +kubebuilder:validation:items:XValidation:rule="isCIDR(self) && cidr(self).ip() == cidr(self).masked().ip()",message="must be a prefix with no host bits set"
	DestinationCIDRs []string `json:"destinationCIDRs,omitempty"`

	// SourcePorts are source port ranges. They require protocol TCP or UDP,
	// and ranges must not overlap.
	// +optional
	// +nullable
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(a, self.exists_one(o, o == a)) && self.all(a, self.all(b, a == b || a.end < b.start || b.end < a.start))",message="port ranges must not overlap"
	SourcePorts []PortRange `json:"sourcePorts,omitempty"`

	// DestinationPorts are destination port ranges. They require protocol TCP
	// or UDP, and ranges must not overlap.
	// +optional
	// +nullable
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:rule="self.all(a, self.exists_one(o, o == a)) && self.all(a, self.all(b, a == b || a.end < b.start || b.end < a.start))",message="port ranges must not overlap"
	DestinationPorts []PortRange `json:"destinationPorts,omitempty"`

	// ICMP matches a message type and code. It requires protocol ICMP or
	// ICMPv6.
	// +optional
	// +nullable
	ICMP *ICMPMatch `json:"icmp,omitempty"`
}

// TrafficRule is one ordered rule of a TrafficPolicy.
type TrafficRule struct {
	// Name identifies the rule in status and metrics. It is unique within the
	// policy. Renaming a rule starts a new counter series.
	// +required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Action is what happens to a packet this rule matches first.
	// +required
	Action RuleAction `json:"action"`

	// Match selects packets. Omitted, the rule matches every packet.
	// +optional
	// +nullable
	Match *TrafficRuleMatch `json:"match,omitempty"`
}

// TrafficPolicySpec is an ordered rule list. The first matching rule decides
// a packet, and a packet no rule matches is denied.
type TrafficPolicySpec struct {
	// Rules are evaluated in order.
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:rule="self.all(r, self.exists_one(o, o.name == r.name))",message="rule names must be unique"
	Rules []TrafficRule `json:"rules"`
}

// TrafficPolicyStatus reports whether the policy is valid and compiles.
type TrafficPolicyStatus struct {
	// ObservedGeneration is the generation the conditions describe.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions include Accepted, false when the policy fails validation or
	// exceeds the compiled entry limit.
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// TrafficPolicy is an ordered list of Allow and Deny rules that a
// TrafficPolicyBinding applies to one direction of one VPC interface.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tpol,categories=galactic
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type TrafficPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +required
	Spec TrafficPolicySpec `json:"spec"`

	// +optional
	Status TrafficPolicyStatus `json:"status,omitempty"`
}

// TrafficPolicyList is a list of TrafficPolicy.
// +kubebuilder:object:root=true
type TrafficPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrafficPolicy `json:"items"`
}
