# API Reference

## Packages
- [galactic.datumapis.com/v1alpha1](#galacticdatumapiscomv1alpha1)


## galactic.datumapis.com/v1alpha1

Package v1alpha1 contains Galactic's own API, galactic.datumapis.com/v1alpha1:
TrafficPolicy and TrafficPolicyBinding, the per-interface ingress and
egress policy the CNI datapath enforces (see
docs/enhancements/networking/interface-traffic-policy), and EdgeProvider
and EdgeService, the Galactic Edge provider registration and tenant grant,
EdgeInstance and EdgeAttachment, a provider pod and its connection to a
granted VPC, and EdgeRoute and EdgeRouteIndex, a prefix's forwarding claim
and the record of every claim accepted in a VPC (see
docs/enhancements/networking/galactic-edge).

### Resource Types
- [EdgeAttachment](#edgeattachment)
- [EdgeInstance](#edgeinstance)
- [EdgeProvider](#edgeprovider)
- [EdgeRoute](#edgeroute)
- [EdgeRouteIndex](#edgerouteindex)
- [EdgeService](#edgeservice)
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


#### ConfigurationKind



ConfigurationKind names the provider-owned resource its services' own
configuration is written in.



_Appears in:_
- [EdgeProviderSpec](#edgeproviderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `group` _string_ | Group is the resource's API group. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `kind` _string_ | Kind is the resource's kind. |  | MaxLength: 63 <br />MinLength: 1 <br /> |




#### DirectionStatus



DirectionStatus reports what one direction's reference resolved to.



_Appears in:_
- [TrafficPolicyBindingStatus](#trafficpolicybindingstatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policy` _[PolicyIdentity](#policyidentity)_ | Policy is the resolved policy, absent while the reference is<br />unresolved. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions include Resolved. |  | MaxItems: 8 <br /> |


#### EdgeAllocation



EdgeAllocation is one client pool address and the attachment holding it.



_Appears in:_
- [EdgeServiceStatus](#edgeservicestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `address` _string_ | Address is the allocated IPv6 address. |  | MaxLength: 39 <br /> |
| `attachment` _string_ | Attachment is the holding EdgeAttachment's namespace and name. |  | MaxLength: 317 <br /> |
| `attachmentUID` _string_ | AttachmentUID is the holding EdgeAttachment's metadata.uid. |  | MaxLength: 36 <br /> |


#### EdgeAttachment



EdgeAttachment is one provider instance's isolated connection to the VPC
its EdgeService grants: an address from the service's client pool, a link
from the pod into the VPC's host VRF on the pod's node and, with
PacketAccess, a TUN device. It lives in the provider's namespace. Its name
is derived from the service and pod UIDs, so a retried create lands on the
same object.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EdgeAttachment` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EdgeAttachmentSpec](#edgeattachmentspec)_ |  |  |  |
| `status` _[EdgeAttachmentStatus](#edgeattachmentstatus)_ |  |  |  |


#### EdgeAttachmentSpec



EdgeAttachmentSpec is an instance's request for one isolated connection to
its service's VPC. The instance writes it at create; a
ValidatingAdmissionPolicy requires podUID to be the pod its token was
issued for.



_Appears in:_
- [EdgeAttachment](#edgeattachment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `providerRef` _[EdgeProviderReference](#edgeproviderreference)_ | ProviderRef is the provider the requesting instance runs. It must be<br />the service's and the instance's provider. The provider's admission<br />binding checks the writer against it. |  |  |
| `serviceRef` _[EdgeServiceReference](#edgeservicereference)_ | ServiceRef is the EdgeService granting the VPC. |  |  |
| `instanceRef` _[EdgeInstanceReference](#edgeinstancereference)_ | InstanceRef is the requesting EdgeInstance. |  |  |
| `podUID` _string_ | PodUID is the requesting pod's metadata.uid. It must equal the<br />instance's. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `contractVersion` _string_ | ContractVersion is the provider contract version the request is<br />written to. |  | MaxLength: 16 <br />MinLength: 1 <br /> |
| `capabilities` _[EdgeCapability](#edgecapability) array_ | Capabilities are the capability versions the attachment uses:<br />SocketAccess, PacketAccess or both. |  | MaxItems: 2 <br />MinItems: 1 <br /> |
| `packetDevice` _[EdgePacketDevice](#edgepacketdevice)_ | PacketDevice owns the TUN device. Required with PacketAccess. |  |  |


#### EdgeAttachmentStatus



EdgeAttachmentStatus is the attachment's lifecycle. A field is written only
by the writer named on it.



_Appears in:_
- [EdgeAttachment](#edgeattachment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are Admitted, Allocated, Draining (core), Programmed,<br />Released (node) and Ready (provider). |  | MaxItems: 8 <br /> |
| `nodeName` _string_ | NodeName is the node that programs the attachment, from its instance.<br />Set by core at admission. |  | MaxLength: 253 <br /> |
| `vpc` _string_ | VPC is the base62 identifier of the service's VPC. Set by core at<br />admission. |  | MaxLength: 16 <br /> |
| `address` _string_ | Address is the attachment's IPv6 address in the VPC, from the<br />service's client pool. Set by core at allocation. |  | MaxLength: 39 <br /> |
| `drainDeadline` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | DrainDeadline is when core deletes an attachment it is draining. |  |  |
| `hostLink` _string_ | HostLink is the host end of the attachment's link. Set by the node. |  | MaxLength: 15 <br /> |
| `podVRF` _string_ | PodVRF is the VRF in the provider pod that the provider binds its<br />sockets to. Set by the node. |  | MaxLength: 15 <br /> |
| `packetDevice` _string_ | PacketDevice is the TUN device in the provider pod. Set by the node<br />for a PacketAccess attachment. |  | MaxLength: 15 <br /> |


#### EdgeCapability



EdgeCapability is a capability a provider implements, at one version, such
as PacketAccess v1.



_Appears in:_
- [EdgeAttachmentSpec](#edgeattachmentspec)
- [EdgeProviderSpec](#edgeproviderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the capability's name. |  | Enum: [SocketAccess PacketAccess PrefixReachability] <br /> |
| `version` _string_ | Version is the capability's version. |  | Pattern: `^v[1-9][0-9]*$` <br /> |


#### EdgeInstance



EdgeInstance is one running Galactic Edge provider pod. Its attachments
name it, and the foundation checks it against the pod it names before
admitting them. Routes name it with its lease's incarnation and epoch, and
their forwarding gates stay open only while that lease is renewed. Its name
is derived from the pod UID, so a retried create lands on the same object.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EdgeInstance` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EdgeInstanceSpec](#edgeinstancespec)_ |  |  |  |


#### EdgeInstanceReference



EdgeInstanceReference names an EdgeInstance in the attachment's namespace.



_Appears in:_
- [EdgeAttachmentSpec](#edgeattachmentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the EdgeInstance's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |


#### EdgeInstanceSpec



EdgeInstanceSpec identifies the provider pod an instance runs in. The pod
writes it at create; a ValidatingAdmissionPolicy requires podUID to be the
pod its token was issued for.



_Appears in:_
- [EdgeInstance](#edgeinstance)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `providerRef` _[EdgeProviderReference](#edgeproviderreference)_ | ProviderRef is the provider the instance runs. The provider's<br />admission binding checks the writer against it. |  |  |
| `podName` _string_ | PodName is the provider pod's name, in the instance's namespace. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `podUID` _string_ | PodUID is the provider pod's metadata.uid. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `nodeName` _string_ | NodeName is the node the pod runs on. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `bootID` _string_ | BootID is the node's boot ID (/proc/sys/kernel/random/boot_id) when<br />the instance was created. Its lease's renew start is on that boot's<br />CLOCK_BOOTTIME, so galactic-edge applies no renewal of an instance<br />whose boot ID is not the node's current one. |  | MaxLength: 36 <br />MinLength: 1 <br /> |


#### EdgePacketDevice



EdgePacketDevice is the owner of a PacketAccess attachment's TUN device,
the user and group the provider opens it as without CAP_NET_ADMIN.



_Appears in:_
- [EdgeAttachmentSpec](#edgeattachmentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `owner` _integer_ | Owner is the user ID allowed to open the device. |  | Maximum: 4.294967294e+09 <br />Minimum: 0 <br /> |
| `group` _integer_ | Group is the group ID allowed to open the device. |  | Maximum: 4.294967294e+09 <br />Minimum: 0 <br /> |


#### EdgeProvider



EdgeProvider registers a Galactic Edge provider: the contract and
capability versions it implements, the ServiceAccounts that act for it, and
the kind of its own configuration.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EdgeProvider` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EdgeProviderSpec](#edgeproviderspec)_ |  |  |  |
| `status` _[EdgeProviderStatus](#edgeproviderstatus)_ |  |  |  |


#### EdgeProviderReference



EdgeProviderReference names an EdgeProvider.



_Appears in:_
- [EdgeAttachmentSpec](#edgeattachmentspec)
- [EdgeInstanceSpec](#edgeinstancespec)
- [EdgeRouteSpec](#edgeroutespec)
- [EdgeServiceSpec](#edgeservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the EdgeProvider's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |


#### EdgeProviderSpec



EdgeProviderSpec is what a provider implements and which identities speak
for it. It grants no tenant authority.



_Appears in:_
- [EdgeProvider](#edgeprovider)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `contractVersions` _string array_ | ContractVersions are the provider contract versions it speaks. |  | MaxItems: 4 <br />MinItems: 1 <br />items:Pattern: ^v[0-9]+((alpha\|beta)[0-9]+)?$ <br /> |
| `capabilities` _[EdgeCapability](#edgecapability) array_ | Capabilities are the capability versions it implements. |  | MaxItems: 16 <br />MinItems: 1 <br /> |
| `serviceAccounts` _[ServiceAccountReference](#serviceaccountreference) array_ | ServiceAccounts are the only identities whose bound tokens act for the<br />provider. A request from any other identity is refused. The<br />foundation's own identities cannot be listed. |  | MaxItems: 16 <br />MinItems: 1 <br /> |
| `configuration` _[ConfigurationKind](#configurationkind)_ | Configuration is the kind of the provider's own per-service<br />configuration. |  |  |


#### EdgeProviderStatus



EdgeProviderStatus records the operator's approval.



_Appears in:_
- [EdgeProvider](#edgeprovider)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `approved` _boolean_ | Approved is set by the operator's approval. No provider identity may<br />write it. An unapproved provider is refused admission, and clearing it<br />revokes every authorization issued to the provider. |  |  |


#### EdgeRoute



EdgeRoute is one prefix's forwarding claim in one VPC: which attachment of
which provider instance forwards the prefix. It lives in the provider's
namespace; its name is derived from the VPC UID and the prefix. Providers
write the claim; only galactic-controller accepts one, and a node opens the
prefix's forwarding gate only for the accepted holder, only while that
holder's instance lease is valid.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EdgeRoute` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EdgeRouteSpec](#edgeroutespec)_ |  |  |  |
| `status` _[EdgeRouteStatus](#edgeroutestatus)_ |  |  |  |


#### EdgeRouteClaim



EdgeRouteClaim is a provider pod's claim on a route: the attachment that
forwards the prefix and the instance lease, at one epoch, that keeps it
forwarding. The pod writes it by compare-and-swap on the route's
resourceVersion. A claim grants nothing until galactic-controller accepts
it into the route's status.



_Appears in:_
- [EdgeRouteSpec](#edgeroutespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `attachment` _string_ | Attachment is the claiming EdgeAttachment's name, in the route's<br />namespace. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `holderPodUID` _string_ | HolderPodUID is the claiming pod's metadata.uid. The provider's<br />admission binding requires it to be the pod the writer's token was<br />issued for. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `holderInstance` _string_ | HolderInstance is the claiming EdgeInstance's name, in the route's<br />namespace. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `instanceEpoch` _integer_ | InstanceEpoch is the epoch of the instance's lease the claim is held<br />under. The claim is valid only while that lease is valid at this epoch. |  | Minimum: 1 <br /> |
| `epoch` _integer_ | Epoch is the claim's epoch. It advances whenever the attachment or the<br />instance epoch changes. |  | Minimum: 1 <br /> |
| `released` _boolean_ | Released reports that the holder of Epoch stopped forwarding and gave<br />the route up. |  |  |


#### EdgeRouteHolder



EdgeRouteHolder is the claim galactic-controller accepted: the only one
any node forwards the prefix for.



_Appears in:_
- [EdgeRouteStatus](#edgeroutestatus)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `epoch` _integer_ | Epoch is the accepted claim epoch. |  | Minimum: 1 <br /> |
| `attachment` _string_ | Attachment is the accepted EdgeAttachment's name, in the route's<br />namespace. |  | MaxLength: 253 <br /> |
| `attachmentUID` _string_ | AttachmentUID is the accepted EdgeAttachment's metadata.uid. |  | MaxLength: 36 <br /> |
| `instance` _string_ | Instance is the accepted EdgeInstance's name, in the route's<br />namespace. |  | MaxLength: 253 <br /> |
| `instanceIncarnation` _string_ | InstanceIncarnation is the incarnation of the instance's lease the<br />route was accepted under. |  | MaxLength: 64 <br /> |
| `instanceEpoch` _integer_ | InstanceEpoch is the epoch of the instance's lease the route was<br />accepted under. |  | Minimum: 1 <br /> |
| `node` _string_ | Node is the node of the attachment, the only node that may forward<br />the prefix. |  | MaxLength: 253 <br /> |
| `vpcNamespace` _string_ | VPCNamespace is the namespace of the VPC, where its EdgeRouteIndex<br />lives. |  | MaxLength: 63 <br /> |


#### EdgeRouteIndex



EdgeRouteIndex is galactic-controller's record of every accepted
EdgeRoute in one VPC. Acceptance is a compare-and-swap on it, so two
controller replicas that both believe they lead cannot accept overlapping
routes. It lives in the VPC's namespace, named by the VPC's UID. Only
galactic-controller reads or writes it.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EdgeRouteIndex` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EdgeRouteIndexSpec](#edgerouteindexspec)_ |  |  |  |


#### EdgeRouteIndexEntry



EdgeRouteIndexEntry is one route the index holds: an accepted holder, or
one whose fencing has not completed since its route was removed or
revoked.



_Appears in:_
- [EdgeRouteIndexSpec](#edgerouteindexspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `prefix` _string_ | Prefix is the route's prefix. |  | MaxLength: 43 <br /> |
| `route` _string_ | Route is the EdgeRoute's namespace and name. |  | MaxLength: 317 <br /> |
| `routeUID` _string_ | RouteUID is the EdgeRoute's metadata.uid. |  | MaxLength: 36 <br /> |
| `epoch` _integer_ | Epoch is the route's last accepted epoch. |  | Minimum: 1 <br /> |
| `attachmentUID` _string_ | AttachmentUID is the accepted attachment's metadata.uid. |  | MaxLength: 36 <br /> |
| `instance` _string_ | Instance is the accepted instance's namespace and name. |  | MaxLength: 317 <br /> |
| `instanceIncarnation` _string_ | InstanceIncarnation is the incarnation of the instance's lease the<br />route was accepted under. |  | MaxLength: 64 <br /> |
| `instanceEpoch` _integer_ | InstanceEpoch is the epoch of the instance's lease the route was<br />accepted under. |  | Minimum: 1 <br /> |
| `node` _string_ | Node is the accepted attachment's node. |  | MaxLength: 253 <br /> |
| `removing` _string_ | Removing, when set, is why the entry is leaving: the route is gone or<br />its holder revoked. The entry stays until the holder's gate is<br />confirmed closed or galactic-controller has waited the takeover<br />interval since it recorded the removal. |  | MaxLength: 64 <br /> |


#### EdgeRouteIndexSpec



EdgeRouteIndexSpec is every route accepted in one VPC.



_Appears in:_
- [EdgeRouteIndex](#edgerouteindex)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpcUID` _string_ | VPCUID is the VPC's metadata.uid, also the index's name. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `routes` _[EdgeRouteIndexEntry](#edgerouteindexentry) array_ | Routes are the accepted routes, keyed by prefix. No two overlap. At<br />most 1024, so a full index stays within etcd's object size limit at<br />its entries' largest. |  | MaxItems: 1024 <br /> |
| `rebuilt` _boolean_ | Rebuilt is set when the index was rebuilt from routes' status after it<br />was lost. Entries of routes deleted meanwhile are gone, so no first<br />claim is accepted until galactic-controller has waited the takeover<br />interval and cleared it. |  |  |


#### EdgeRouteSpec



EdgeRouteSpec is a provider's request to forward one prefix of a VPC
through one of its attachments.



_Appears in:_
- [EdgeRoute](#edgeroute)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `providerRef` _[EdgeProviderReference](#edgeproviderreference)_ | ProviderRef is the provider of the instances that claim the route. |  |  |
| `vpcUID` _string_ | VPCUID is the metadata.uid of the VPC the prefix is in. |  | MaxLength: 36 <br />MinLength: 1 <br /> |
| `prefix` _string_ | Prefix is the IPv6 prefix forwarded, a masked CIDR. It must be inside<br />the service's granted prefixes and must not overlap another route of<br />the VPC. |  | MaxLength: 43 <br /> |
| `incarnation` _string_ | Incarnation identifies this route object across its deletion and<br />recreation, set once at create. A recreated route has a new one, so no<br />acceptance of the old object applies to it. |  | MaxLength: 64 <br />MinLength: 1 <br /> |
| `claim` _[EdgeRouteClaim](#edgerouteclaim)_ | Claim is the current claim on the route. |  |  |


#### EdgeRouteStatus



EdgeRouteStatus is the route's acceptance and the fencing of its accepted
holder.



_Appears in:_
- [EdgeRoute](#edgeroute)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions are Accepted and Claimed, set by galactic-controller. |  | MaxItems: 8 <br /> |
| `accepted` _[EdgeRouteHolder](#edgerouteholder)_ | Accepted is the holder galactic-controller last accepted, written only<br />after the route is committed to its VPC's EdgeRouteIndex. It stays<br />after a revocation, with Accepted False, so the node can confirm the<br />holder's gate closed. |  |  |
| `closedEpoch` _integer_ | ClosedEpoch is the highest accepted epoch whose forwarding gate the<br />accepted holder's node confirmed closed. Only galactic-edge on that<br />node writes it, and it never decreases. |  | Minimum: 0 <br /> |


#### EdgeService



EdgeService grants one Galactic Edge provider the use of one VPC: the
capabilities it may use there and the prefixes it may request. It lives in
the VPC's namespace and is written by the platform authority, never by the
provider. Changing the spec revokes every authorization issued under the
previous generation; deleting it revokes them all.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `EdgeService` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[EdgeServiceSpec](#edgeservicespec)_ |  |  |  |
| `status` _[EdgeServiceStatus](#edgeservicestatus)_ |  |  |  |


#### EdgeServiceReference



EdgeServiceReference names an EdgeService by namespace, name and UID. The
UID pins the attachment to one grant object, so a service deleted and
recreated under the same name does not inherit it.



_Appears in:_
- [EdgeAttachmentSpec](#edgeattachmentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ | Namespace is the EdgeService's namespace, its VPC's namespace. |  | MaxLength: 63 <br />MinLength: 1 <br /> |
| `name` _string_ | Name is the EdgeService's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `uid` _string_ | UID is the EdgeService's metadata.uid. |  | MaxLength: 36 <br />MinLength: 1 <br /> |


#### EdgeServiceSpec



EdgeServiceSpec is a tenant's grant to one provider in one VPC.



_Appears in:_
- [EdgeService](#edgeservice)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `providerRef` _[EdgeProviderReference](#edgeproviderreference)_ | ProviderRef is the only provider the grant authorizes. |  |  |
| `vpcRef` _[EdgeVPCReference](#edgevpcreference)_ | VPCRef is the only VPC the grant authorizes. |  |  |
| `capabilities` _string array_ | Capabilities are the capability names the provider may use in the VPC. |  | MaxItems: 3 <br />MinItems: 1 <br />items:Enum: [SocketAccess PacketAccess PrefixReachability] <br /> |
| `prefixes` _string array_ | Prefixes bound the prefixes the provider may request in the VPC. Each<br />is a masked CIDR. |  | MaxItems: 64 <br />items:MaxLength: 43 <br /> |
| `validUntil` _[Time](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#time-v1-meta)_ | ValidUntil, when set, is the wall-clock time after which the grant<br />authorizes nothing. Admission refuses it, and revokes what it issued,<br />once fewer than the cell's maximum clock skew remain. |  |  |
| `clientPool` _string_ | ClientPool is the IPv6 range, inside the VPC, that attachments take<br />their addresses from: a masked CIDR from /64 to /120. At most 1024 of<br />its addresses are allocated, whatever its size. Pools of services<br />granting the same VPC must not overlap; galactic-controller refuses<br />the attachments of the later of two overlapping services. Without a<br />pool, the service admits no attachment. A pool can be added to a<br />service that has none, and is fixed from then on. |  | MaxLength: 43 <br /> |
| `drainSeconds` _integer_ | DrainSeconds is how long an attachment the foundation revokes keeps<br />its resources before they are released. Unset means 30. |  | Maximum: 300 <br />Minimum: 0 <br /> |


#### EdgeServiceStatus



EdgeServiceStatus reports the grant's admission state.



_Appears in:_
- [EdgeService](#edgeservice)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the generation Conditions describe. |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ | Conditions include Admitted. |  | MaxItems: 8 <br /> |
| `allocations` _[EdgeAllocation](#edgeallocation) array_ | Allocations are the client pool addresses held by attachments. Core<br />writes them with a resourceVersion precondition, so two writers never<br />hand out one address, and removes one only after the attachment's node<br />has released it. |  | MaxItems: 1024 <br /> |


#### EdgeVPCReference



EdgeVPCReference names a VPC in the service's own namespace. UID pins the
grant to one VPC object, so a VPC deleted and recreated under the same name
is not granted.



_Appears in:_
- [EdgeServiceSpec](#edgeservicespec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the VPC's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |
| `uid` _string_ | UID is the VPC's metadata.uid. |  | MaxLength: 36 <br />MinLength: 1 <br /> |


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


#### ServiceAccountReference



ServiceAccountReference names one ServiceAccount.



_Appears in:_
- [EdgeProviderSpec](#edgeproviderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespace` _string_ | Namespace is the ServiceAccount's namespace. |  | MaxLength: 63 <br />MinLength: 1 <br /> |
| `name` _string_ | Name is the ServiceAccount's name. |  | MaxLength: 253 <br />MinLength: 1 <br /> |


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
