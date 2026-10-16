# API Reference

## Packages
- [galactic.datumapis.com/v1alpha1](#galacticdatumapiscomv1alpha1)


## galactic.datumapis.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the galactic.datumapis.com/v1alpha1 API group.

### Resource Types
- [NetworkFabricIdentity](#networkfabricidentity)
- [VPC](#vpc)
- [VPCAttachment](#vpcattachment)



#### IPAddress

_Underlying type:_ _string_

IPAddress is an IPv4 or IPv6 address with CIDR notation.

_Validation:_
- MaxLength: 64

_Appears in:_
- [VPCAttachmentInterface](#vpcattachmentinterface)



#### Network

_Underlying type:_ _string_

Network is an IPv4 or IPv6 CIDR block (e.g., "10.0.0.0/24").

_Validation:_
- MaxLength: 64

_Appears in:_
- [VPCSpec](#vpcspec)



#### NetworkFabricIdentity



NetworkFabricIdentity tells a location what identity the fabric knows a
network by.

There is one per network, not one per location. A VPC is the network's
realization at a single location and takes its identity from here, which is
what makes the locations of one network the same network on the fabric
instead of unrelated ones that happen to share a name.

This is platform-internal. It is written centrally and carried to the cells
where the network is required; it never appears in a project control plane
and no consumer reads or writes one. The identity is a value the fabric acts
on directly, so it is kept to the platform rather than published beside the
network it belongs to.

This object is managed for you. It follows the Network it was allocated for.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `NetworkFabricIdentity` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[NetworkFabricIdentitySpec](#networkfabricidentityspec)_ | Spec is the whole of this object. There is no status: federation carries<br />configuration to a cell and deliberately does not carry status, so<br />anything a cell has to read has to be here. |  |  |


#### NetworkFabricIdentityNetworkRef



NetworkFabricIdentityNetworkRef identifies the network an identity was
allocated for.



_Appears in:_
- [NetworkFabricIdentitySpec](#networkfabricidentityspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the network's name. |  | Required: \{\} <br /> |


#### NetworkFabricIdentitySpec



NetworkFabricIdentitySpec carries the identity the fabric knows one network
by.



_Appears in:_
- [NetworkFabricIdentity](#networkfabricidentity)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `identity` _integer_ | Identity is what the fabric knows the network by, the same in every<br />location the network reaches. The Route Target is derived from it, which<br />is what makes two locations of one network import each other's routes<br />rather than behave as two networks that share a name. The VRF device is<br />named from it for the same reason.<br />It is an integer rather than an encoded string because a consumer builds<br />`ASN:<identity>` from it and encodes it for its own use. It is 32 bits<br />wide because that is what survives into the Route Target: the fabric<br />truncates, so a wider value would be uniqueness the platform believes it<br />has and the fabric does not.<br />It is never zero and never changes. The fabric embeds it in import policy<br />in every location the network reaches, so a network that changed identity<br />would be a different network to everything already carrying its traffic. |  | Maximum: 4.294967295e+09 <br />Minimum: 1 <br />Required: \{\} <br /> |
| `networkRef` _[NetworkFabricIdentityNetworkRef](#networkfabricidentitynetworkref)_ | NetworkRef names the network this identity belongs to.<br />It carries a name and no UID, deliberately. The identity is a permanent<br />property of a name in a namespace, not of one object's lifetime: a<br />network deleted and recreated under the same name inherits it. A UID here<br />would document the opposite of the rule. |  | Required: \{\} <br /> |


#### NetworkInterfaceRef



NetworkInterfaceRef references a networking.datumapis.com NetworkInterface in
the same namespace.



_Appears in:_
- [VPCAttachmentSpec](#vpcattachmentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the NetworkInterface. |  | MinLength: 1 <br /> |


#### VPC



VPC represents a virtual private cloud — an isolated Layer 2 domain backed
by one or more CIDR blocks.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `VPC` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[VPCSpec](#vpcspec)_ | Desired CIDR address space. |  |  |
| `status` _[VPCStatus](#vpcstatus)_ | Controller-observed state. |  |  |


#### VPCAttachment



VPCAttachment is the Schema for the vpcattachments API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `galactic.datumapis.com/v1alpha1` | | |
| `kind` _string_ | `VPCAttachment` | | |
| `kind` _string_ | Kind is a string value representing the REST resource this object represents.<br />Servers may infer this from the endpoint the client submits requests to.<br />Cannot be updated.<br />In CamelCase.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds |  |  |
| `apiVersion` _string_ | APIVersion defines the versioned schema of this representation of an object.<br />Servers should convert recognized schemas to the latest internal value, and<br />may reject unrecognized values.<br />More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources |  |  |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[VPCAttachmentSpec](#vpcattachmentspec)_ | spec defines the desired state of VPCAttachment |  |  |
| `status` _[VPCAttachmentStatus](#vpcattachmentstatus)_ | status defines the observed state of VPCAttachment |  |  |


#### VPCAttachmentInterface



VPCAttachmentInterface defines the network interface details.



_Appears in:_
- [VPCAttachmentSpec](#vpcattachmentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the interface (e.g., eth0). |  |  |
| `mode` _[VPCAttachmentInterfaceMode](#vpcattachmentinterfacemode)_ | Mode is how the workload consumes the interface, resolved and written by<br />the attachment controller rather than by whoever runs the workload. | Netns | Enum: [Netns Hypervisor HypervisorDeclared] <br /> |
| `addresses` _[IPAddress](#ipaddress) array_ | A list of IPv4 or IPv6 addresses associated with the interface. Empty when<br />the guest manages its own addressing. |  | MaxItems: 16 <br />MaxLength: 64 <br /> |


#### VPCAttachmentInterfaceMode

_Underlying type:_ _string_

VPCAttachmentInterfaceMode is how the workload consumes the interface. It
describes the guest, not the data plane, so a change of implementation on the
data plane side does not move this API.

_Validation:_
- Enum: [Netns Hypervisor HypervisorDeclared]

_Appears in:_
- [VPCAttachmentInterface](#vpcattachmentinterface)

| Field | Description |
| --- | --- |
| `Netns` | VPCAttachmentInterfaceModeNetns moves the interface into the workload's<br />network namespace, which is what a container consumes.<br /> |
| `Hypervisor` | VPCAttachmentInterfaceModeHypervisor hands the interface to a hypervisor as<br />a device, which is what a virtual machine guest consumes.<br /> |
| `HypervisorDeclared` | VPCAttachmentInterfaceModeHypervisorDeclared also hands the interface to a<br />hypervisor as a device. It differs from Hypervisor in who tells the<br />hypervisor that the device exists. Under Hypervisor the hypervisor finds<br />the device from what the node publishes. Under HypervisorDeclared the data<br />plane states the device, its addresses, and its MTU to the hypervisor<br />directly, which is what a guest whose hypervisor reads no node state<br />needs.<br /> |


#### VPCAttachmentSpec



VPCAttachmentSpec defines the desired state of VPCAttachment



_Appears in:_
- [VPCAttachment](#vpcattachment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `vpc` _[VPCRef](#vpcref)_ | VPC this attachment belongs to. |  |  |
| `interfaceRef` _[NetworkInterfaceRef](#networkinterfaceref)_ | NetworkInterface this attachment realizes. |  |  |
| `interface` _[VPCAttachmentInterface](#vpcattachmentinterface)_ | Interface defines the network interface configuration. |  |  |


#### VPCAttachmentStatus



VPCAttachmentStatus defines the observed state of VPCAttachment.

Every field but Conditions is optional: an identifier is recorded before a pod
attaches, and a guest managing its own addressing never reports a subnet.



_Appears in:_
- [VPCAttachment](#vpcattachment)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ |  |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ |  |  |  |
| `vpc` _string_ | Base62-encoded VPC identifier. |  | MaxLength: 16 <br />MinLength: 1 <br /> |
| `vpcAttachment` _string_ | Base62-encoded VPCAttachment identifier. |  | MaxLength: 16 <br />MinLength: 1 <br /> |
| `node` _string_ | Kubernetes node name where the attachment lives. |  | MinLength: 1 <br /> |
| `containerID` _string_ | Full container ID (46 hex characters). |  | MaxLength: 46 <br />MinLength: 46 <br /> |
| `podName` _string_ | Pod name. |  | MinLength: 1 <br /> |
| `hostInterface` _string_ | Host-side veth or tap device name (e.g., "G000000010013H"). |  | MinLength: 1 <br /> |
| `vrfInterface` _string_ | VRF device name, which is per-VPC (e.g., "G000000010V"). |  | MinLength: 1 <br /> |
| `guestInterface` _string_ | Guest-side veth device name (e.g., "G000000010013G"). |  | MinLength: 1 <br /> |
| `podSubnet` _string_ | Allocated subnet in CIDR notation (e.g., "fd00:10:ff01:0:1::/80"). |  | MinLength: 1 <br /> |
| `networkAttachmentDefinition` _string_ | NetworkAttachmentDefinition rendered for this attachment. |  | MinLength: 1 <br /> |


#### VPCRef



VPCRef references a VPC by name within the same namespace.



_Appears in:_
- [VPCAttachmentSpec](#vpcattachmentspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the VPC. |  | MinLength: 1 <br /> |


#### VPCSpec



VPCSpec defines the desired state of a VPC. It specifies the CIDR address space.



_Appears in:_
- [VPC](#vpc)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `networks` _[Network](#network) array_ | CIDR blocks that form the VPC address space. |  | MaxItems: 64 <br />MaxLength: 64 <br />MinItems: 1 <br /> |


#### VPCStatus



VPCStatus defines the observed state of a VPC, populated by the controller.



_Appears in:_
- [VPC](#vpc)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ |  |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v/#condition-v1-meta) array_ |  |  |  |
| `vpc` _string_ | Base62-encoded VPC identifier. |  | MaxLength: 16 <br />MinLength: 1 <br /> |
