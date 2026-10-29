# Instance VPC attachments — `galactic_vpc_instance_*`

See [scraping and component ports](README.md#where-the-metrics-come-from) and [shipped alerts](alerts.md).

`galactic-controller --role=cell` compares each running compute instance's
interfaces with what its pods and the data plane report. An interface counts
as programmed when a pod meets every condition below:

1. The pod carries `networking.datumapis.com/inject-interfaces=true`, has the
   compute `Instance` as its controller, is scheduled and `Running`, and is
   not terminating.
2. The instance's declared interface is bound to a `NetworkInterface`.
3. The `NetworkInterface` names a `VPCAttachment` in `status.attachmentRef`.
4. The pod's Multus `k8s.v1.cni.cncf.io/network-status` annotation lists the
   interface's NetworkAttachmentDefinition, which has the same name as the
   `NetworkInterface`.
5. The attachment's `Programmed` condition is True, and its `status.node` is
   the pod's node.

The controller copies `Programmed` from the `Advertised` condition that
`galactic-router` sets on the attachment's `BGPAdvertisement` from live
GoBGP state. A `Running` pod already has its sandbox, so Multus should already
have attached each interface through the Galactic CNI.

A pod can start on the cluster's default network without Multus, for example
during a node boot. It can report Ready with no VPC connectivity. Its
network-status does not list the attachment, so it is reported as
`PodNotAttached`. That holds even when an earlier pod's advertisement still
keeps the attachment `Programmed` on the same node.

Each instance interface is exported once. It counts as programmed when any
of the instance's running pods passes every condition. Otherwise the series
carries the newest pod's node and reason.

Every replica reads its cache at scrape time, so aggregate replicas with
`max`. Without `--edge`, the controller caches only pods that carry the
injection label. The Edge controllers watch every pod.

| Metric                                            | Type  | Labels                                                                                                            | Meaning                                                                                         |
| ------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `galactic_vpc_instance_interfaces`                | gauge | `state` (`Programmed`, `NotProgrammed`)                                                                           | Interfaces of running instances. Both series are always exported, at 0 when empty               |
| `galactic_vpc_instance_interface_unprogrammed`    | gauge | `instance_namespace`, `compute_instance`, `interface`, `vpc`, `attachment`, `instance_node`, `location`, `reason` | 1 for each interface that no running pod holds programmed. Programmed interfaces have no series |
| `galactic_vpc_instance_interfaces_collect_errors` | gauge | none                                                                                                              | Kinds the last scrape could not list. While above 0, no interface series are exported           |

`instance_node` is the newest running pod's node, and `location` is the
instance's `spec.location`. `vpc` and `attachment` are empty when the
interface does not resolve to an attachment. `reason` takes one of these
values:

| `reason`                  | Meaning                                                                                                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PodNotAttached`          | The pod's network-status lists no network for the attachment, or the pod has no network-status                                                                                        |
| `NetworkStatusUnreadable` | The pod's network-status is not valid JSON                                                                                                                                            |
| `AwaitingDataPlane`       | The pod is attached, but no node ever advertised the attachment                                                                                                                       |
| `NodeMismatch`            | The attachment is programmed, but from a node other than the pod's                                                                                                                    |
| `InterfaceUnbound`        | The instance has no bound `NetworkInterface` for the declared interface                                                                                                               |
| `AttachmentMissing`       | The `NetworkInterface` names no Galactic `VPCAttachment`, or the attachment it names does not exist. That includes an interface that still references the former attachment API group |
| any other value           | The attachment's `Programmed` reason, as `galactic-router` reported it, such as `AdvertisementWithdrawn`                                                                              |

A failed list would make every interface that depends on it look
unprogrammed. Until the list succeeds again, the collector exports only the
error gauge.

This comparison doesn't cover instances whose runtime starts no pod.
