# Consolidating the cloud and network APIs

This change moves the `cloud` and `network` main-branch API types and the cloud
controllers into Galactic. The served API group for VPC, BGP, gateway, traffic
policy, and FabricQuery resources is `galactic.datumapis.com/v1alpha1`.
`NetworkRule` is now `NetworkService`, matching the network main branch.

The source revisions are cloud `55c38b5`, network `5a51626`, and Galactic
`c1769cb`. The cloud cell reconcilers run in `galactic-controller --role=cell`
with the traffic-policy reconcilers. The central fabric identity reconciler
runs in the same binary with `--role=fabric` and a separate deployment because
its hub and IPAM credentials do not belong in each cell.

## Cutover sequence

1. Export the existing `cloud.datumapis.com` and `network.datumapis.com`
   resources, including their status, before changing any CRD or controller.
   Keep the old CRDs installed throughout cutover. Kubernetes treats each new
   group as a different resource; installing the Galactic CRDs does not copy
   objects or convert owner references.
2. Apply `config/crd` on the hub and every cell that serves these kinds.
   Apply `config/fabric-api/crd/galactic.datumapis.com_fabricqueries.yaml`
   wherever FabricQuery is served. Install the `galactic-controller` cell
   RBAC, webhook certificate, and both webhook configurations before routing
   requests to the new controller.
3. Deploy `config/galactic-controller/fabric` centrally, with a hub credential
   bound to `config/galactic-controller/fabric/hub-rbac.yaml` on the hub and an
   IPAM credential for the platform project. Confirm the new
   `NetworkFabricIdentity` objects have the same identity values as the old
   objects and have propagated to their cells before stopping the old fabric
   identity controller. The claim names are stable, so the allocator reuses
   the retained IPAM claims.
4. Move the desired BGP, gateway, egress, and service resources to the new
   group before replacing their node controllers. Use the new API schemas;
   `NetworkRule` becomes `NetworkService`. Copy specs and selected labels and
   annotations, not Kubernetes UIDs, resource versions, or status. The old
   objects do not become visible to the new controllers automatically.
5. Stop the old cloud cell controller before starting the new cell role, so
   only one controller writes each NetworkAttachmentDefinition and NSO
   `NetworkInterface` status. Start `galactic-controller --role=cell` with the
   correct `--attachment-mode` for the cell. It reuses the legacy NAD's VPC and
   attachment IDs, transfers its owner reference to the new attachment, and
   updates `NetworkInterface.status.attachmentRef.apiGroup` to
   `galactic.datumapis.com`. On group change it sets `Programmed=Unknown` until
   the new-group BGP advertisement proves programming again.
6. Reattach or roll existing workloads to republish their CNI-created
   `BGPAdvertisement` objects under the new group. Keep old routing state
   available until their new advertisements are present and the NSO interface
   and claim conditions have reconverged. Verify every live interface reports
   the Galactic attachment group and `Programmed=True`, and check gateway
   and BGP node status before retiring old CRDs and controllers.

NSO's `NetworkInterfaceAttachmentRef.APIGroup` is a free-form string written
by the provider. NSO preserves that field and the provider-owned `Programmed`
condition across reconcile, release, and rebind. Its regression test now
covers the change from the old cloud group to the Galactic group; no NSO
controller code change is required for that reference transition.

The old group's VPC finalizers require the old controller to finish deletion,
or an operator-reviewed cleanup after the old objects are no longer serving.
Do not remove old CRDs while objects still carry finalizers or while a node
still depends on their advertisements.
