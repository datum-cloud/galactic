# Consolidating the cloud and network APIs

This change moves the `cloud` and `network` main-branch API types and the cloud
API types into Galactic. The served API group for VPC, BGP, gateway, traffic
policy, and FabricQuery resources is `galactic.datumapis.com/v1alpha1`.
`NetworkRule` is now `NetworkService`, matching the network main branch.

The source revisions are cloud `55c38b5`, network `5a51626`, and Galactic
`c1769cb`. The VPC, subnet status, and attachment reconcilers run in the NSO
cell manager with `galactic.enabled: true` and the cell's `attachmentMode`.
The Galactic cell role retains BGP status projection and traffic policy. The central fabric identity reconciler
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
   requests to the new controllers. Upgrade NSO's cell manager with Galactic
   reconciliation disabled until the old cell writer is stopped.
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
5. Stop the old cloud cell controller before enabling Galactic reconciliation
   in NSO's cell manager, so only one controller writes each
   NetworkAttachmentDefinition and NSO `NetworkInterface` status. Configure
   the correct `galactic.attachmentMode` for the cell. NSO reuses the legacy NAD's VPC and
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

NSO writes `NetworkInterfaceAttachmentRef.APIGroup` as
`galactic.datumapis.com` when its cell reconciler creates a new attachment.
The tenant-facing NSO CRDs remain in `networking.datumapis.com`. Galactic's
BGP reconciler projects data-plane programming status to the Galactic
attachment and NSO interface and claim.

The old group's VPC finalizers require the old controller to finish deletion,
or an operator-reviewed cleanup after the old objects are no longer serving.
Do not remove old CRDs while objects still carry finalizers or while a node
still depends on their advertisements.

## Retiring the old API groups

The new Galactic binaries read and write `galactic.datumapis.com`. Old
`network.datumapis.com` BGP objects can remain after rollout, including objects
for a workload whose CNI ADD ran before the new group was installed. Their old
`Ready` conditions may be stale; do not treat that status as proof that the new
router still advertises their routes.

Run `hack/audit-legacy-bgp.py --context <cell>` for every migrated cell. For
each old-only advertisement or VRF, check whether its workload still needs a
route. Reattach or restart a live workload and confirm the new-group
advertisement and VRF become ready before removing the old object. Once the
old group has no users, export its objects for the migration record, remove the
old objects, then remove the old CRDs through infra's retirement procedure.
Never delete an old CRD while it still holds objects: Kubernetes deletes those
objects with the CRD.
