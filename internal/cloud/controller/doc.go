/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package controller holds the galactic-controller reconcilers and metrics
// collector that project data-plane state onto the Datum API and allocate
// fabric identities.
//
// It creates no VPC, VPCAttachment or NetworkAttachmentDefinition. When
// Galactic integration is enabled the network-services-operator cell manager
// owns those, and docs/controller/README.md describes the split.
//
// With --role=cell, BGPAdvertisementReconciler projects the BGPAdvertisement
// galactic-router publishes onto VPCAttachment, NetworkInterface and
// NetworkInterfaceClaim as Programmed, and InstanceAttachmentCollector reports
// running instances' attachment state. The pod-interface webhook is in
// internal/cloud/webhook. With --role=fabric, NetworkFabricIdentityReconciler
// allocates each network's NetworkFabricIdentity on the federation hub.
package controller

// Leader election elects the one replica that reconciles, so the lease and
// event permissions below are load-bearing rather than boilerplate.
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
