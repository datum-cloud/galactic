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

// Package controller reconciles VPC and VPCAttachment in a POP cell: it turns a
// NetworkContext into a VPC identity, creates the attachment and the
// NetworkAttachmentDefinition when a NetworkInterface claim is fulfilled,
// reports Prepared, and projects what the galactic data plane published back
// onto the Datum API.
package controller

// Leader election is what serializes identifier allocation, so the lease and
// event permissions below are load-bearing rather than boilerplate.
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
