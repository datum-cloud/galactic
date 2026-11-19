// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"strings"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/plumbing/intf"
)

// InternalAliasPrefix starts the alias of every link Worker's Local module
// creates, such as the NAT end of a service-internal veth pair, which lives
// in the host's namespace outside any VRF.
const InternalAliasPrefix = "galactic-local:"

// IsInternalLink reports whether link is one Galactic creates for tenant
// delivery and so can never be a node's uplink: a link carrying a Local alias,
// or one named as a CNI attachment, a VPC VRF or a Local link
// (intf.IsGalacticLinkName). Every uplink discovery path skips it, whatever
// routes it carries; a VRF slave is skipped separately (isVRFSlave).
func IsInternalLink(link netlink.Link) bool {
	attrs := link.Attrs()
	return strings.HasPrefix(attrs.Alias, InternalAliasPrefix) || intf.IsGalacticLinkName(attrs.Name)
}
