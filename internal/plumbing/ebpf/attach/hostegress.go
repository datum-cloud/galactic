// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package attach

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"
)

// DetachEgress removes the managed egress chain, usid_service_egress and
// usid_egress, from ifaceName's tc ingress and tp_deliver from its tc egress,
// under galactic-cni's per-interface lock. Other filters stay. An interface
// that no longer exists is not an error.
func DetachEgress(ifaceName string) error {
	return withInterfaceLockFn(ifaceName, func() error {
		return errors.Join(
			detachOne(ifaceName, serviceEgressFilterName, netlink.HANDLE_MIN_INGRESS),
			detachOne(ifaceName, egressFilterName, netlink.HANDLE_MIN_INGRESS),
			detachOne(ifaceName, tpDeliverFilterName, netlink.HANDLE_MIN_EGRESS),
		)
	})
}

// HasAnyEgress reports whether ifaceName carries any part of the egress
// datapath DetachEgress removes.
func HasAnyEgress(ifaceName string) (bool, error) {
	l, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return false, fmt.Errorf("find link %q: %w", ifaceName, err)
	}
	if ok, err := hasManagedEgressChain(l); err != nil || ok {
		return ok, err
	}
	return HasDeliver(ifaceName)
}
