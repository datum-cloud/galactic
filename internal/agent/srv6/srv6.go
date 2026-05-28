// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package srv6

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"go.datum.net/galactic/internal/agent/srv6/routeingress"
	"go.datum.net/galactic/pkg/common/util"
)

func RouteIngressAdd(ipStr string) error {
	ip, err := util.ParseIP(ipStr)
	if err != nil {
		return fmt.Errorf("invalid ip: %w", err)
	}
	vpc, vpcAttachment, err := util.DecodeSRv6Endpoint(ip)
	if err != nil {
		return fmt.Errorf("could not extract SRv6 endpoint: %w", err)
	}
	vpc, err = util.HexToBase62(vpc)
	if err != nil {
		return fmt.Errorf("invalid vpc: %w", err)
	}
	vpcAttachment, err = util.HexToBase62(vpcAttachment)
	if err != nil {
		return fmt.Errorf("invalid vpcattachment: %w", err)
	}

	if err := routeingress.Add(netlink.NewIPNet(ip), vpc, vpcAttachment); err != nil {
		return fmt.Errorf("routeingress add failed: %w", err)
	}
	return nil
}

func RouteIngressDel(ipStr string) error {
	ip, err := util.ParseIP(ipStr)
	if err != nil {
		return fmt.Errorf("invalid ip: %w", err)
	}
	vpc, vpcAttachment, err := util.DecodeSRv6Endpoint(ip)
	if err != nil {
		return fmt.Errorf("could not extract SRv6 endpoint: %w", err)
	}
	vpc, err = util.HexToBase62(vpc)
	if err != nil {
		return fmt.Errorf("invalid vpc: %w", err)
	}
	vpcAttachment, err = util.HexToBase62(vpcAttachment)
	if err != nil {
		return fmt.Errorf("invalid vpcattachment: %w", err)
	}

	if err := routeingress.Delete(netlink.NewIPNet(ip), vpc, vpcAttachment); err != nil {
		return fmt.Errorf("routeingress delete failed: %w", err)
	}
	return nil
}
