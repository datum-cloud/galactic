package srv6

import (
	"errors"
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/datum-cloud/galactic-agent/srv6/neighborproxy"
	"github.com/datum-cloud/galactic-agent/srv6/routeegress"
	"github.com/datum-cloud/galactic-agent/srv6/routeingress"
	"github.com/datum-cloud/galactic-common/util"
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

func RouteEgressAdd(prefixStr, srcStr string, segmentsStr []string) error {
	prefix, err := netlink.ParseIPNet(prefixStr)
	if err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}
	src, err := util.ParseIP(srcStr)
	if err != nil {
		return fmt.Errorf("invalid src: %w", err)
	}
	segments, err := util.ParseSegments(segmentsStr)
	if err != nil {
		return fmt.Errorf("invalid segments: %w", err)
	}

	vpc, vpcAttachment, err := util.DecodeSRv6Endpoint(src)
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

	var errs []error
	if util.IsHost(prefix) {
		if err := neighborproxy.Add(prefix, vpc, vpcAttachment); err != nil {
			errs = append(errs, fmt.Errorf("neighborproxy add failed: %w", err))
		}
	}
	if err := routeegress.Add(vpc, vpcAttachment, prefix, segments); err != nil {
		errs = append(errs, fmt.Errorf("routeegress add failed: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func RouteEgressDel(prefixStr, srcStr string, segmentsStr []string) error {
	prefix, err := netlink.ParseIPNet(prefixStr)
	if err != nil {
		return fmt.Errorf("invalid prefix: %w", err)
	}
	src, err := util.ParseIP(srcStr)
	if err != nil {
		return fmt.Errorf("invalid src: %w", err)
	}
	segments, err := util.ParseSegments(segmentsStr)
	if err != nil {
		return fmt.Errorf("invalid segments: %w", err)
	}

	vpc, vpcAttachment, err := util.DecodeSRv6Endpoint(src)
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

	var errs []error
	if util.IsHost(prefix) {
		if err := neighborproxy.Delete(prefix, vpc, vpcAttachment); err != nil {
			errs = append(errs, fmt.Errorf("neighborproxy delete failed: %w", err))
		}
	}
	if err := routeegress.Delete(vpc, vpcAttachment, prefix, segments); err != nil {
		errs = append(errs, fmt.Errorf("routeegress delete failed: %w", err))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
