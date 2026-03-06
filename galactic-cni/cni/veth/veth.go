package veth

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"github.com/datum-cloud/galactic-common/sysctl"
	"github.com/datum-cloud/galactic-common/util"
	"github.com/vishvananda/netlink"
)

func updateForwardRule(interfaceName string, action string) error {
	ruleSpec := []string{"-o", interfaceName, "-j", "ACCEPT"}

	protocols := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6}
	for _, proto := range protocols {
		ipt, err := iptables.NewWithProtocol(proto)
		if err != nil {
			return err
		}

		switch action {
		case "add":
			if err := ipt.Insert("filter", "FORWARD", 1, ruleSpec...); err != nil {
				return err
			}
		case "delete":
			if err := ipt.Delete("filter", "FORWARD", ruleSpec...); err != nil {
				return err
			}
		default:
			return fmt.Errorf("invalid action: '%s' (must be 'add' or 'delete')", action)
		}
	}

	return nil
}

func Add(vpc, vpcAttachment string, mtu int) error {
	vrfName := util.GenerateInterfaceNameVRF(vpc, vpcAttachment)
	hostName := util.GenerateInterfaceNameHost(vpc, vpcAttachment)
	guestName := util.GenerateInterfaceNameGuest(vpc, vpcAttachment)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostName,
			MTU:  mtu,
		},
		PeerName: guestName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return err
	}

	if err := updateForwardRule(hostName, "add"); err != nil {
		return err
	}

	if err := sysctl.ConfigureInterfaceSysctls(hostName); err != nil {
		return err
	}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return err
	}
	guestLink, err := netlink.LinkByName(guestName)
	if err != nil {
		return err
	}
	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetUp(hostLink); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(guestLink); err != nil {
		return err
	}

	return netlink.LinkSetMaster(hostLink, vrfLink)
}

func Delete(vpc, vpcAttachment string, mtu int) error {
	hostName := util.GenerateInterfaceNameHost(vpc, vpcAttachment)

	if err := updateForwardRule(hostName, "delete"); err != nil {
		return err
	}

	hostLink, err := netlink.LinkByName(hostName)
	if err != nil {
		return err
	}

	return netlink.LinkDel(hostLink)
}
