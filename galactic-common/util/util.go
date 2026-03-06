package util

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"

	"github.com/kenshaw/baseconv"
)

const InterfaceNameTemplate = "G%09s%03s%s"

func GenerateInterfaceNameVRF(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "V")
}

func GenerateInterfaceNameHost(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "H")
}

func GenerateInterfaceNameGuest(vpc, vpcAttachment string) string {
	return fmt.Sprintf(InterfaceNameTemplate, vpc, vpcAttachment, "G")
}

func ParseIP(ip string) (net.IP, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("cannot parse IP: %v", ip)
	}
	return parsed, nil
}

func ParseSegments(input []string) ([]net.IP, error) {
	var segments []net.IP
	for _, ipStr := range input {
		ip, err := ParseIP(ipStr)
		if err != nil {
			return nil, fmt.Errorf("could not parse ip (%s): %v", ipStr, err)
		}
		if ip.To4() != nil {
			return nil, fmt.Errorf("not an ipv6 address: %s", ipStr)
		}
		segments = append([]net.IP{ip}, segments...)
	}
	if len(segments) == 0 {
		return nil, fmt.Errorf("no segments parsed: %v", input)
	}
	return segments, nil
}

func IsHost(ipNet *net.IPNet) bool {
	ones, bits := ipNet.Mask.Size()
	// host if mask is full length: /32 for IPv4, /128 for IPv6
	return ones == bits
}

func DecodeSRv6Endpoint(endpoint net.IP) (string, string, error) {
	if endpoint.To4() != nil {
		return "", "", fmt.Errorf("provided endpoint is not an IPv6 address: %s", endpoint)
	}

	endpointNum := new(big.Int).SetBytes(endpoint)
	vpcNum := new(big.Int).And(
		new(big.Int).Rsh(endpointNum, 16), // drop the vpcattachment bits
		big.NewInt(0xFFFFFFFFFFFF),        // mask the vpc bits
	)
	vpcAttachmentNum := new(big.Int).And(
		endpointNum,
		big.NewInt(0xFFFF), // mask the vpcattachment bits
	)

	return fmt.Sprintf("%012x", vpcNum), fmt.Sprintf("%04x", vpcAttachmentNum), nil
}

func EncodeSRv6Endpoint(srv6_net, vpc, vpcAttachment string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(srv6_net)
	if err != nil {
		return "", err
	}
	if ip.To4() != nil {
		return "", fmt.Errorf("provided srv6_net is not IPv6: %s", srv6_net)
	}
	mask_len, _ := ipnet.Mask.Size()
	if mask_len > 64 {
		return "", fmt.Errorf("srv6_net must be at least 64 bits long")
	}

	vpcInt, err := strconv.ParseUint(vpc, 16, 64)
	if err != nil {
		return "", fmt.Errorf("invalid vpc %q: %w", vpc, err)
	}
	vpcAttachmentInt, err := strconv.ParseUint(vpcAttachment, 16, 16)
	if err != nil {
		return "", fmt.Errorf("invalid vpcAttachment %q: %w", vpcAttachment, err)
	}

	binary.BigEndian.PutUint64(ip[8:16], (vpcInt<<16)|vpcAttachmentInt)
	return ip.String(), nil
}

func HexToBase62(value string) (string, error) {
	return baseconv.Convert(strings.ToLower(value), baseconv.DigitsHex, baseconv.Digits62)
}

func Base62ToHex(value string) (string, error) {
	return baseconv.Convert(value, baseconv.Digits62, baseconv.DigitsHex)
}
