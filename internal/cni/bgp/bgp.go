// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package bgp

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	gobgpapi "github.com/osrg/gobgp/v4/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.datum.net/galactic/pkg/common/util"
	"go.datum.net/galactic/pkg/common/vrf"
)

const rpcTimeout = 5 * time.Second

// PathConfig bundles the parameters needed to add or delete L3VPN BGP paths.
type PathConfig struct {
	Client           gobgpapi.GoBgpServiceClient // caller owns the connection
	SRv6Locator      string                      // node's SRv6 network CIDR, e.g. "fc00::/56"
	VPCHex           string                      // 12-char hex, 48-bit VPC ID
	VPCAttachmentHex string                      // 4-char hex, 16-bit attachment ID
	Networks         []string                    // CIDRs to advertise
}

// NewClient dials the GoBGP gRPC API at address and returns a client. The
// caller is responsible for closing the underlying connection.
func NewClient(address string) (gobgpapi.GoBgpServiceClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to gobgp at %s: %w", address, err)
	}
	return gobgpapi.NewGoBgpServiceClient(conn), conn, nil
}

// AddPaths injects L3VPN BGP paths into the local GoBGP instance for each network in cfg.
func AddPaths(cfg *PathConfig) error {
	paths, err := buildPaths(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel() //nolint:errcheck
	for _, path := range paths {
		if _, err := cfg.Client.AddPath(ctx, &gobgpapi.AddPathRequest{Path: path}); err != nil {
			return fmt.Errorf("adding path: %w", err)
		}
	}
	return nil
}

// DeletePaths withdraws L3VPN BGP paths from the local GoBGP instance for each network in cfg.
func DeletePaths(cfg *PathConfig) error {
	paths, err := buildPaths(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel() //nolint:errcheck
	for _, path := range paths {
		if _, err := cfg.Client.DeletePath(ctx, &gobgpapi.DeletePathRequest{Path: path}); err != nil {
			return fmt.Errorf("deleting path: %w", err)
		}
	}
	return nil
}

func buildPaths(cfg *PathConfig) ([]*gobgpapi.Path, error) {
	nexthop, err := util.EncodeSRv6Endpoint(cfg.SRv6Locator, cfg.VPCHex, cfg.VPCAttachmentHex)
	if err != nil {
		return nil, fmt.Errorf("encoding SRv6 endpoint: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel() //nolint:errcheck
	bgpResp, err := cfg.Client.GetBgp(ctx, &gobgpapi.GetBgpRequest{})
	if err != nil {
		return nil, fmt.Errorf("getting BGP global config: %w", err)
	}
	localASN := bgpResp.GetGlobal().GetAsn()
	routerID := bgpResp.GetGlobal().GetRouterId()

	// Convert hex identifiers to base62 to look up the VRF interface name.
	vpcBase62, err := util.HexToBase62(cfg.VPCHex)
	if err != nil {
		return nil, fmt.Errorf("converting VPC hex to base62: %w", err)
	}
	vpcAttachBase62, err := util.HexToBase62(cfg.VPCAttachmentHex)
	if err != nil {
		return nil, fmt.Errorf("converting VPCAttachment hex to base62: %w", err)
	}
	vrfID, err := vrf.GetVRFIdForVPC(vpcBase62, vpcAttachBase62)
	if err != nil {
		return nil, fmt.Errorf("getting VRF ID for VPC %s/%s: %w", cfg.VPCHex, cfg.VPCAttachmentHex, err)
	}

	// RD: Type 1 (IP:2-byte) — router-id:vrfID, unique per node per VRF.
	rd := &gobgpapi.RouteDistinguisher{
		Rd: &gobgpapi.RouteDistinguisher_IpAddress{
			IpAddress: &gobgpapi.RouteDistinguisherIPAddress{
				Admin:    routerID,
				Assigned: vrfID,
			},
		},
	}

	// RT: Type 0 (2-byte-AS:4-byte-AN) — localASN:fnv32a(vpcHex).
	// All nodes in the same VPC share this RT so they import each other's paths.
	extComm := &gobgpapi.ExtendedCommunitiesAttribute{
		Communities: []*gobgpapi.ExtendedCommunity{
			{
				Extcom: &gobgpapi.ExtendedCommunity_TwoOctetAsSpecific{
					TwoOctetAsSpecific: &gobgpapi.TwoOctetAsSpecificExtended{
						IsTransitive: true,
						SubType:      0x02, // Route Target sub-type
						Asn:          localASN,
						LocalAdmin:   vpcRouteTarget(cfg.VPCHex),
					},
				},
			},
		},
	}

	attrOrigin := &gobgpapi.Attribute{Attr: &gobgpapi.Attribute_Origin{Origin: &gobgpapi.OriginAttribute{Origin: 0}}} // IGP
	attrLocalPref := &gobgpapi.Attribute{Attr: &gobgpapi.Attribute_LocalPref{LocalPref: &gobgpapi.LocalPrefAttribute{LocalPref: 100}}}
	attrExtComm := &gobgpapi.Attribute{Attr: &gobgpapi.Attribute_ExtendedCommunities{ExtendedCommunities: extComm}}

	paths := make([]*gobgpapi.Path, 0, len(cfg.Networks))
	for _, network := range cfg.Networks {
		path, err := buildPath(network, rd, nexthop, attrOrigin, attrLocalPref, attrExtComm)
		if err != nil {
			return nil, fmt.Errorf("building path for %s: %w", network, err)
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func buildPath(network string, rd *gobgpapi.RouteDistinguisher, nexthop string, attrOrigin, attrLocalPref, attrExtComm *gobgpapi.Attribute) (*gobgpapi.Path, error) {
	ip, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return nil, fmt.Errorf("parsing CIDR: %w", err)
	}
	prefixLen, _ := ipnet.Mask.Size()

	var family *gobgpapi.Family
	if ip.To4() == nil {
		family = &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP6, Safi: gobgpapi.Family_SAFI_MPLS_VPN}
	} else {
		family = &gobgpapi.Family{Afi: gobgpapi.Family_AFI_IP, Safi: gobgpapi.Family_SAFI_MPLS_VPN}
	}

	// LabeledVPNIPAddressPrefix covers both AFI=1 and AFI=2 with SAFI=128.
	// MPLS label is always 0 — the SRv6 SID carries all forwarding state.
	vpnNLRI := &gobgpapi.NLRI{
		Nlri: &gobgpapi.NLRI_LabeledVpnIpPrefix{
			LabeledVpnIpPrefix: &gobgpapi.LabeledVPNIPAddressPrefix{
				Labels:    []uint32{0},
				Rd:        rd,
				PrefixLen: uint32(prefixLen),
				Prefix:    ipnet.IP.String(),
			},
		},
	}

	attrMpReach := &gobgpapi.Attribute{
		Attr: &gobgpapi.Attribute_MpReach{
			MpReach: &gobgpapi.MpReachNLRIAttribute{
				Family:   family,
				NextHops: []string{nexthop},
				Nlris:    []*gobgpapi.NLRI{vpnNLRI},
			},
		},
	}

	return &gobgpapi.Path{
		Family: family,
		Nlri:   vpnNLRI,
		Pattrs: []*gobgpapi.Attribute{attrOrigin, attrLocalPref, attrExtComm, attrMpReach},
	}, nil
}

// vpcRouteTarget returns a stable 32-bit value derived from the VPC hex ID via FNV-32a.
// All nodes advertising the same VPC produce the same RT, enabling VPC-scoped route import.
func vpcRouteTarget(vpcHex string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(vpcHex)) //nolint:errcheck
	return h.Sum32()
}
