// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package ingresssidecar

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/intf"
	bgpv1alpha1 "go.datum.net/network/api/v1alpha1"
)

// ingressVPCAttachment is the synthetic "vpcAttachment" segment
// crdnames.BGPAdvertisementName needs a third argument for. This sidecar
// has no real VPCAttachment of its own (that identity belongs to a CNI
// attachment — see internal/cnibgp) — it uses this fixed, valid-base62
// literal so its own advertisement's name still follows the established
// (vpc, vpcAttachment, node) convention and can never collide with a real
// CNI-derived attachment's own advertisement for the same (vpc, node),
// which always shares this sidecar's own BGPVRFInstance (see
// PublishGateway) but never its BGPAdvertisement.
//
// Aliased to crdnames' own constant rather than repeating the literal: the
// host side has to recognize the advertisements this writes (see
// internal/installer's sidecar return path), so both ends must read the
// same value or the recognition quietly stops matching.
const ingressVPCAttachment = crdnames.IngressAttachment

// ErrGatewayAddressNotProvisioned is returned by a GatewayAddressResolver
// when this VPC has no local gateway address to advertise yet. Callers
// (Store) treat this as "nothing to do yet", not a reconcile error — see
// Store's own gateway-publish call site.
var ErrGatewayAddressNotProvisioned = errors.New("ingresssidecar: no gateway address provisioned for this VPC yet")

// GatewayAddressResolver discovers this sidecar's own local address inside
// a managed VPC's subnet — the source address Envoy's outbound connections
// into that VPC use (see internal/plumbing/srv6.ResolveNodeSourceAddress's
// doc comment for why the kernel, not this codebase, picks that address).
// GatewayPublisher advertises whatever this returns so that a VPC backend's
// reply traffic has an SRv6 route back to it.
//
// This interface deliberately does not create that address: provisioning
// it (a veth-style attachment into the VPC, with its own IPAM allocation)
// is a real, unimplemented gap — see docs/plans/855-return-path-gateway-
// advertisement.md's "Not implemented here" section. NetlinkGatewayAddressResolver
// only discovers an address some other mechanism already provisioned.
type GatewayAddressResolver interface {
	// ResolveGatewayAddress returns this node's own local address for vpc,
	// or ErrGatewayAddressNotProvisioned (wrapped) if none exists yet.
	ResolveGatewayAddress(vpc string) (net.IP, error)
}

// NetlinkGatewayAddressResolver is the production GatewayAddressResolver:
// it looks for a global-scope IPv6 address on some interface enslaved to
// vpc's own Linux VRF device (the same device internal/plumbing/vrf.Add
// creates) — the shape a veth-style ingress attachment would take if one
// exists. Requires CAP_NET_ADMIN, like internal/plumbing/vrf itself.
type NetlinkGatewayAddressResolver struct{}

// ResolveGatewayAddress implements GatewayAddressResolver.
func (NetlinkGatewayAddressResolver) ResolveGatewayAddress(vpc string) (net.IP, error) {
	vrfName := intf.GenerateInterfaceNameVRF(vpc)
	vrfLink, err := netlink.LinkByName(vrfName)
	if err != nil {
		return nil, fmt.Errorf("%w: VRF interface %q: %w", ErrGatewayAddressNotProvisioned, vrfName, err)
	}
	vrfIndex := vrfLink.Attrs().Index

	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Index == vrfIndex || attrs.MasterIndex != vrfIndex {
			continue // not a slave of this VPC's VRF
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return nil, fmt.Errorf("list addresses on %s: %w", attrs.Name, err)
		}
		for _, a := range addrs {
			if a.Scope == unix.RT_SCOPE_UNIVERSE && !a.IP.IsUnspecified() {
				return a.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: no globally-scoped address found on any interface enslaved to %q",
		ErrGatewayAddressNotProvisioned, vrfName)
}

// GatewayPublisher advertises (and withdraws) this sidecar's own local
// gateway address for a VPC via a BGPAdvertisement CRD, so that a backend
// pod's reply traffic — addressed back to that gateway address — has an
// SRv6 route to follow. Mirrors internal/cnibgp/bgp.go's own
// BGPVRFInstance/BGPAdvertisement publish pattern (lookupBGPRouter,
// allocateArgument, routeTarget, buildVRFInstanceSpec/buildAdvertisementSpec)
// for a pod's own address; deliberately reimplemented here in miniature
// rather than imported, since cnibgp's version is entangled with CNI-only
// concerns (prevResult, IPAM, container-ID-keyed annotations, rollback
// tracking) this sidecar has none of. Consolidating the two into one shared
// package is a reasonable follow-up, not done here to avoid touching
// cnibgp's existing, heavily-relied-upon publish path in the same change
// that introduces this new caller.
type GatewayPublisher interface {
	// PublishGateway ensures a BGPAdvertisement exists for addr, the local
	// gateway address for vpc, originated from this node's own BGPRouter.
	// Idempotent: safe to call every time Store creates vpc's VRF.
	PublishGateway(ctx context.Context, vpc string, addr net.IP) error
	// WithdrawGateway removes the BGPAdvertisement PublishGateway created
	// for vpc, if any. Never removes the (possibly shared) BGPVRFInstance
	// PublishGateway reused or created — see its own doc comment for why
	// that's galactic-router's GC controller's job, not this one's.
	WithdrawGateway(ctx context.Context, vpc string) error
}

// k8sGatewayPublisher is the production GatewayPublisher.
type k8sGatewayPublisher struct {
	client    client.Client
	nodeName  string
	namespace string
}

// NewK8sGatewayPublisher returns a GatewayPublisher that reads/writes BGP
// CRDs in namespace via c, attributing every advertisement it creates to
// the BGPRouter targeting nodeName.
func NewK8sGatewayPublisher(c client.Client, nodeName, namespace string) GatewayPublisher {
	return &k8sGatewayPublisher{client: c, nodeName: nodeName, namespace: namespace}
}

// gatewayBGPConfig is the subset of a matched BGPRouter's spec PublishGateway
// needs — mirrors internal/cnibgp/bgp.go's own unexported bgpConfig, minus
// the SRv6Locator/NodeID fields that caller doesn't need: unlike a pod's own
// advertisement, this one never computes a SID directly (see
// internal/reconcile.resolveSRv6SID, which derives it from the
// BGPAdvertisement's own VRFID/Function plus the BGPRouter it targets, at
// reconcile time, not here).
type gatewayBGPConfig struct {
	asNumber   int64
	routerName string
}

func (p *k8sGatewayPublisher) lookupBGPRouter(ctx context.Context) (gatewayBGPConfig, error) {
	routerList := &bgpv1alpha1.BGPRouterList{}
	if err := p.client.List(ctx, routerList, client.InNamespace(p.namespace)); err != nil {
		return gatewayBGPConfig{}, fmt.Errorf("list BGPRouters in namespace %s: %w", p.namespace, err)
	}
	var matches []bgpv1alpha1.BGPRouter
	for _, r := range routerList.Items {
		if r.Spec.TargetRef.Name == p.nodeName {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return gatewayBGPConfig{}, fmt.Errorf("no BGPRouter found for node %s in namespace %s", p.nodeName, p.namespace)
	case 1:
		return gatewayBGPConfig{asNumber: matches[0].Spec.LocalASN, routerName: matches[0].Name}, nil
	default:
		return gatewayBGPConfig{}, fmt.Errorf("ambiguous BGP config: %d BGPRouters target node %s in namespace %s",
			len(matches), p.nodeName, p.namespace)
	}
}

// vpcRouteTarget mirrors internal/cnibgp/bgp.go's own routeTarget: the RT in
// "ASN:NN" format using the low 32 bits of the VPC identifier, so this
// advertisement's community matches every other advertisement for the same
// VPC (whichever node/attachment originated them) bit for bit — that
// equality, not any shared code path, is what makes a receiving node's own
// ImportRouteTargets pick this advertisement up.
func vpcRouteTarget(asNumber int64, vpc string) (string, error) {
	vpcHex, err := intf.Base62ToHex(vpc)
	if err != nil {
		return "", fmt.Errorf("convert vpc %q to hex: %w", vpc, err)
	}
	v, err := strconv.ParseUint(vpcHex, 16, 64)
	if err != nil {
		return "", fmt.Errorf("parse VPC hex %q: %w", vpcHex, err)
	}
	return fmt.Sprintf("%d:%d", asNumber, uint32(v)), nil
}

// allocateGatewayArgument mirrors internal/cnibgp/bgp.go's own
// allocateArgument: the value already registered under vrfName if a
// BGPVRFInstance by that name exists, otherwise the lowest value in
// [uformat.ArgumentMin, uformat.ArgumentMax] not already used by routerName's
// other BGPVRFInstances.
func allocateGatewayArgument(
	ctx context.Context, k8s client.Client, namespace, routerName, vrfName string,
) (int32, error) {
	list := &bgpv1alpha1.BGPVRFInstanceList{}
	if err := k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return 0, fmt.Errorf("list BGPVRFInstances in namespace %s: %w", namespace, err)
	}
	used := make(map[int32]struct{}, len(list.Items))
	for _, inst := range list.Items {
		if inst.Spec.RouterRef == nil || inst.Spec.RouterRef.Name != routerName {
			continue
		}
		if inst.Name == vrfName {
			return inst.Spec.VRFID, nil
		}
		used[inst.Spec.VRFID] = struct{}{}
	}
	for arg := int32(uformat.ArgumentMin); arg <= int32(uformat.ArgumentMax); arg++ {
		if _, ok := used[arg]; !ok {
			return arg, nil
		}
	}
	return 0, fmt.Errorf("allocate SID argument: router %s has no free Argument in [%#x,%#x]",
		routerName, uint16(uformat.ArgumentMin), uint16(uformat.ArgumentMax))
}

// PublishGateway implements GatewayPublisher.
func (p *k8sGatewayPublisher) PublishGateway(ctx context.Context, vpc string, addr net.IP) error {
	if addr == nil || addr.IsUnspecified() {
		return fmt.Errorf("refusing to publish gateway advertisement for vpc %s: address %s is not usable", vpc, addr)
	}

	bgp, err := p.lookupBGPRouter(ctx)
	if err != nil {
		return err
	}

	// Same (vpc, node)-keyed BGPVRFInstance a real CNI attachment on this
	// node would use (crdnames.BGPVRFInstanceName's own doc comment) —
	// CreateOrUpdate here reuses one that already exists (a tenant pod
	// sharing this node and VPC) rather than creating a competing entry, or
	// creates one for the shared VRFID/route-target bookkeeping if none
	// does yet.
	vrfName := crdnames.BGPVRFInstanceName(vpc, p.nodeName)
	vrfID, err := allocateGatewayArgument(ctx, p.client, p.namespace, bgp.routerName, vrfName)
	if err != nil {
		return err
	}
	rtValue, err := vpcRouteTarget(bgp.asNumber, vpc)
	if err != nil {
		return fmt.Errorf("compute route target for vpc %s: %w", vpc, err)
	}

	vrfInst := &bgpv1alpha1.BGPVRFInstance{
		ObjectMeta: metav1.ObjectMeta{Name: vrfName, Namespace: p.namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, p.client, vrfInst, func() error {
		vrfInst.Spec = bgpv1alpha1.BGPVRFInstanceSpec{
			RouterTarget:       bgpv1alpha1.RouterTarget{RouterRef: &bgpv1alpha1.RouterRef{Name: bgp.routerName}},
			VRFID:              vrfID,
			ImportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
			ExportRouteTargets: []bgpv1alpha1.RouteTarget{{Value: rtValue}},
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apply BGPVRFInstance %s: %w", vrfName, err)
	}

	function := bgpv1alpha1.SRv6FunctionEndDT46
	advName := crdnames.BGPAdvertisementName(vpc, ingressVPCAttachment, p.nodeName)
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: advName, Namespace: p.namespace},
	}
	if _, err := controllerutil.CreateOrUpdate(ctx, p.client, adv, func() error {
		adv.Spec = bgpv1alpha1.BGPAdvertisementSpec{
			RouterRef:     bgpv1alpha1.RouterRef{Name: bgp.routerName},
			AddressFamily: bgpv1alpha1.AddressFamily{AFI: bgpv1alpha1.AFIL2VPN, SAFI: bgpv1alpha1.SAFIEVPN},
			Prefixes:      []bgpv1alpha1.Prefix{bgpv1alpha1.Prefix(addr.String() + "/128")},
			Communities:   []bgpv1alpha1.Community{bgpv1alpha1.Community(rtValue)},
			VRFID:         &vrfID,
			Function:      &function,
		}
		return nil
	}); err != nil {
		return fmt.Errorf("apply BGPAdvertisement %s: %w", advName, err)
	}
	return nil
}

// WithdrawGateway implements GatewayPublisher.
func (p *k8sGatewayPublisher) WithdrawGateway(ctx context.Context, vpc string) error {
	advName := crdnames.BGPAdvertisementName(vpc, ingressVPCAttachment, p.nodeName)
	adv := &bgpv1alpha1.BGPAdvertisement{
		ObjectMeta: metav1.ObjectMeta{Name: advName, Namespace: p.namespace},
	}
	if err := p.client.Delete(ctx, adv); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete BGPAdvertisement %s: %w", advName, err)
	}
	return nil
}
