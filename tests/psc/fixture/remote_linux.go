// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	cloudapi "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/crdnames"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/plumbing/ebpf/uformat"
	"go.datum.net/galactic/internal/plumbing/ebpf/usidmap"
	"go.datum.net/galactic/internal/plumbing/srv6"
	networkapi "go.datum.net/network/api/v1alpha1"
)

const (
	roleConsumer = "consumer"
	roleProducer = "producer"
)

func (f *fixture) setupRemoteNetwork(ctx context.Context) error {
	if f.cfg.Role != roleConsumer && f.cfg.Role != roleProducer {
		return errors.New("role must be consumer or producer")
	}
	if f.cfg.RouterName == "" || f.cfg.PeerMAC == "" || f.cfg.NodeID == 0 || f.cfg.Locator == "" {
		return errors.New("routerName, nodeID, locator and peerMAC required")
	}
	source, device, err := globalIPv6()
	if err != nil {
		return err
	}
	f.rootSource, f.rootDevice = source, device
	suffix := strconv.Itoa(os.Getpid())
	f.pinDir = filepath.Join("/sys/fs/bpf", "psc-remote-"+f.cfg.NodeName+"-"+suffix)
	f.objects, err = attach.Load(f.pinDir)
	if err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = f.objects.Close(); _ = os.RemoveAll(f.pinDir) })
	if err := f.configureNode(ctx); err != nil {
		return err
	}
	if f.cfg.Role == roleProducer {
		return f.setupProducer(ctx, suffix)
	}
	for index, entry := range f.cfg.Cases {
		if err := f.setupConsumer(ctx, entry, index, suffix); err != nil {
			return err
		}
	}
	return nil
}

func (f *fixture) configureNode(ctx context.Context) error {
	router := &networkapi.BGPRouter{ObjectMeta: metav1.ObjectMeta{Name: f.cfg.RouterName, Namespace: f.cfg.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, f.api, router, func() error {
		router.Spec = networkapi.BGPRouterSpec{TargetRef: networkapi.TargetRef{Kind: "Node", Name: f.cfg.NodeName},
			LocalASN: 65000, RouterID: fmt.Sprintf("192.0.2.%d", f.cfg.NodeID%250+1),
			AddressFamilies: []networkapi.AddressFamily{{AFI: "ipv6", SAFI: "unicast"}},
			SRv6Locator:     f.cfg.Locator, NodeID: f.cfg.NodeID}
		return nil
	}); err != nil {
		return err
	}
	if err := f.api.Get(ctx, client.ObjectKeyFromObject(router), router); err != nil {
		return err
	}
	base, err := srv6.NodeSIDBase(router.Spec.SRv6Locator, router.Spec.NodeID)
	if err != nil {
		return err
	}
	block, err := uformat.Block(base)
	if err != nil {
		return err
	}
	f.block = block
	registry := usidmap.NewRegistryFromObjects(f.objects)
	if err := registry.Locator.Register(block, uint16(router.Spec.NodeID)); err != nil {
		return err
	}
	if err := registry.Function.Register(block, uformat.FunctionEndDT46); err != nil {
		return err
	}
	if err := f.objects.NodeSrcAddrTable.Put(uint32(0), base.As16()); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(f.rootDevice)
	if err != nil {
		return err
	}
	peerMAC, err := net.ParseMAC(f.cfg.PeerMAC)
	if err != nil {
		return err
	}
	uplink := prog.UsidPublicUplinkValue{LinkIfindex: uint32(iface.Index)}
	copy(uplink.Dmac[:], peerMAC)
	copy(uplink.Smac[:], iface.HardwareAddr)
	if err := f.objects.PublicUplinkTable.Put(uint32(0), uplink); err != nil {
		return err
	}
	if err := attach.Attach(f.objects.UsidIngress, []string{f.rootDevice}); err != nil {
		return err
	}
	for _, scope := range []string{"all", f.rootDevice} {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/"+scope+"/forwarding", []byte("1"), 0600); err != nil {
			return err
		}
	}
	return nil
}

func (f *fixture) configureAttachment(ctx context.Context, identity, host string, argument uint16) error {
	routerRef := &networkapi.RouterRef{Name: f.cfg.RouterName}
	object := &networkapi.BGPVRFInstance{ObjectMeta: metav1.ObjectMeta{
		Name: crdnames.BGPVRFInstanceName(identity, f.cfg.NodeName), Namespace: f.cfg.Namespace}}
	if _, err := controllerutil.CreateOrUpdate(ctx, f.api, object, func() error {
		rt := networkapi.RouteTarget{Value: fmt.Sprintf("65000:%d", argument)}
		object.Spec = networkapi.BGPVRFInstanceSpec{RouterTarget: networkapi.RouterTarget{RouterRef: routerRef},
			VRFID: int32(argument), ImportRouteTargets: []networkapi.RouteTarget{rt},
			ExportRouteTargets: []networkapi.RouteTarget{rt}}
		return nil
	}); err != nil {
		return err
	}
	if err := f.api.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
		return err
	}
	actualArgument := uint16(object.Spec.VRFID)
	tableID := uint32(500) + uint32(actualArgument)
	registry := usidmap.NewRegistryFromObjects(f.objects)
	if err := registry.VRF.Register(f.block, actualArgument, tableID, usidmap.EgressKindVeth); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(host)
	if err != nil {
		return err
	}
	if err := f.objects.IfindexVrfTable.Put(uint32(iface.Index), prog.UsidIfindexVrfValue{
		Block: f.block, Argument: actualArgument}); err != nil {
		return err
	}
	if err := f.objects.IfindexEgressKindTable.Put(uint32(iface.Index), uint32(0)); err != nil {
		return err
	}
	return attach.AttachEgressWithIdentity(f.objects.UsidServiceEgress, f.objects.UsidEgress,
		f.objects.AttachmentIdentityTable, uint32(iface.Index), host)
}

func (f *fixture) setupConsumer(ctx context.Context, entry fixtureCase, index int, suffix string) error {
	letter := string(rune('a' + index))
	lab := labState{Project: entry.Project, ConsumerNS: "pscr-c-" + letter + suffix,
		ConsumerHost: "pscrc" + letter + suffix,
		Destination:  entry.Destination}
	gateway := "fd00:ca:" + strconv.Itoa(index+1) + "::1"
	if err := ip(ipNetNS, ipAdd, lab.ConsumerNS); err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = ip(ipNetNS, "del", lab.ConsumerNS) })
	for _, args := range [][]string{
		{ipLink, ipAdd, lab.ConsumerHost, ipType, ipVeth, ipPeer, ipName, "c0"},
		{ipLink, ipSet, "c0", ipNetNS, lab.ConsumerNS}, {ipLink, ipSet, lab.ConsumerHost, "up"},
		{ipAddr, ipAdd, gateway + "/64", ipDevice, lab.ConsumerHost, ipNoDAD},
		{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipLink, ipSet, "lo", "up"},
		{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipAddr, ipAdd, consumerCIDR, ipDevice, "c0", ipNoDAD},
		{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipLink, ipSet, "c0", "up"},
		{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipRoute, ipAdd, gateway + "/128", ipDevice, "c0"},
		{ipNetNS, ipExec, lab.ConsumerNS, "ip", ipRoute, ipAdd, "fd70:ffff::10/128", ipVia, gateway},
		{"-6", ipRoute, ipAdd, ipTable, strconv.Itoa(601 + index), consumerCIDR, ipDevice, lab.ConsumerHost},
	} {
		if err := ip(args...); err != nil {
			return err
		}
	}
	if err := f.assistAttachment(ctx, entry.ConsumerAttachment, lab.ConsumerHost, entry.VPCIdentity); err != nil {
		return err
	}
	if err := f.configureAttachment(ctx, entry.VPCIdentity, lab.ConsumerHost, uint16(101+index)); err != nil {
		return err
	}
	f.labs = append(f.labs, lab)
	return nil
}

func (f *fixture) setupProducer(ctx context.Context, suffix string) error {
	producerName := f.cfg.Cases[0].ProducerAttachment
	if producerName == "" || producerName != f.cfg.Cases[1].ProducerAttachment {
		return errors.New("one shared producer required")
	}
	f.producerNS, f.producerHost = "pscr-p-"+suffix, "pscrp"+suffix
	if err := ip(ipNetNS, ipAdd, f.producerNS); err != nil {
		return err
	}
	f.cleanup = append(f.cleanup, func() { _ = ip(ipNetNS, "del", f.producerNS) })
	for _, args := range [][]string{
		{ipLink, ipAdd, f.producerHost, ipType, ipVeth, ipPeer, ipName, "p0"},
		{ipLink, ipSet, "p0", ipNetNS, f.producerNS}, {ipLink, ipSet, f.producerHost, "up"},
		{ipAddr, ipAdd, "fd00:da:1::1/64", ipDevice, f.producerHost, ipNoDAD},
		{ipNetNS, ipExec, f.producerNS, "ip", ipLink, ipSet, "lo", "up"},
		{ipNetNS, ipExec, f.producerNS, "ip", ipAddr, ipAdd, "fd00:da:1::2/64", ipDevice, "p0", ipNoDAD},
		{ipNetNS, ipExec, f.producerNS, "ip", ipLink, ipSet, "p0", "up"},
		{ipNetNS, ipExec, f.producerNS, "ip", ipRoute, ipAdd, ipDefault, ipVia, producerGateway},
		{"-6", "rule", ipAdd, "priority", relayTable, "from", f.rootSource + "/128", ipTable, relayTable},
	} {
		if err := ip(args...); err != nil {
			return err
		}
	}
	if err := f.assistAttachment(ctx, producerName, f.producerHost, ""); err != nil {
		return err
	}
	producer := &cloudapi.VPCAttachment{}
	if err := f.api.Get(ctx, client.ObjectKey{Namespace: f.cfg.Namespace, Name: producerName}, producer); err != nil {
		return err
	}
	if err := f.configureAttachment(ctx, producer.Status.VPC, f.producerHost, 301); err != nil {
		return err
	}
	for _, entry := range f.cfg.Cases {
		if err := f.addDestination(entry.Destination); err != nil {
			return err
		}
		f.labs = append(f.labs, labState{Project: entry.Project, ProducerNS: f.producerNS, ProducerHost: f.producerHost,
			Destination: entry.Destination})
	}
	return nil
}
