// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A remote service request as the producer's node receives it: the service
// tunnel to this node's SID, carrying the consumer's packet to the endpoint's
// address. That address is virtual, so the producer VPC's table has no route
// for it, as in production.
const (
	remoteServiceToken           = uint64(7)
	remoteServicePort     uint16 = 53
	remoteServiceClient   uint16 = 40000
	remoteServiceProducer        = "fd00:5::10"
)

var (
	remoteServiceAddr     = netip.MustParseAddr("fd70:100::53")
	remoteServiceFrontend = netip.MustParseAddr("fd53::53")
	remoteServiceConsumer = netip.MustParseAddr("fd20:0:17::1:0:2")
	remoteServiceReturn   = netip.MustParseAddr("fd00:123:456:20::")
	remoteServiceGrant    = [16]byte{0x47, 15: 0x01}
)

// setUpRemoteProducer makes the lab's veth the producer and installs what the
// producer's node programs for one remote consumer: the producer's identity
// and next hop, and the consumer's grant. withTarget adds the remote target
// row naming the producer.
func (lab *redirectLab) setUpRemoteProducer(t *testing.T, withTarget bool) {
	t.Helper()
	lab.registerVeth(t)
	setNetns(t, lab.peerNS)
	addLinkAddr(t, "dv1", remoteServiceProducer+"/64")
	setNetns(t, lab.labNS)
	addLinkAddr(t, "dv0", "fd00:5::1/64")
	awaitLinkLocal(t, lab.vethIfindex)

	objs := lab.objs
	if err := objs.ServicePolicyStateTable.Put(uint32(0), UsidServicePolicyStateValue{Enabled: 1}); err != nil {
		t.Fatalf("enable service policy: %v", err)
	}
	if err := objs.AttachmentIdentityTable.Put(lab.vethIfindex, remoteServiceToken); err != nil {
		t.Fatalf("populate producer identity: %v", err)
	}
	peer := UsidServicePeerValue{Token: remoteServiceToken, Address: netip.MustParseAddr(remoteServiceProducer).As16()}
	if err := objs.ServicePeerTable.Put(UsidServicePeerKey{Ifindex: lab.vethIfindex, Family: egressRouteFamilyINET6},
		peer); err != nil {
		t.Fatalf("populate producer next hop: %v", err)
	}
	grant := UsidServiceRemoteGrantKey{
		ProducerIfindex: lab.vethIfindex, Family: egressRouteFamilyINET6, Protocol: ipProtoUDP,
		Port: bits.ReverseBytes16(remoteServicePort), GrantId: remoteServiceGrant, Addr: remoteServiceAddr.As16(),
	}
	if err := objs.ServiceRemoteGrantTable.Put(grant, UsidServiceRemoteGrantValue{
		ConsumerSid: remoteServiceReturn.As16(), FrontendAddr: remoteServiceFrontend.As16(),
		ProducerToken: remoteServiceToken,
	}); err != nil {
		t.Fatalf("populate remote grant: %v", err)
	}
	// What CNI ADD writes for the producer: its VPC's (block, argument).
	if err := objs.IfindexVrfTable.Put(lab.vethIfindex, UsidIfindexVrfValue{
		Block: baseUSID.block, Argument: baseUSID.argument,
	}); err != nil {
		t.Fatalf("populate producer VRF: %v", err)
	}
	if withTarget {
		target := grant
		target.ProducerIfindex = 0
		if err := objs.ServiceRemoteTargetTable.Put(target,
			UsidServiceRemoteTargetValue{ProducerIfindex: lab.vethIfindex}); err != nil {
			t.Fatalf("populate remote target: %v", err)
		}
	}
}

// sendServiceRequest writes one tunneled UDP request into the uplink and
// returns the marker its payload carries.
func (lab *redirectLab) sendServiceRequest(t *testing.T, label string) []byte {
	t.Helper()
	marker := fmt.Appendf(nil, "galactic-remote-service:%s:%d", label, time.Now().UnixNano())
	payload := make([]byte, 64)
	copy(payload, marker)

	udp := make([]byte, 8, 8+len(payload))
	udpLen := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(udp[0:2], remoteServiceClient)
	binary.BigEndian.PutUint16(udp[2:4], remoteServicePort)
	binary.BigEndian.PutUint16(udp[4:6], udpLen)
	udp = append(udp, payload...)

	inner := make([]byte, 0, ip6HeaderLen+len(udp))
	inner = append(inner, 0x60, 0x00, 0x00, 0x00, byte(udpLen>>8), byte(udpLen), ipProtoUDP, 64)
	inner = append(inner, remoteServiceConsumer.AsSlice()...)
	inner = append(inner, remoteServiceAddr.AsSlice()...)
	inner = append(inner, udp...)

	// version, inner next header, direction (request), reserved
	tunnel := make([]byte, 0, 4+len(remoteServiceGrant)+16)
	tunnel = append(tunnel, 1, 41, 1, 0)
	tunnel = append(tunnel, remoteServiceGrant[:]...)
	tunnel = append(tunnel, remoteServiceFrontend.AsSlice()...)

	outerLen := len(tunnel) + len(inner)
	frame := make([]byte, 0, ethHeaderLen+ip6HeaderLen+outerLen)
	frame = append(frame, lab.uplinkMAC...)
	frame = append(frame, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x86, 0xDD)
	frame = append(frame, 0x60, 0x00, 0x00, 0x00, byte(outerLen>>8), byte(outerLen), 253, 64)
	frame = append(frame, remoteServiceReturn.AsSlice()...)
	dst := baseUSID.addr(t).As16()
	frame = append(frame, dst[:]...)
	frame = append(frame, tunnel...)
	frame = append(frame, inner...)

	if _, err := unix.Write(lab.uplinkFd, frame); err != nil {
		t.Fatalf("write frame into uplink tap: %v", err)
	}
	return marker
}

// A request a consumer on another node sends to a producer here reaches the
// producer through its next hop, though the producer's VPC has no route for
// the endpoint's address, and leaves the reverse row its reply needs.
func TestUsidIngress_RemoteServiceRequestReachesProducerWithoutRoute(t *testing.T) {
	lab := newRedirectLab(t)
	lab.setUpRemoteProducer(t, true)

	marker := lab.sendServiceRequest(t, "with-target")
	if !awaitMarker(t, lab.vethPeerCapture, marker, deliveryWait, readCapture(false)) {
		t.Fatalf("remote service request never reached the producer; drops: fib_unreachable=%d service_route_denied=%d",
			sumPerCPU(t, lab.objs.DropReasons, DropReasonFibUnreachable),
			sumPerCPU(t, lab.objs.DropReasons, DropReasonServiceRouteDenied))
	}
	reverse := UsidServiceReverseKey{
		IngressIfindex: lab.vethIfindex, Family: egressRouteFamilyINET6, Protocol: ipProtoUDP,
		SourcePort: bits.ReverseBytes16(remoteServicePort), DestPort: bits.ReverseBytes16(remoteServiceClient),
		SourceAddr: remoteServiceAddr.As16(), DestAddr: remoteServiceConsumer.As16(),
	}
	var value UsidServiceReverseValue
	if err := lab.objs.ServiceReverseTable.Lookup(reverse, &value); err != nil {
		t.Fatalf("look up the request's reverse row: %v", err)
	}
	if value.Mode != 2 || value.ReturnSid != remoteServiceReturn.As16() || value.GrantId != remoteServiceGrant {
		t.Errorf("reverse row = %+v, want a remote row returning to %s", value, remoteServiceReturn)
	}
}

// The target row only chooses the interface: a request whose grant is gone
// is still refused there.
func TestUsidIngress_RemoteServiceRequestStillNeedsItsGrant(t *testing.T) {
	lab := newRedirectLab(t)
	lab.setUpRemoteProducer(t, true)
	if err := lab.objs.ServiceRemoteGrantTable.Delete(UsidServiceRemoteGrantKey{
		ProducerIfindex: lab.vethIfindex, Family: egressRouteFamilyINET6, Protocol: ipProtoUDP,
		Port: bits.ReverseBytes16(remoteServicePort), GrantId: remoteServiceGrant, Addr: remoteServiceAddr.As16(),
	}); err != nil {
		t.Fatalf("delete remote grant: %v", err)
	}

	marker := lab.sendServiceRequest(t, "revoked")
	if awaitMarker(t, lab.vethPeerCapture, marker, quietWait, readCapture(false)) {
		t.Fatal("request without a grant reached the producer")
	}
	if got := sumPerCPU(t, lab.objs.DropReasons, DropReasonServiceRouteDenied); got == 0 {
		t.Error("drop_reasons[service_route_denied] = 0, want the request refused")
	}
}

// Without a target row, as written by a router older than the table, the
// request is delivered by a route lookup as before: with no route for the
// endpoint's address it does not arrive, and with one it does.
func TestUsidIngress_RemoteServiceRequestWithoutTargetUsesRoute(t *testing.T) {
	lab := newRedirectLab(t)
	lab.setUpRemoteProducer(t, false)

	marker := lab.sendServiceRequest(t, "no-route")
	if awaitMarker(t, lab.vethPeerCapture, marker, quietWait, readCapture(false)) {
		t.Fatal("request reached the producer with neither a target nor a route")
	}

	routeUnresolved(t, lab.vethIfindex, net.IP(remoteServiceAddr.AsSlice()))
	// The kernel resolves the routed address itself, which the producer
	// answers for only once it holds it, as a service binding it would.
	setNetns(t, lab.peerNS)
	addLinkAddr(t, "dv1", remoteServiceAddr.String()+"/128")
	setNetns(t, lab.labNS)
	marker = lab.sendServiceRequest(t, "routed")
	if !awaitMarker(t, lab.vethPeerCapture, marker, deliveryWait, readCapture(false)) {
		t.Fatal("routed request without a target never reached the producer")
	}
}

// A target in another VRF than the tunnel's SID names is not used: the
// request falls back to the route lookup of the SID's VRF, which has no
// route for the address.
func TestUsidIngress_RemoteServiceTargetOutsideTheVRFIsIgnored(t *testing.T) {
	lab := newRedirectLab(t)
	lab.setUpRemoteProducer(t, true)
	if err := lab.objs.IfindexVrfTable.Put(lab.vethIfindex, UsidIfindexVrfValue{
		Block: baseUSID.block, Argument: baseUSID.argument + 1,
	}); err != nil {
		t.Fatalf("move producer to another VRF: %v", err)
	}
	marker := lab.sendServiceRequest(t, "other-vrf")
	if awaitMarker(t, lab.vethPeerCapture, marker, quietWait, readCapture(false)) {
		t.Fatal("request reached a producer outside the tunnel's VRF")
	}
}
