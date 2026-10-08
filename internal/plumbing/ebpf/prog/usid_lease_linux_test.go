//go:build linux

// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package prog

import (
	"math/bits"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestUsidServiceEgress_AuthorizationExpiryRevokesEstablishedFlow(t *testing.T) {
	requireRoot(t)
	for _, mode := range []uint8{1, 2} {
		name := "Local"
		if mode == 2 {
			name = "RemoteConsumer"
		}
		t.Run(name, func(t *testing.T) {
			objs := loadObjects(t)
			setServiceIdentity(t, objs, 1)
			setUpEgressRouteAttachment(t, objs, 0xABCDEF, 0x100, 7)
			setUpNodeSIDBase(t, objs, netip.MustParseAddr("fd00:1:2:3::"), 0x100)
			if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{LinkIfindex: 1}); err != nil {
				t.Fatal(err)
			}
			service, consumer := netip.MustParseAddr("fd20:70::100"), netip.MustParseAddr("fd20:70::2")
			value := UsidServiceRouteValue{TargetIfindex: 1, Mode: mode, ConsumerToken: 1, ProducerToken: 1,
				GrantId: [16]byte{1}, TargetSid: netip.MustParseAddr("fd00:9:8:7:e000::").As16(),
				BackendAddr: service.As16(), AuthorizationDeadlineNs: ^uint64(0)}
			key := serviceRouteKey(service)
			if err := objs.ServiceRouteTable.Put(key, value); err != nil {
				t.Fatal(err)
			}
			if err := objs.ServiceAccessTable.Put(UsidServiceAccessKey{IngressIfindex: 1, Family: egressRouteFamilyINET6,
				Protocol: 6, Port: bits.ReverseBytes16(8443), Addr: service.As16()},
				UsidServiceAccessValue{AttachmentToken: 1}); err != nil {
				t.Fatal(err)
			}
			request := buildPlainV6PacketWithL4Ports(t, consumer, service, 49152, 8443)
			reply := buildPlainV6PacketWithL4Ports(t, service, consumer, 8443, 49152)
			if ret, _, err := objs.UsidServiceEgress.Test(request); err != nil || ret != tcActRedirect {
				t.Fatalf("authorized request=%d, err=%v", ret, err)
			}
			if mode == 1 {
				if ret, _, err := objs.UsidServiceEgress.Test(reply); err != nil || ret != tcActRedirect {
					t.Fatalf("authorized reply=%d, err=%v", ret, err)
				}
			}
			value.AuthorizationDeadlineNs = 1
			if err := objs.ServiceRouteTable.Put(key, value); err != nil {
				t.Fatal(err)
			}
			if ret, _, err := objs.UsidServiceEgress.Test(request); err != nil || ret != tcActShot {
				t.Fatalf("expired request=%d, err=%v, want drop", ret, err)
			}
			if mode == 1 {
				if ret, _, err := objs.UsidServiceEgress.Test(reply); err != nil || ret != tcActShot {
					t.Fatalf("expired established reply=%d, err=%v, want drop", ret, err)
				}
			}
			value.AuthorizationDeadlineNs = ^uint64(0)
			if err := objs.ServiceRouteTable.Put(key, value); err != nil {
				t.Fatal(err)
			}
			if ret, _, err := objs.UsidServiceEgress.Test(request); err != nil || ret != tcActRedirect {
				t.Fatalf("renewed request=%d, err=%v", ret, err)
			}
		})
	}
}

func TestUsidServiceEgress_RemoteProducerExpiryRevokesEstablishedReply(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	setServiceIdentity(t, objs, 1)
	setUpEgressRouteAttachment(t, objs, 0xABCDEF, 0x100, 7)
	setUpNodeSIDBase(t, objs, netip.MustParseAddr("fd00:1:2:3::"), 0x100)
	if err := objs.PublicUplinkTable.Put(uint32(0), UsidPublicUplinkValue{LinkIfindex: 1}); err != nil {
		t.Fatal(err)
	}
	service, consumer := netip.MustParseAddr("fd20:70::100"), netip.MustParseAddr("fd20:70::2")
	consumerSID := netip.MustParseAddr("fd00:9:8:7:e000::").As16()
	grantID := [16]byte{1}
	grantKey := UsidServiceRemoteGrantKey{ProducerIfindex: 1, Family: egressRouteFamilyINET6, Protocol: 6,
		Port: bits.ReverseBytes16(8443), GrantId: grantID, Addr: service.As16()}
	grant := UsidServiceRemoteGrantValue{ProducerToken: 1, ConsumerSid: consumerSID,
		FrontendAddr: service.As16(), AuthorizationDeadlineNs: ^uint64(0)}
	if err := objs.ServiceRemoteGrantTable.Put(grantKey, grant); err != nil {
		t.Fatal(err)
	}
	// The remote ingress path normally establishes this row after granting the request.
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		t.Fatal(err)
	}
	reverseKey := UsidServiceReverseKey{IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: 6,
		SourcePort: bits.ReverseBytes16(8443), DestPort: bits.ReverseBytes16(49152), SourceAddr: service.As16(),
		DestAddr: consumer.As16()}
	if err := objs.ServiceReverseTable.Put(reverseKey, UsidServiceReverseValue{Mode: 2, ProducerToken: 1, GrantId: grantID,
		ReturnSid: consumerSID, FrontendAddr: service.As16(), LastSeenNs: uint64(now.Nano())}); err != nil {
		t.Fatal(err)
	}
	reply := buildPlainV6PacketWithL4Ports(t, service, consumer, 8443, 49152)
	if ret, _, err := objs.UsidServiceEgress.Test(reply); err != nil || ret != tcActRedirect {
		t.Fatalf("authorized remote reply=%d err=%v", ret, err)
	}
	grant.AuthorizationDeadlineNs = 1
	if err := objs.ServiceRemoteGrantTable.Put(grantKey, grant); err != nil {
		t.Fatal(err)
	}
	if ret, _, err := objs.UsidServiceEgress.Test(reply); err != nil || ret != tcActShot {
		t.Fatalf("expired established remote reply=%d err=%v, want drop", ret, err)
	}
}

func TestUsidServiceEgress_TranslatedCollisionRequiresExpiredOwner(t *testing.T) {
	requireRoot(t)
	for _, expired := range []bool{false, true} {
		name := "LiveOwner"
		if expired {
			name = "ExpiredOwner"
		}
		t.Run(name, func(t *testing.T) {
			objs := loadObjects(t)
			setServiceIdentity(t, objs, 1)
			if err := objs.AttachmentIdentityTable.Put(uint32(2), uint64(2)); err != nil {
				t.Fatal(err)
			}
			frontend := netip.MustParseAddr("fd20:70::53")
			backend := netip.MustParseAddr("fd20:70::100")
			consumer := netip.MustParseAddr("fd20:70::2")
			newKey := serviceRouteKey(frontend)
			value := UsidServiceRouteValue{TargetIfindex: 1, Mode: 1, ConsumerToken: 1, ProducerToken: 1,
				BackendAddr: backend.As16()}
			if err := objs.ServiceRouteTable.Put(newKey, value); err != nil {
				t.Fatal(err)
			}
			oldKey := newKey
			oldKey.IngressIfindex = 2
			oldValue := value
			oldValue.ConsumerToken = 2
			if expired {
				oldValue.AuthorizationDeadlineNs = 1
			}
			if err := objs.ServiceRouteTable.Put(oldKey, oldValue); err != nil {
				t.Fatal(err)
			}
			if err := objs.ServiceAccessTable.Put(UsidServiceAccessKey{IngressIfindex: 1, Family: egressRouteFamilyINET6,
				Protocol: 6, Port: bits.ReverseBytes16(8443), Addr: frontend.As16()},
				UsidServiceAccessValue{AttachmentToken: 1}); err != nil {
				t.Fatal(err)
			}
			var now unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
				t.Fatal(err)
			}
			reverseKey := UsidServiceReverseKey{IngressIfindex: 1, Family: egressRouteFamilyINET6, Protocol: 6,
				SourcePort: bits.ReverseBytes16(8443), DestPort: bits.ReverseBytes16(49152), SourceAddr: backend.As16(),
				DestAddr: consumer.As16()}
			if err := objs.ServiceReverseTable.Put(reverseKey, UsidServiceReverseValue{ConsumerIfindex: 2, Mode: 1,
				ConsumerToken: 2,
				ProducerToken: 1, FrontendAddr: frontend.As16(), LastSeenNs: uint64(now.Nano())}); err != nil {
				t.Fatal(err)
			}
			pkt := buildPlainV6PacketWithL4Ports(t, consumer, frontend, 49152, 8443)
			want := uint32(tcActShot)
			if expired {
				want = tcActRedirect
			}
			if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != want {
				t.Fatalf("collision verdict=%d err=%v, want %d", ret, err, want)
			}
		})
	}
}

func TestUsidServiceEgress_LeaseExpiresWithoutController(t *testing.T) {
	requireRoot(t)
	objs := loadObjects(t)
	setServiceIdentity(t, objs, 1)
	service, consumer := netip.MustParseAddr("fd20:70::100"), netip.MustParseAddr("fd20:70::2")
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		t.Fatal(err)
	}
	deadline := uint64(now.Nano()) + uint64(time.Second)
	if err := objs.ServiceRouteTable.Put(serviceRouteKey(service), UsidServiceRouteValue{TargetIfindex: 1, Mode: 1,
		ConsumerToken: 1, ProducerToken: 1, BackendAddr: service.As16(), AuthorizationDeadlineNs: deadline}); err != nil {
		t.Fatal(err)
	}
	if err := objs.ServiceAccessTable.Put(UsidServiceAccessKey{IngressIfindex: 1, Family: egressRouteFamilyINET6,
		Protocol: 6, Port: bits.ReverseBytes16(8443), Addr: service.As16()},
		UsidServiceAccessValue{AttachmentToken: 1}); err != nil {
		t.Fatal(err)
	}
	request := buildPlainV6PacketWithL4Ports(t, consumer, service, 49152, 8443)
	reply := buildPlainV6PacketWithL4Ports(t, service, consumer, 8443, 49152)
	if ret, _, err := objs.UsidServiceEgress.Test(request); err != nil || ret != tcActRedirect {
		t.Fatalf("before expiry=%d err=%v", ret, err)
	}
	time.Sleep(1100 * time.Millisecond)
	// No control-plane or map mutation occurs between the live and expired packets.
	for _, pkt := range [][]byte{request, reply} {
		if ret, _, err := objs.UsidServiceEgress.Test(pkt); err != nil || ret != tcActShot {
			t.Fatalf("after expiry=%d err=%v, want drop", ret, err)
		}
	}
}
