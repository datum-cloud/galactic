// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectipinterop

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

type transport struct {
	name    string // report name
	alpn    string // Xray's alpn setting and the server's negotiated ALPN
	counter string // nftables counter for its outer packets
	dial    func(h *harness, t *testing.T) rawConn
}

var transports = []transport{
	{name: "HTTP/3", alpn: "h3", counter: counterUDP443, dial: (*harness).dialH3},
	{name: "HTTP/2", alpn: "h2", counter: counterTCP443, dial: (*harness).dialH2},
}

// clientXray and clientRaw name the client of each recorded check.
const (
	clientXray = "xray"
	clientRaw  = "raw"
)

const (
	udpRoundTrips = 20
	tcpEchoBytes  = 256 << 10
)

// TestXrayRoundTrip proves each transport with the independent client: UDP
// datagrams that are exactly innerPacketSize-byte IPv6 packets in both
// directions, and a TCP stream, across Xray's CONNECT-IP tunnel to the VPC.
func TestXrayRoundTrip(t *testing.T) {
	h := requireFixture(t)
	for _, tr := range transports {
		t.Run(tr.alpn, func(t *testing.T) {
			c := newConnector("roundtrip-" + tr.alpn)
			detail := map[string]any{
				"negotiated_alpn": tr.alpn, "udp_round_trips": udpRoundTrips, "tcp_echo_bytes": tcpEchoBytes,
			}
			h.record(t, result{Check: "round trip", Transport: tr.name, Client: clientXray, Detail: detail})
			before := h.counters(t)
			alpnBefore, h2Before := h.alpnCount(tr.alpn), h.h2ProtoCount("HTTP/2.0")
			x := h.startXray(t, "roundtrip-"+tr.alpn, c, tr.alpn, h.caFile)
			udpErr := x.udpRoundTrips(udpRoundTrips, 10*time.Second)
			// The UDP phase alone carries the packet-size evidence: the TCP
			// stream that follows also produces 1280-byte segments.
			toVPC, toClient, _, _ := h.backend.sizes(c.prefix).snapshot()
			tcpErr := x.tcpRoundTrip(tcpEchoBytes)
			after := h.counters(t)
			allToVPC, allToClient, opened, _ := h.backend.sizes(c.prefix).snapshot()
			detail["udp_error"] = errString(udpErr)
			detail["tcp_error"] = errString(tcpErr)
			detail["tls_handshakes_with_alpn"] = h.alpnCount(tr.alpn) - alpnBefore
			detail["udp_phase_inner_1280_to_vpc"] = toVPC[innerPacketSize]
			detail["udp_phase_inner_1280_to_client"] = toClient[innerPacketSize]
			detail["udp_phase_largest_inner_to_vpc"] = largest(toVPC)
			detail["udp_phase_largest_inner_to_client"] = largest(toClient)
			detail["backend_sessions"] = opened
			detail["outer_udp443_packets"] = after[counterUDP443] - before[counterUDP443]
			detail["outer_tcp443_packets"] = after[counterTCP443] - before[counterTCP443]
			detail["http2_requests_as_HTTP2.0"] = h.h2ProtoCount("HTTP/2.0") - h2Before
			t.Logf("%s: %v", tr.name, detail)

			if udpErr != nil {
				t.Errorf("UDP: %v", udpErr)
			}
			if tcpErr != nil {
				t.Errorf("TCP: %v", tcpErr)
			}
			if h.alpnCount(tr.alpn) == alpnBefore {
				t.Errorf("no TLS handshake negotiated ALPN %q", tr.alpn)
			}
			// Only the 20 datagrams cross during the UDP phase, so 20 packets of
			// exactly innerPacketSize each way means one unfragmented packet each.
			if toVPC[innerPacketSize] < udpRoundTrips || toClient[innerPacketSize] < udpRoundTrips ||
				largest(toVPC) > innerPacketSize || largest(toClient) > innerPacketSize {
				t.Errorf("UDP phase packets by size: to VPC %v, to client %v; want %d of %d bytes each way, none larger",
					toVPC, toClient, udpRoundTrips, innerPacketSize)
			}
			if largest(allToVPC) > innerPacketSize || largest(allToClient) > innerPacketSize {
				t.Errorf("a packet over the whole session exceeded %d bytes", innerPacketSize)
			}
			if opened != 1 {
				t.Errorf("backend sessions = %d, want 1", opened)
			}
			other := map[string]string{counterUDP443: counterTCP443, counterTCP443: counterUDP443}[tr.counter]
			if after[tr.counter] == before[tr.counter] || after[other] != before[other] {
				t.Errorf("outer packets: %s %d, %s %d; want only %s",
					tr.counter, after[tr.counter]-before[tr.counter], other, after[other]-before[other], tr.counter)
			}
			if tr.alpn == "h2" && h.h2ProtoCount("HTTP/2.0") == h2Before {
				t.Error("no request reached the HTTP/2 server as HTTP/2.0")
			}
		})
	}
}

// TestXrayRejectsUntrustedServer requires the client to validate the server
// certificate: with an unrelated CA, no tunnel and no session may exist.
func TestXrayRejectsUntrustedServer(t *testing.T) {
	h := requireFixture(t)
	for _, tr := range transports {
		t.Run(tr.alpn, func(t *testing.T) {
			c := newConnector("untrusted-" + tr.alpn)
			x := h.startXray(t, "untrusted-"+tr.alpn, c, tr.alpn, h.otherCAFile)
			err := x.udpRoundTrips(1, 3*time.Second)
			_, _, opened, _ := h.backend.sizes(c.prefix).snapshot()
			certErr := strings.Contains(x.log(), "certificate signed by unknown authority")
			h.record(t, result{Check: "untrusted server certificate", Transport: tr.name, Client: clientXray,
				Detail: map[string]any{
					"round_trip_error":                  errString(err),
					"backend_sessions":                  opened,
					"client_reported_unknown_authority": certErr,
				}})
			if err == nil || opened != 0 {
				t.Fatalf("round trip error %v, backend sessions %d; want a failure and none", err, opened)
			}
			if !certErr {
				t.Errorf("Xray did not report an unknown certificate authority:\n%s", x.log())
			}
		})
	}
}

// TestHTTP2WithUDP443Blocked drops UDP/443 in the server namespace: the
// HTTP/3 client must fail with its packets dropped, and a separate HTTP/2
// client must pass without sending any UDP/443.
func TestHTTP2WithUDP443Blocked(t *testing.T) {
	h := requireFixture(t)
	h.blockUDP443(t)

	h3 := newConnector("blocked-h3")
	before := h.counters(t)
	x3 := h.startXray(t, "blocked-h3", h3, "h3", h.caFile)
	h3Err := x3.udpRoundTrips(1, 5*time.Second)
	// Stop the HTTP/3 client so its retransmissions cannot be counted
	// against the HTTP/2 run.
	x3.stop()
	mid := h.counters(t)
	_, _, h3Sessions, _ := h.backend.sizes(h3.prefix).snapshot()

	h2 := newConnector("blocked-h2")
	x2 := h.startXray(t, "blocked-h2", h2, "h2", h.caFile)
	h2Err := x2.udpRoundTrips(udpRoundTrips, 10*time.Second)
	after := h.counters(t)
	toVPC, toClient, h2Sessions, _ := h.backend.sizes(h2.prefix).snapshot()

	h.record(t, result{Check: "HTTP/2 with UDP/443 blocked", Transport: "HTTP/2", Client: clientXray,
		Detail: map[string]any{
			"http3_round_trip_error":     errString(h3Err),
			"http3_udp443_dropped":       mid[counterUDP443Dropped] - before[counterUDP443Dropped],
			"http3_backend_sessions":     h3Sessions,
			"http2_round_trip_error":     errString(h2Err),
			"http2_udp443_dropped":       after[counterUDP443Dropped] - mid[counterUDP443Dropped],
			"http2_outer_tcp443_packets": after[counterTCP443] - mid[counterTCP443],
			"http2_inner_1280_to_vpc":    toVPC[innerPacketSize],
			"http2_inner_1280_to_client": toClient[innerPacketSize],
			"http2_backend_sessions":     h2Sessions,
		}})
	if h3Err == nil || h3Sessions != 0 || mid[counterUDP443Dropped] == before[counterUDP443Dropped] {
		t.Errorf("HTTP/3 with UDP/443 blocked: error %v, sessions %d, dropped %d; want a failure, none and some",
			h3Err, h3Sessions, mid[counterUDP443Dropped]-before[counterUDP443Dropped])
	}
	if h2Err != nil {
		t.Errorf("HTTP/2 with UDP/443 blocked: %v", h2Err)
	}
	if after[counterUDP443Dropped] != mid[counterUDP443Dropped] || after[counterTCP443] == mid[counterTCP443] {
		t.Errorf("HTTP/2 run: %d UDP/443 packets dropped, %d TCP/443 packets; want none and some",
			after[counterUDP443Dropped]-mid[counterUDP443Dropped], after[counterTCP443]-mid[counterTCP443])
	}
	if toVPC[innerPacketSize] < udpRoundTrips || toClient[innerPacketSize] < udpRoundTrips {
		t.Errorf("HTTP/2 %d-byte packets: %d toward the VPC, %d toward the client; want at least %d each",
			innerPacketSize, toVPC[innerPacketSize], toClient[innerPacketSize], udpRoundTrips)
	}
}

// TestMalformedRequestLeavesSiblingIntact sends malformed input on one of two
// requests sharing a connection. A malformed or truncated capsule must end
// only that request; a datagram that is not IP, carries a spoofed source or a
// destination outside the advertised routes must be dropped without reaching
// the VPC or ending either request. A hop limit of 1 is forwarded, because
// the client decremented it on encapsulation. An oversized DATAGRAM capsule
// ends the request on HTTP/2, where the server must buffer it to forward it;
// on HTTP/3, connect-ip-go discards stream DATAGRAM capsules as they arrive,
// so the request stays open with nothing buffered.
func TestMalformedRequestLeavesSiblingIntact(t *testing.T) {
	h := requireFixture(t)
	datagram := appendDatagram(nil, make([]byte, 100))
	oversized := quicvarint.Append(nil, capsuleDatagram)
	oversized = quicvarint.Append(oversized, 1<<20)
	badRequest := appendCapsule(nil, capsuleAddressRequest, []byte{0x01, 0x05, 0xff})
	for _, tr := range transports {
		for _, tc := range []struct {
			name  string
			input func(r *rawRequest) error
			ends  bool
			// forwarded is the number of packets from the input itself that
			// must reach the VPC.
			forwarded int
		}{
			{"oversized capsule", func(r *rawRequest) error { return r.writeStream(oversized) }, tr.alpn == "h2", 0},
			{"malformed ADDRESS_REQUEST", func(r *rawRequest) error { return r.writeStream(badRequest) }, true, 0},
			{"capsule truncated by FIN", func(r *rawRequest) error {
				if err := r.writeStream(datagram[:len(datagram)-10]); err != nil {
					return err
				}
				return r.closeWrite()
			}, true, 0},
			{"non-IP datagram", func(r *rawRequest) error { return r.sendDatagram([]byte{0x45, 0, 0, 20}) }, false, 0},
			{"spoofed source", func(r *rawRequest) error {
				return r.sendDatagram(udpPacket(echoAddr, echoAddr, 64, make([]byte, echoPayload)))
			}, false, 0},
			{"destination outside the routes", func(r *rawRequest) error {
				return r.sendDatagram(udpPacket(r.prefix.Addr().Next(), outsideRoute, 64, make([]byte, echoPayload)))
			}, false, 0},
			// Decapsulation leaves the hop limit alone (RFC 9484, Section 7.2).
			{"hop limit 1", func(r *rawRequest) error {
				return r.sendDatagram(udpPacket(r.prefix.Addr().Next(), echoAddr, 1, make([]byte, echoPayload)))
			}, false, 1},
		} {
			t.Run(tr.alpn+"/"+tc.name, func(t *testing.T) {
				conn := tr.dial(h, t)
				ca := newConnector("malformed-a-" + tr.alpn + "-" + tc.name)
				a := conn.open(t, ca)
				b := conn.open(t, newConnector("malformed-b-"+tr.alpn+"-"+tc.name))
				a.roundTrip(t, 1)
				b.roundTrip(t, 1)
				detail := map[string]any{}
				h.record(t, result{Check: "malformed input: " + tc.name, Transport: tr.name, Client: clientRaw, Detail: detail})
				toVPCBefore, _, _, _ := h.backend.sizes(ca.prefix).snapshot()
				if err := tc.input(a); err != nil {
					t.Fatalf("send malformed input: %v", err)
				}
				ended := waitClosed(a.ended, 3*time.Second)
				detail["malformed_request_ended"] = ended
				detail["sibling_round_trip_bytes"] = b.roundTrip(t, 2)
				switch {
				case tc.ends && !ended:
					t.Fatal("the malformed request was not ended")
				case !tc.ends && ended:
					t.Fatal("the request was ended")
				}
				// The packets that may reach the VPC after the input: those the
				// input must forward, plus, for a request that stays open, the
				// probe sent after it on the same request.
				want := tc.forwarded
				if tc.ends {
					closed := waitFor(3*time.Second, func() bool {
						_, _, _, n := h.backend.sizes(ca.prefix).snapshot()
						return n == 1
					})
					detail["malformed_backend_closed"] = closed
					if !closed {
						t.Error("the malformed request's backend session was not closed")
					}
				} else {
					detail["malformed_request_round_trip_bytes"] = a.roundTrip(t, 3)
					want++
				}
				toVPCAfter, _, _, _ := h.backend.sizes(ca.prefix).snapshot()
				reached := sum(toVPCAfter) - sum(toVPCBefore)
				detail["packets_reached_vpc_after_input"] = reached
				if reached != want {
					t.Errorf("%d packets reached the VPC after the input, want %d", reached, want)
				}
			})
		}
	}
}

// TestCancelledRequestLeavesSiblingIntact cancels one of two requests on a
// connection; the server must close that request's backend session while
// the other keeps forwarding.
func TestCancelledRequestLeavesSiblingIntact(t *testing.T) {
	h := requireFixture(t)
	for _, tr := range transports {
		t.Run(tr.alpn, func(t *testing.T) {
			conn := tr.dial(h, t)
			ca, cb := newConnector("cancel-a-"+tr.alpn), newConnector("cancel-b-"+tr.alpn)
			a, b := conn.open(t, ca), conn.open(t, cb)
			a.roundTrip(t, 1)
			b.roundTrip(t, 1)
			a.cancel()
			closed := waitFor(5*time.Second, func() bool {
				_, _, _, n := h.backend.sizes(ca.prefix).snapshot()
				return n == 1
			})
			size := b.roundTrip(t, 2)
			_, _, _, bClosed := h.backend.sizes(cb.prefix).snapshot()
			h.record(t, result{Check: "cancel one request", Transport: tr.name, Client: clientRaw, Detail: map[string]any{
				"cancelled_backend_session_closed": closed,
				"sibling_round_trip_bytes":         size,
				"sibling_backend_session_closed":   bClosed == 1,
			}})
			if !closed {
				t.Error("the cancelled request's backend session was not closed")
			}
			if bClosed != 0 {
				t.Error("the sibling's backend session was closed")
			}
		})
	}
}

func waitClosed(ch <-chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

func waitFor(d time.Duration, cond func() bool) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for !cond() {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(20 * time.Millisecond):
		}
	}
	return true
}

func largest(m map[int]int) int {
	n := 0
	for k := range m {
		n = max(n, k)
	}
	return n
}

func sum(m map[int]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
