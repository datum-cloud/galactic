// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// connectIP opens one CONNECT-IP request over HTTP/3, or over HTTP/2 with
// -transport h2, and sends ICMPv6 echo requests through it from an address
// in its assigned /96, one to each destination of -to on every tick. It
// prints the response status and the ALPN protocol the connection
// negotiated {"t","status","proto"}, the assignment {"t","assigned"}, each
// echo reply {"t","seq","from","dst","len","reply":"echo"}, every other
// packet the tunnel delivers {"t","from","dst","len","reply":"other"}, the
// end of a tunnel the server closed {"t","end","error"} and the count
// {"t","sent"}. A refused request exits 0 after printing its status.
func connectIP(args []string) error {
	fs := flag.NewFlagSet("connectip", flag.ExitOnError)
	server := fs.String("server", "", "server [address]:port")
	authority := fs.String("authority", "", "host:port of the URI template; the host is the TLS server name")
	caFile := fs.String("ca", "", "PEM file of the CA that signed the server's certificate")
	token := fs.String("token", "", "bearer credential")
	vpc := fs.String("vpc", "", "Galactic-VPC header value")
	transport := fs.String("transport", "h3", "h3 for HTTP/3 over QUIC, h2 for HTTP/2 over TLS")
	to := fs.String("to", "", "comma-separated echo destinations")
	srcFlag := fs.String("src", "", "comma-separated source addresses, each sent to every destination; "+
		"default the first address after the assigned prefix's")
	id := fs.Int("id", os.Getpid()&0xffff, "ICMPv6 echo identifier")
	size := fs.Int("size", 64, "IPv6 packet size in bytes")
	interval := fs.Duration("interval", 50*time.Millisecond, "time between echo requests")
	duration := fs.Duration("duration", 5*time.Second, "how long to send")
	_ = fs.Parse(args)
	var dial dialFunc
	switch *transport {
	case "h3":
		dial = dialH3
	case "h2":
		dial = dialH2
	default:
		return fmt.Errorf("-transport %q: want h3 or h2", *transport)
	}
	var dsts []netip.Addr
	for _, a := range strings.Split(*to, ",") {
		dst, err := netip.ParseAddr(a)
		if err != nil {
			return fmt.Errorf("-to: %w", err)
		}
		dsts = append(dsts, dst)
	}
	host, _, err := net.SplitHostPort(*authority)
	if err != nil {
		return fmt.Errorf("-authority: %w", err)
	}
	pemBytes, err := os.ReadFile(*caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return errors.New("-ca holds no certificate")
	}
	tmpl, err := uritemplate.New("https://" + *authority + "/.well-known/masque/ip/*/*/")
	if err != nil {
		return err
	}
	req := cipRequest{
		server:   *server,
		tls:      &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS13},
		template: tmpl,
		header:   http.Header{},
	}
	req.header.Set("Authorization", "Bearer "+*token)
	req.header.Set("Galactic-VPC", *vpc)

	ctx, cancel := context.WithTimeout(context.Background(), *duration+30*time.Second)
	defer cancel()
	tun, rsp, err := dial(ctx, req)
	if rsp.Status != 0 {
		_ = out.Encode(cipEvent{T: boottime(), Status: rsp.Status, Proto: rsp.Proto})
	}
	if err != nil {
		if rsp.Status != 0 {
			return nil
		}
		return err
	}
	defer func() { _ = tun.Close() }()
	assigned, err := tun.assigned(ctx)
	if err != nil {
		return err
	}
	if len(assigned) != 1 {
		return fmt.Errorf("assigned %v, want one prefix", assigned)
	}
	prefix := assigned[0]
	_ = out.Encode(cipEvent{T: boottime(), Assigned: prefix.String()})
	srcs := []netip.Addr{prefix.Addr().Next()}
	if *srcFlag != "" {
		srcs = nil
		for _, a := range strings.Split(*srcFlag, ",") {
			src, err := netip.ParseAddr(a)
			if err != nil {
				return fmt.Errorf("-src: %w", err)
			}
			srcs = append(srcs, src)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, err := tun.ReadPacket(buf)
			if err != nil {
				_ = out.Encode(cipEvent{T: boottime(), End: true, Error: err.Error()})
				return
			}
			report(buf[:n], *id)
		}
	}()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	deadline := time.Now().Add(*duration)
	sent := 0
loop:
	for time.Now().Before(deadline) {
		for _, src := range srcs {
			for _, dst := range dsts {
				pkt, err := echoRequest(src, dst, *id, sent, *size)
				if err != nil {
					return err
				}
				if err := tun.WritePacket(pkt); err != nil {
					break loop
				}
				sent++
			}
		}
		select {
		case <-tick.C:
		case <-done:
			break loop
		}
	}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
	}
	_ = tun.Close()
	<-done
	return out.Encode(cipEvent{T: boottime(), Sent: sent})
}

// cipRequest is what both transports send: the server to dial, the TLS
// settings without ALPN, the URI template and the request headers.
type cipRequest struct {
	server   string
	tls      *tls.Config
	template *uritemplate.Template
	header   http.Header
}

// cipResponse is what a transport learned before the tunnel opened: the ALPN
// protocol the connection negotiated and the response status, 0 when no
// response arrived.
type cipResponse struct {
	Proto  string
	Status int
}

// dialFunc opens one CONNECT-IP request. An error with a nonzero
// cipResponse.Status means the server answered and refused the request.
type dialFunc func(ctx context.Context, r cipRequest) (cipTunnel, cipResponse, error)

// cipTunnel is an accepted CONNECT-IP request on either transport. assigned
// is called once, before ReadPacket. ReadPacket returns an error once the
// tunnel ends and only the one reading goroutine calls it; WritePacket is
// called from one other goroutine.
type cipTunnel interface {
	assigned(ctx context.Context) ([]netip.Prefix, error)
	ReadPacket(b []byte) (int, error)
	WritePacket(pkt []byte) error
	Close() error
}

// dialH3 opens the request on a QUIC connection with connect-ip-go.
func dialH3(ctx context.Context, r cipRequest) (cipTunnel, cipResponse, error) {
	cfg := r.tls.Clone()
	cfg.NextProtos = []string{http3.NextProtoH3}
	qconn, err := quic.DialAddr(ctx, r.server, cfg, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	if err != nil {
		return nil, cipResponse{}, fmt.Errorf("dial %s: %w", r.server, err)
	}
	rsp := cipResponse{Proto: qconn.ConnectionState().TLS.NegotiatedProtocol}
	cc, err := (&connectip.Transport{}).NewClientConn(qconn)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, rsp, err
	}
	req, err := connectip.NewRequest(ctx, r.template)
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, rsp, err
	}
	for k, vs := range r.header {
		for _, v := range vs {
			req.Header().Add(k, v)
		}
	}
	conn, hrsp, err := cc.Dial(req)
	if hrsp != nil {
		rsp.Status = hrsp.StatusCode
	}
	if err != nil {
		_ = qconn.CloseWithError(0, "")
		return nil, rsp, err
	}
	return &h3Tunnel{conn: conn, qconn: qconn}, rsp, nil
}

// h3Tunnel carries packets as HTTP/3 datagrams.
type h3Tunnel struct {
	conn  *connectip.Conn
	qconn *quic.Conn
}

func (t *h3Tunnel) assigned(ctx context.Context) ([]netip.Prefix, error) {
	a, err := t.conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, len(a))
	for i, p := range a {
		prefixes[i] = p.IPPrefix
	}
	return prefixes, nil
}

func (t *h3Tunnel) ReadPacket(b []byte) (int, error) { return t.conn.ReadPacket(b) }

// WritePacket ignores the Packet Too Big connect-ip-go returns for a packet
// over the path's datagram size: the probe only counts what it sent.
func (t *h3Tunnel) WritePacket(pkt []byte) error {
	_, err := t.conn.WritePacket(pkt)
	return err
}

func (t *h3Tunnel) Close() error {
	err := t.conn.Close()
	_ = t.qconn.CloseWithError(0, "")
	return err
}

// report prints one packet the tunnel delivered.
func report(p []byte, id int) {
	t := boottime()
	if len(p) < ipv6.HeaderLen || p[0]>>4 != 6 {
		_ = out.Encode(cipEvent{T: t, Len: len(p), Reply: replyOther})
		return
	}
	src, _ := netip.AddrFromSlice(p[8:24])
	dst, _ := netip.AddrFromSlice(p[24:40])
	ev := cipEvent{T: t, From: src.String(), Dst: dst.String(), Len: len(p), Reply: replyOther}
	if p[6] == 58 {
		if m, err := icmp.ParseMessage(58, p[ipv6.HeaderLen:]); err == nil && m.Type == ipv6.ICMPTypeEchoReply {
			if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id {
				ev.Reply, ev.Seq = replyEcho, &e.Seq
			}
		}
	}
	_ = out.Encode(ev)
}

// Values of cipEvent.Reply.
const (
	replyEcho  = "echo"
	replyOther = "other"
)

// cipEvent is one line connectIP prints.
type cipEvent struct {
	T        int64  `json:"t"`
	Status   int    `json:"status,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Assigned string `json:"assigned,omitempty"`
	Seq      *int   `json:"seq,omitempty"`
	From     string `json:"from,omitempty"`
	Dst      string `json:"dst,omitempty"`
	Len      int    `json:"len,omitempty"`
	Reply    string `json:"reply,omitempty"`
	End      bool   `json:"end,omitempty"`
	Error    string `json:"error,omitempty"`
	Sent     int    `json:"sent,omitempty"`
}

// echoRequest builds an IPv6 ICMPv6 echo request of size bytes.
func echoRequest(src, dst netip.Addr, id, seq, size int) ([]byte, error) {
	data := make([]byte, max(size-ipv6.HeaderLen-8, 0))
	m := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: id, Seq: seq & 0xffff, Data: data}}
	body, err := m.Marshal(icmp.IPv6PseudoHeader(net.IP(src.AsSlice()), net.IP(dst.AsSlice())))
	if err != nil {
		return nil, err
	}
	pkt := make([]byte, ipv6.HeaderLen, ipv6.HeaderLen+len(body))
	pkt[0] = 6 << 4
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(body)))
	pkt[6], pkt[7] = 58, 64
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])
	return append(pkt, body...), nil
}
