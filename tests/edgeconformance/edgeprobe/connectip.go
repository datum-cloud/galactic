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

// connectIP opens one CONNECT-IP request over HTTP/3 and sends ICMPv6 echo
// requests through it from an address in its assigned /96, one to each
// destination of -to on every tick. It prints the
// response status {"t","status"}, the assignment {"t","assigned"}, each echo
// reply {"t","seq","from","dst","reply":"echo"}, every other packet the
// tunnel delivers {"t","from","dst","reply":"other"}, the end of a tunnel
// the server closed {"t","end","error"} and the count {"t","sent"}. A
// refused request exits 0 after printing its status.
func connectIP(args []string) error {
	fs := flag.NewFlagSet("connectip", flag.ExitOnError)
	server := fs.String("server", "", "server [address]:port")
	authority := fs.String("authority", "", "host:port of the URI template; the host is the TLS server name")
	caFile := fs.String("ca", "", "PEM file of the CA that signed the server's certificate")
	token := fs.String("token", "", "bearer credential")
	vpc := fs.String("vpc", "", "Galactic-VPC header value")
	to := fs.String("to", "", "comma-separated echo destinations")
	srcFlag := fs.String("src", "", "source address; default the first address after the assigned prefix's")
	id := fs.Int("id", os.Getpid()&0xffff, "ICMPv6 echo identifier")
	size := fs.Int("size", 64, "IPv6 packet size in bytes")
	interval := fs.Duration("interval", 50*time.Millisecond, "time between echo requests")
	duration := fs.Duration("duration", 5*time.Second, "how long to send")
	_ = fs.Parse(args)
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

	ctx, cancel := context.WithTimeout(context.Background(), *duration+30*time.Second)
	defer cancel()
	qconn, err := quic.DialAddr(ctx, *server, &tls.Config{ServerName: host, RootCAs: roots,
		NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13},
		&quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	if err != nil {
		return fmt.Errorf("dial %s: %w", *server, err)
	}
	defer func() { _ = qconn.CloseWithError(0, "") }()
	cc, err := (&connectip.Transport{}).NewClientConn(qconn)
	if err != nil {
		return err
	}
	req, err := connectip.NewRequest(ctx, tmpl)
	if err != nil {
		return err
	}
	req.Header().Set("Authorization", "Bearer "+*token)
	req.Header().Set("Galactic-VPC", *vpc)
	conn, rsp, err := cc.Dial(req)
	if rsp != nil {
		_ = out.Encode(cipEvent{T: boottime(), Status: rsp.StatusCode})
	}
	if err != nil {
		if rsp != nil {
			return nil
		}
		return err
	}
	defer func() { _ = conn.Close() }()
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		return err
	}
	if len(assigned) != 1 {
		return fmt.Errorf("assigned %v, want one prefix", assigned)
	}
	prefix := assigned[0].IPPrefix
	_ = out.Encode(cipEvent{T: boottime(), Assigned: prefix.String()})
	src := prefix.Addr().Next()
	if *srcFlag != "" {
		if src, err = netip.ParseAddr(*srcFlag); err != nil {
			return fmt.Errorf("-src: %w", err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, err := conn.ReadPacket(buf)
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
		for _, dst := range dsts {
			pkt, err := echoRequest(src, dst, *id, sent, *size)
			if err != nil {
				return err
			}
			if _, err := conn.WritePacket(pkt); err != nil {
				break loop
			}
			sent++
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
	_ = conn.Close()
	<-done
	return out.Encode(cipEvent{T: boottime(), Sent: sent})
}

// cipEvent is one line connectIP prints.
type cipEvent struct {
	T        int64  `json:"t"`
	Status   int    `json:"status,omitempty"`
	Assigned string `json:"assigned,omitempty"`
	Seq      *int   `json:"seq,omitempty"`
	From     string `json:"from,omitempty"`
	Dst      string `json:"dst,omitempty"`
	Reply    string `json:"reply,omitempty"`
	End      bool   `json:"end,omitempty"`
	Error    string `json:"error,omitempty"`
	Sent     int    `json:"sent,omitempty"`
}

// report prints one packet the tunnel delivered.
func report(p []byte, id int) {
	t := boottime()
	if len(p) < ipv6.HeaderLen || p[0]>>4 != 6 {
		_ = out.Encode(cipEvent{T: t, Reply: "other"})
		return
	}
	src, _ := netip.AddrFromSlice(p[8:24])
	dst, _ := netip.AddrFromSlice(p[24:40])
	ev := cipEvent{T: t, From: src.String(), Dst: dst.String(), Reply: "other"}
	if p[6] == 58 {
		if m, err := icmp.ParseMessage(58, p[ipv6.HeaderLen:]); err == nil && m.Type == ipv6.ICMPTypeEchoReply {
			if e, ok := m.Body.(*icmp.Echo); ok && e.ID == id {
				ev.Reply, ev.Seq = "echo", &e.Seq
			}
		}
	}
	_ = out.Encode(ev)
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
