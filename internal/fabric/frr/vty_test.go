// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package frr

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.datum.net/galactic/internal/fabric/query"
)

// fakeDaemon serves one FRR daemon's vty socket. handle receives each
// command and writes whatever it likes to the connection.
type fakeDaemon struct {
	dir      string
	commands chan string
}

// oneOneOneOne is an address, not a prefix or AS path.
const oneOneOneOne = "1.1.1.1"

func startFake(t *testing.T, daemon Daemon, handle func(cmd string, c net.Conn)) *fakeDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "vty")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(dir, string(daemon)+".vty"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := &fakeDaemon{dir: dir, commands: make(chan string, 16)}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				cmd, err := bufio.NewReader(c).ReadString(0)
				if err != nil {
					return
				}
				cmd = strings.TrimSuffix(cmd, "\x00")
				f.commands <- cmd
				handle(cmd, c)
			}()
		}
	}()
	return f
}

func reply(out string, ret byte) func(string, net.Conn) {
	return func(_ string, c net.Conn) {
		_, _ = c.Write(append([]byte(out), 0, 0, 0, ret))
	}
}

func mustSummary(t *testing.T) Command {
	t.Helper()
	c, err := SummaryCommand(query.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVTYRun(t *testing.T) {
	f := startFake(t, DaemonBGP, reply(`{"routerId":"1.1.1.1"}`+"\n", 0))
	v := &VTY{SocketDir: f.dir}
	resp, err := v.Run(context.Background(), mustSummary(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Output) != `{"routerId":"1.1.1.1"}`+"\n" || resp.Warning {
		t.Errorf("resp = %q %v", resp.Output, resp.Warning)
	}
	if got := <-f.commands; got != "show bgp ipv4 unicast summary json" {
		t.Errorf("sent %q", got)
	}
}

func TestVTYPartialReads(t *testing.T) {
	f := startFake(t, DaemonBGP, func(_ string, c net.Conn) {
		for _, part := range []string{`{"a":`, `1}`, "\x00", "\x00\x00", "\x00"} {
			_, _ = c.Write([]byte(part))
			time.Sleep(5 * time.Millisecond)
		}
	})
	resp, err := (&VTY{SocketDir: f.dir}).Run(context.Background(), mustSummary(t))
	if err != nil || string(resp.Output) != `{"a":1}` {
		t.Fatalf("resp = %q, %v", resp.Output, err)
	}
}

func TestVTYReturnCodes(t *testing.T) {
	tests := []struct {
		ret     byte
		code    ErrorCode
		warning bool
	}{
		{ret: 0},
		{ret: 1, warning: true},
		{ret: 2, code: CodeCommandFailed},
		{ret: 13, code: CodeCommandFailed},
	}
	for _, tt := range tests {
		f := startFake(t, DaemonBGP, reply("out", tt.ret))
		resp, err := (&VTY{SocketDir: f.dir}).Run(context.Background(), mustSummary(t))
		if CodeOf(err) != tt.code {
			t.Errorf("ret %d: err = %v, want %q", tt.ret, err, tt.code)
		}
		if err == nil && resp.Warning != tt.warning {
			t.Errorf("ret %d: warning = %v", tt.ret, resp.Warning)
		}
	}
}

func TestVTYByteCap(t *testing.T) {
	f := startFake(t, DaemonBGP, func(_ string, c net.Conn) {
		_, _ = c.Write([]byte(strings.Repeat("x", 4096)))
		_, _ = c.Write([]byte{0, 0, 0, 0})
	})
	_, err := (&VTY{SocketDir: f.dir, MaxResponseBytes: 1024}).Run(context.Background(), mustSummary(t))
	if CodeOf(err) != CodeResponseTooLarge {
		t.Fatalf("err = %v", err)
	}
}

func TestVTYClosedEarly(t *testing.T) {
	f := startFake(t, DaemonBGP, func(_ string, c net.Conn) { _, _ = c.Write([]byte(`{"partial":`)) })
	_, err := (&VTY{SocketDir: f.dir}).Run(context.Background(), mustSummary(t))
	if CodeOf(err) != CodeMalformed {
		t.Fatalf("err = %v", err)
	}
}

func TestVTYTimeoutAndCancel(t *testing.T) {
	f := startFake(t, DaemonBGP, func(_ string, _ net.Conn) { time.Sleep(2 * time.Second) })
	v := &VTY{SocketDir: f.dir}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := v.Run(ctx, mustSummary(t))
	if CodeOf(err) != CodeTimeout || time.Since(start) > time.Second {
		t.Fatalf("deadline: err = %v after %v", err, time.Since(start))
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel2() }()
	start = time.Now()
	_, err = v.Run(ctx2, mustSummary(t))
	if CodeOf(err) != CodeTimeout || time.Since(start) > time.Second {
		t.Fatalf("cancel: err = %v after %v", err, time.Since(start))
	}
}

func TestVTYUnavailable(t *testing.T) {
	// A daemon that restarted has no socket for a moment.
	_, err := (&VTY{SocketDir: t.TempDir()}).Run(context.Background(), mustSummary(t))
	if CodeOf(err) != CodeUnavailable {
		t.Fatalf("err = %v", err)
	}
}

func TestVTYRoutesToDaemon(t *testing.T) {
	f := startFake(t, DaemonZebra, reply("{}\n", 1))
	cmd, err := RouteCommand(netip.MustParsePrefix("10.99.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&VTY{SocketDir: f.dir}).Run(context.Background(), cmd)
	if err != nil || !resp.Warning {
		t.Fatalf("resp = %+v, %v", resp, err)
	}
	if got := <-f.commands; got != "show ip route 10.99.0.0/16 json" {
		t.Errorf("sent %q", got)
	}
}

func TestCommands(t *testing.T) {
	mustQ := func(q query.Query) query.Query {
		c, err := query.Canonicalize(q)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	tests := []struct {
		build func() (Command, error)
		want  string
		d     Daemon
	}{
		{func() (Command, error) { return SummaryCommand(query.IPv6) }, "show bgp ipv6 unicast summary json", DaemonBGP},
		{func() (Command, error) {
			return LookupCommand(mustQ(query.Query{Type: query.TypeRouteLookup, Target: docPrefixV4}))
		}, "show bgp ipv4 unicast 198.51.100.0/24 json", DaemonBGP},
		{func() (Command, error) {
			return LookupCommand(mustQ(query.Query{Type: query.TypeRouteLookup, Target: "2001:DB8::1"}))
		}, "show bgp ipv6 unicast 2001:db8::1 json", DaemonBGP},
		{func() (Command, error) {
			return SearchCommand(mustQ(query.Query{Type: query.TypeASPath, Target: "^65001_", AddressFamily: query.IPv6}))
		}, "show bgp ipv6 unicast regexp ^65001_ json", DaemonBGP},
		{func() (Command, error) {
			return SearchCommand(mustQ(query.Query{Type: query.TypeCommunity, Target: "65001:100"}))
		}, "show bgp ipv4 unicast community 65001:100 json", DaemonBGP},
		{func() (Command, error) {
			return SearchCommand(mustQ(query.Query{Type: query.TypeLargeCommunity, Target: "65001:1:1"}))
		}, "show bgp ipv4 unicast large-community 65001:1:1 json", DaemonBGP},
		{func() (Command, error) {
			return RouteCommand(netip.MustParsePrefix("2001:db8::/32"))
		}, "show ipv6 route 2001:db8::/32 json", DaemonZebra},
	}
	for _, tt := range tests {
		c, err := tt.build()
		if err != nil {
			t.Fatalf("%s: %v", tt.want, err)
		}
		if c.String() != tt.want || c.Daemon() != tt.d {
			t.Errorf("got %q to %s, want %q to %s", c, c.Daemon(), tt.want, tt.d)
		}
	}

	// Each constructor rejects inputs that did not come through Canonicalize.
	bad := []func() (Command, error){
		func() (Command, error) {
			return LookupCommand(query.Query{
				Type: query.TypeRouteLookup, Target: "1.1.1.0/24 json\nclear bgp *", AddressFamily: query.IPv4,
			})
		},
		func() (Command, error) {
			return LookupCommand(query.Query{Type: query.TypeRouteLookup, Target: oneOneOneOne, AddressFamily: query.IPv6})
		},
		func() (Command, error) {
			return LookupCommand(query.Query{Type: query.TypeASPath, Target: oneOneOneOne, AddressFamily: query.IPv4})
		},
		func() (Command, error) {
			return SearchCommand(query.Query{Type: query.TypeASPath, Target: "^1 json", AddressFamily: query.IPv4})
		},
		func() (Command, error) {
			return SearchCommand(query.Query{Type: query.TypeCommunity, Target: "065001:100", AddressFamily: query.IPv4})
		},
		func() (Command, error) {
			return SearchCommand(query.Query{Type: query.TypeRouteLookup, Target: oneOneOneOne, AddressFamily: query.IPv4})
		},
		func() (Command, error) { return SummaryCommand("ipv4") },
		func() (Command, error) { return RouteCommand(netip.MustParsePrefix("10.0.0.1/8")) },
		func() (Command, error) { return build(DaemonBGP, "clear bgp *") },
		func() (Command, error) { return build(DaemonBGP, "show x\ny") },
	}
	for i, b := range bad {
		if c, err := b(); err == nil {
			t.Errorf("bad[%d]: built %q", i, c)
		}
	}
}
