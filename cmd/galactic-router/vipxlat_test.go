// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"go.datum.net/galactic/internal/plumbing/ebpf/vipxlatmap"
)

// fakeXlatTable records UnregisterBinding calls and serves fixed rows.
type fakeXlatTable struct {
	entries []vipxlatmap.Entry
	calls   []string
}

func (f *fakeXlatTable) List() ([]vipxlatmap.Entry, error) { return f.entries, nil }

func (f *fakeXlatTable) UnregisterBinding(proto uint8, vipAddr net.IP, vipPort uint16,
	backendAddr net.IP, backendPort uint16) ([]vipxlatmap.Entry, error) {
	f.calls = append(f.calls, strings.Join([]string{
		xlatProtocolName(proto),
		net.JoinHostPort(vipAddr.String(), itoa(vipPort)),
		net.JoinHostPort(backendAddr.String(), itoa(backendPort)),
	}, " "))
	return f.entries, nil
}

func itoa(v uint16) string { return strconv.Itoa(int(v)) }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// runXlat runs "vip xlat <args>" against table and returns its output.
func runXlat(t *testing.T, table *fakeXlatTable, args ...string) (string, error) {
	t.Helper()
	orig := openVipXlatTable
	openVipXlatTable = func(string) (vipXlatTable, io.Closer, error) { return table, nopCloser{}, nil }
	t.Cleanup(func() { openVipXlatTable = orig })

	cmd := newVIPCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"xlat"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

func testXlatEntries() []vipxlatmap.Entry {
	return []vipxlatmap.Entry{
		{
			Key:         vipxlatmap.Key{Block: 0x20010db8ff01, Argument: 70, Proto: vipxlatmap.ProtoTCP, Port: 8080},
			Direction:   vipxlatmap.DirectionIngress,
			Addr:        net.ParseIP("fd20:60::1"),
			RewritePort: 30080,
		},
		{
			Key:         vipxlatmap.Key{Block: 0x20010db8ff01, Argument: 70, Proto: vipxlatmap.ProtoTCP, Port: 30080},
			Direction:   vipxlatmap.DirectionEgress,
			Addr:        net.ParseIP("2001:db8::1"),
			RewritePort: 8080,
		},
	}
}

func TestVIPXlatList(t *testing.T) {
	out, err := runXlat(t, &fakeXlatTable{entries: testXlatEntries()}, "list")
	if err != nil {
		t.Fatalf("list: unexpected error: %v", err)
	}
	for _, want := range []string{
		"DIRECTION", "ingress", "egress", "0x20010db8ff01", "[fd20:60::1]:30080", "[2001:db8::1]:8080",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
}

func TestVIPXlatRemove(t *testing.T) {
	table := &fakeXlatTable{entries: testXlatEntries()}
	out, err := runXlat(t, table, "remove",
		"--protocol", "TCP", "--vip", "2001:db8::1", "--port", "8080",
		"--backend", "fd20:60::1", "--backend-port", "30080")
	if err != nil {
		t.Fatalf("remove: unexpected error: %v", err)
	}
	want := "tcp [2001:db8::1]:8080 [fd20:60::1]:30080"
	if len(table.calls) != 1 || table.calls[0] != want {
		t.Errorf("UnregisterBinding calls = %q, want [%q]", table.calls, want)
	}
	if !strings.Contains(out, "egress") {
		t.Errorf("remove output does not list the removed rows:\n%s", out)
	}
}

func TestVIPXlatRemoveNoMatch(t *testing.T) {
	out, err := runXlat(t, &fakeXlatTable{}, "remove",
		"--protocol", "udp", "--vip", "2001:db8::1", "--port", "53",
		"--backend", "fd20:60::1", "--backend-port", "53")
	if err != nil {
		t.Fatalf("remove: unexpected error: %v", err)
	}
	if !strings.Contains(out, "no matching rows") {
		t.Errorf("remove output = %q, want it to say no rows matched", out)
	}
}

func TestVIPXlatRemoveRejectsBadInput(t *testing.T) {
	valid := map[string]string{
		xlatFlagProtocol: xlatProtocolTCP, xlatFlagVIP: "2001:db8::1", xlatFlagPort: "8080",
		xlatFlagBackend: "fd20:60::1", xlatFlagBackendPort: "30080",
	}
	cases := map[string]map[string]string{
		"bad protocol": {xlatFlagProtocol: "sctp"},
		"bad vip":      {xlatFlagVIP: "not-an-ip"},
		"bad backend":  {xlatFlagBackend: "not-an-ip"},
		"zero port":    {xlatFlagPort: "0"},
		"port too big": {xlatFlagBackendPort: "70000"},
		"missing flag": {xlatFlagVIP: ""},
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			var args []string
			for flag, value := range valid {
				if v, ok := override[flag]; ok {
					value = v
				}
				if value == "" {
					continue
				}
				args = append(args, "--"+flag, value)
			}
			table := &fakeXlatTable{}
			if _, err := runXlat(t, table, append([]string{"remove"}, args...)...); err == nil {
				t.Error("remove: expected an error")
			}
			if len(table.calls) != 0 {
				t.Errorf("UnregisterBinding called %d times, want 0", len(table.calls))
			}
		})
	}
}
