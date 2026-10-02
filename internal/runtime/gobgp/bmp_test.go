// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gobgp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/types"

	"go.datum.net/galactic/internal/model"
)

const (
	bmpTestWait    = 10 * time.Second
	bmpTestSysName = "node-a"
)

// bmpMessage is one BMP message a fakeCollector received: its type, and for an
// Initiation the sysName it carried.
type bmpMessage struct {
	typ     uint8
	sysName string
}

// fakeCollector is a BMP collector that records the messages it receives on
// each accepted session.
type fakeCollector struct {
	ln       net.Listener
	sessions chan chan bmpMessage
}

func newFakeCollector(t *testing.T) *fakeCollector {
	t.Helper()
	return newFakeCollectorAt(t, "127.0.0.1:0")
}

// newFakeCollectorAt starts a fakeCollector listening on addr.
func newFakeCollectorAt(t *testing.T, addr string) *fakeCollector {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &fakeCollector{ln: ln, sessions: make(chan chan bmpMessage, 4)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			msgs := make(chan bmpMessage, 64)
			c.sessions <- msgs
			go readBMP(conn, msgs)
		}
	}()
	return c
}

// station returns the collector's address as a BMPStation.
func (c *fakeCollector) station() BMPStation {
	ap := netip.MustParseAddrPort(c.ln.Addr().String())
	return BMPStation{Host: ap.Addr().String(), Port: ap.Port()}
}

// readBMP decodes BMP messages from conn into msgs, closing msgs when the
// session ends.
func readBMP(conn net.Conn, msgs chan<- bmpMessage) {
	defer close(msgs)
	defer func() { _ = conn.Close() }()
	hdr := make([]byte, bmp.BMP_HEADER_SIZE)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(hdr[1:5])-bmp.BMP_HEADER_SIZE)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		m := bmpMessage{typ: hdr[5]}
		if m.typ == bmp.BMP_MSG_INITIATION {
			m.sysName = initiationSysName(body)
		}
		msgs <- m
	}
}

// initiationSysName returns the sysName TLV of an Initiation message body.
func initiationSysName(body []byte) string {
	for len(body) >= 4 {
		typ := binary.BigEndian.Uint16(body[0:2])
		n := int(binary.BigEndian.Uint16(body[2:4]))
		if len(body) < 4+n {
			return ""
		}
		if typ == bmp.BMP_INIT_TLV_TYPE_SYS_NAME {
			return string(body[4 : 4+n])
		}
		body = body[4+n:]
	}
	return ""
}

// nextSession waits for the collector to accept a session.
func (c *fakeCollector) nextSession(t *testing.T) chan bmpMessage {
	t.Helper()
	select {
	case s := <-c.sessions:
		return s
	case <-time.After(bmpTestWait):
		t.Fatal("no BMP session opened")
		return nil
	}
}

// expectNoSession fails if the collector accepts a session within d.
func (c *fakeCollector) expectNoSession(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-c.sessions:
		t.Fatal("unexpected BMP session opened")
	case <-time.After(d):
	}
}

// expectInitiation waits for the next message on session and fails unless it
// is an Initiation, the first message of every BMP session.
func expectInitiation(t *testing.T, session chan bmpMessage) bmpMessage {
	t.Helper()
	select {
	case m, ok := <-session:
		if !ok {
			t.Fatal("session closed, want an Initiation")
		}
		if m.typ != bmp.BMP_MSG_INITIATION {
			t.Fatalf("message type = %d, want Initiation", m.typ)
		}
		return m
	case <-time.After(bmpTestWait):
		t.Fatal("no message, want an Initiation")
		return bmpMessage{}
	}
}

// expectTerminated waits for session to deliver a Termination and then close,
// skipping any messages before the Termination.
func expectTerminated(t *testing.T, session chan bmpMessage) {
	t.Helper()
	deadline := time.After(bmpTestWait)
	sawTermination := false
	for {
		select {
		case m, ok := <-session:
			if !ok {
				if !sawTermination {
					t.Fatal("session closed without a Termination")
				}
				return
			}
			sawTermination = sawTermination || m.typ == bmp.BMP_MSG_TERMINATION
		case <-deadline:
			t.Fatal("session not terminated")
		}
	}
}

// recordingBMPObserver records the last state reported for each station.
type recordingBMPObserver struct {
	mu    sync.Mutex
	state map[string]bool
}

func (o *recordingBMPObserver) BMPStationState(_, station string, up bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state == nil {
		o.state = make(map[string]bool)
	}
	o.state[station] = up
}

// get returns the last state reported for station and whether one was.
func (o *recordingBMPObserver) get(station string) (up, reported bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	up, reported = o.state[station]
	return up, reported
}

// newBMPTestRuntime returns a runtime streaming to stations, stopped at test
// cleanup. resolve, when non-nil, replaces the keeper's name resolution.
func newBMPTestRuntime(
	t *testing.T, obs BMPStateObserver, resolve func(context.Context, string) (netip.Addr, error),
	stations ...BMPStation,
) *GoBGPRuntime {
	t.Helper()
	rt, err := NewRuntimeFactory(-1, false, "", nil, BMPConfig{
		Stations: stations,
		Policy:   api.AddBmpRequest_MONITORING_POLICY_PRE,
		SysName:  bmpTestSysName,
		Observer: obs,
	})(types.NamespacedName{Name: "bmp-test"})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	gr := rt.(*GoBGPRuntime)
	if resolve != nil {
		gr.bmp.resolve = resolve
	}
	t.Cleanup(func() { _ = gr.Stop(context.Background()) })
	return gr
}

func applyASN(t *testing.T, rt *GoBGPRuntime, asn int64) {
	t.Helper()
	if err := rt.Apply(context.Background(), model.DesiredRouter{LocalASN: asn, RouterID: testRouterID1}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// TestBMP_StreamsToStation verifies a runtime opens a session to its station
// once BGP starts, names itself with the configured sysName, reports the
// station up, and on Stop closes the session with a Termination and reports
// it down.
func TestBMP_StreamsToStation(t *testing.T) {
	col := newFakeCollector(t)
	obs := &recordingBMPObserver{}
	rt := newBMPTestRuntime(t, obs, nil, col.station())

	applyASN(t, rt, 65000)
	session := col.nextSession(t)
	if m := expectInitiation(t, session); m.sysName != bmpTestSysName {
		t.Errorf("sysName = %q, want %q", m.sysName, bmpTestSysName)
	}

	rt.bmp.sync(context.Background())
	if up, _ := obs.get(col.station().String()); !up {
		t.Error("station not reported up while its session is open")
	}

	if err := rt.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	expectTerminated(t, session)
	if up, reported := obs.get(col.station().String()); !reported || up {
		t.Errorf("after Stop: up = %v, reported = %v, want reported down", up, reported)
	}
}

// TestBMP_ReconfigureMovesStationToNewServer verifies that replacing the GoBGP
// server, here for an ASN change, terminates the old server's session and
// opens one from the new server. GoBGP does not stop a server's BMP clients
// when it stops the server, so without this the old session would stay open
// for the life of the process.
func TestBMP_ReconfigureMovesStationToNewServer(t *testing.T) {
	col := newFakeCollector(t)
	rt := newBMPTestRuntime(t, nil, nil, col.station())

	applyASN(t, rt, 65000)
	first := col.nextSession(t)
	expectInitiation(t, first)

	applyASN(t, rt, 65001)
	expectTerminated(t, first)
	second := col.nextSession(t)
	expectInitiation(t, second)

	// A further Apply with the same config must not open another session.
	applyASN(t, rt, 65001)
	col.expectNoSession(t, time.Second)
}

// TestBMP_FollowsStationAddressChange verifies that a station addressed by
// name moves to the new address when the name starts resolving elsewhere: the
// old session is terminated and one opens to the new address.
func TestBMP_FollowsStationAddressChange(t *testing.T) {
	colA := newFakeCollector(t)
	port := colA.station().Port
	// The station's port is fixed, so the second collector shares it on a
	// second loopback address.
	colB := newFakeCollectorAt(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), port).String())
	var target atomic.Pointer[fakeCollector]
	target.Store(colA)
	resolve := func(context.Context, string) (netip.Addr, error) {
		return netip.MustParseAddr(target.Load().station().Host), nil
	}
	rt := newBMPTestRuntime(t, nil, resolve, BMPStation{Host: "collector.test", Port: port})

	applyASN(t, rt, 65000)
	first := colA.nextSession(t)
	expectInitiation(t, first)

	target.Store(colB)
	rt.bmp.sync(context.Background())
	expectTerminated(t, first)
	expectInitiation(t, colB.nextSession(t))
}

// TestBMP_UnresolvableStationReportedDown verifies a station whose host does
// not resolve is reported down rather than skipped, and is registered once it
// resolves.
func TestBMP_UnresolvableStationReportedDown(t *testing.T) {
	col := newFakeCollector(t)
	obs := &recordingBMPObserver{}
	var resolvable atomic.Bool
	resolve := func(context.Context, string) (netip.Addr, error) {
		if !resolvable.Load() {
			return netip.Addr{}, errors.New("no such host")
		}
		return netip.MustParseAddr(col.station().Host), nil
	}
	st := BMPStation{Host: "collector.test", Port: col.station().Port}
	rt := newBMPTestRuntime(t, obs, resolve, st)

	applyASN(t, rt, 65000)
	rt.bmp.sync(context.Background())
	if up, reported := obs.get(st.String()); !reported || up {
		t.Errorf("unresolvable station: up = %v, reported = %v, want reported down", up, reported)
	}
	col.expectNoSession(t, time.Second)

	resolvable.Store(true)
	rt.bmp.sync(context.Background())
	expectInitiation(t, col.nextSession(t))
}

// TestBMP_NoStationsDisablesKeeper verifies the zero BMPConfig creates no
// keeper, and that a runtime without one applies and stops normally.
func TestBMP_NoStationsDisablesKeeper(t *testing.T) {
	rt := newBMPTestRuntime(t, nil, nil)
	if rt.bmp != nil {
		t.Fatal("keeper created with no stations")
	}
	applyASN(t, rt, 65000)
	if err := rt.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestParseBMPPolicy(t *testing.T) {
	tests := []struct {
		name    string
		want    api.AddBmpRequest_MonitoringPolicy
		wantErr bool
	}{
		{name: BMPPolicyPrePolicy, want: api.AddBmpRequest_MONITORING_POLICY_PRE},
		{name: BMPPolicyPostPolicy, want: api.AddBmpRequest_MONITORING_POLICY_POST},
		{name: BMPPolicyLocalRIB, want: api.AddBmpRequest_MONITORING_POLICY_LOCAL},
		{name: BMPPolicyAll, want: api.AddBmpRequest_MONITORING_POLICY_ALL},
		{name: "both", wantErr: true},
		{name: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBMPPolicy(tt.name)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("policy = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBMPSessionUp(t *testing.T) {
	// state builds a station state from its up and down times in seconds, 0
	// meaning never.
	state := func(up, down int64) *api.ListBmpResponse_BmpStation_State {
		st := &api.ListBmpResponse_BmpStation_State{}
		if up != 0 {
			st.Uptime = timestamppb.New(time.Unix(up, 0))
		}
		if down != 0 {
			st.Downtime = timestamppb.New(time.Unix(down, 0))
		}
		return st
	}
	tests := []struct {
		name string
		st   *api.ListBmpResponse_BmpStation_State
		want bool
	}{
		{name: "never connected", st: state(0, 0), want: false},
		{name: "nil state", st: nil, want: false},
		{name: "connected, never dropped", st: state(10, 0), want: true},
		{name: "dropped after connecting", st: state(10, 20), want: false},
		{name: "reconnected after dropping", st: state(30, 20), want: true},
		{name: "reconnected within the second", st: state(20, 20), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bmpSessionUp(tt.st); got != tt.want {
				t.Errorf("bmpSessionUp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBMPStationString(t *testing.T) {
	if got := (BMPStation{Host: "2001:db8::5", Port: 5000}).String(); got != "[2001:db8::5]:5000" {
		t.Errorf("IPv6 station = %q", got)
	}
	const name = "gobmp.galactic-system.svc"
	if got := (BMPStation{Host: name, Port: 5000}).String(); got != name+":5000" {
		t.Errorf("named station = %q", got)
	}
}
