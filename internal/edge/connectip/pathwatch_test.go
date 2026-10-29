// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

func setBlackHoleWindow(t *testing.T, d time.Duration) {
	t.Helper()
	old := blackHoleWindow
	blackHoleWindow = d
	t.Cleanup(func() { blackHoleWindow = old })
}

func newTestWatch(t *testing.T) *pathWatch {
	t.Helper()
	w := newPathWatch(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if rec := w.AddProducer(); rec != w {
		t.Fatal("the first producer must be the watch")
	}
	return w
}

// sent records a 1-RTT packet pn carrying a DATAGRAM of datagram bytes.
func sent(w *pathWatch, pn int64, datagram int64) {
	w.RecordEvent(qlog.PacketSent{
		Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT, PacketNumber: qlog.PacketNumber(pn)},
		Frames: []qlog.Frame{{Frame: &qlog.DatagramFrame{Length: datagram}}},
	})
}

// acked records a 1-RTT ACK whose ranges are given highest first, each as
// smallest and largest.
func acked(w *pathWatch, ranges ...[2]int64) {
	rs := make([]qlog.AckRange, len(ranges))
	for i, r := range ranges {
		rs[i] = qlog.AckRange{Smallest: qlog.PacketNumber(r[0]), Largest: qlog.PacketNumber(r[1])}
	}
	w.RecordEvent(qlog.PacketReceived{
		Header: qlog.PacketHeader{PacketType: qlog.PacketType1RTT},
		Frames: []qlog.Frame{{Frame: &qlog.AckFrame{AckRanges: rs}}},
	})
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestAcknowledged(t *testing.T) {
	ranges := []qlog.AckRange{{Smallest: 9, Largest: 10}, {Smallest: 4, Largest: 6}, {Smallest: 1, Largest: 1}}
	for pn, want := range map[int64]bool{
		0: false, 1: true, 2: false, 3: false, 4: true, 6: true, 7: false, 8: false, 9: true, 10: true, 11: false,
	} {
		if got := acknowledged(ranges, pn); got != want {
			t.Errorf("acknowledged(%d) = %v, want %v", pn, got, want)
		}
	}
}

// TestPathWatchDeclaresBlackHole checks that blackHoleLosses floor packets
// lost in a row while later packets arrive, over at least blackHoleWindow,
// declare the path lost, and that a floor packet sent afterwards and
// acknowledged clears it.
func TestPathWatchDeclaresBlackHole(t *testing.T) {
	setBlackHoleWindow(t, time.Hour)
	w := newTestWatch(t)
	lost := w.pathLost()
	sent(w, 0, floorDatagramLen)
	acked(w, [2]int64{0, 0})
	for i := range int64(blackHoleLosses) {
		floor, small := 1+2*i, 2+2*i
		sent(w, floor, floorDatagramLen)
		sent(w, small, 0)
		acked(w, [2]int64{small, small}, [2]int64{0, 0})
	}
	if isClosed(lost) {
		t.Fatal("path declared lost before the run lasted blackHoleWindow")
	}
	setBlackHoleWindow(t, 0)
	sent(w, 7, 0)
	acked(w, [2]int64{7, 7}, [2]int64{0, 0})
	if !isClosed(lost) {
		t.Fatalf("path not declared lost after %d floor packets were lost", blackHoleLosses)
	}
	if !isClosed(w.pathLost()) {
		t.Fatal("a session that starts while the path is lost must see it lost")
	}

	sent(w, 8, floorDatagramLen)
	acked(w, [2]int64{8, 8})
	if isClosed(w.pathLost()) {
		t.Fatal("path still lost after a floor packet sent later was acknowledged")
	}
}

// TestPathWatchIgnoresRandomLoss checks that floor losses broken up by an
// acknowledged floor packet never declare the path lost, and that a smaller
// datagram's loss does not count.
func TestPathWatchIgnoresRandomLoss(t *testing.T) {
	setBlackHoleWindow(t, 0)
	w := newTestWatch(t)
	lost := w.pathLost()
	var pn int64
	for range 10 {
		sent(w, pn, floorDatagramLen)       // lost
		sent(w, pn+1, floorDatagramLen-1)   // lost, below the floor
		sent(w, pn+2, floorDatagramLen)     // lost
		sent(w, pn+3, floorDatagramLen+100) // arrives
		acked(w, [2]int64{pn + 3, pn + 3})
		pn += 4
	}
	if isClosed(lost) {
		t.Fatal("path declared lost although floor packets keep arriving")
	}
}

// TestPathWatchDecidesBelowLowestRange checks the ranges a receiver no
// longer reports: a floor packet above every earlier ACK's largest that the
// ACK omits never arrived, while one at or below it is left undecided, since
// only a truncated ACK frame can have omitted it.
func TestPathWatchDecidesBelowLowestRange(t *testing.T) {
	setBlackHoleWindow(t, time.Hour)
	w := newTestWatch(t)
	sent(w, 0, 0)
	acked(w, [2]int64{0, 0})
	sent(w, 1, floorDatagramLen)
	sent(w, 2, 0)
	acked(w, [2]int64{2, 2})
	if w.runLosses != 1 || len(w.outstanding) != 0 {
		t.Fatalf("run losses %d, outstanding %v; want the floor packet lost", w.runLosses, w.outstanding)
	}

	w = newTestWatch(t)
	sent(w, 0, 0)
	sent(w, 1, floorDatagramLen)
	sent(w, 2, 0)
	acked(w, [2]int64{2, 2})
	sent(w, 3, 0)
	// The previous ACK already decided packet 1, so plant an undecided one
	// at or below its largest, as a truncated frame would leave it.
	w.outstanding = append(w.outstanding, floorPacket{pn: 1})
	acked(w, [2]int64{3, 3})
	if w.runLosses != 1 || len(w.outstanding) != 0 {
		t.Fatalf("run losses %d, outstanding %v; want only the first loss and nothing outstanding",
			w.runLosses, w.outstanding)
	}
}

type recordingTrace struct {
	producers int
	events    []qlogwriter.Event
}

func (r *recordingTrace) AddProducer() qlogwriter.Recorder { r.producers++; return r }
func (r *recordingTrace) SupportsSchemas(s string) bool    { return s == "inner" }
func (r *recordingTrace) RecordEvent(ev qlogwriter.Event)  { r.events = append(r.events, ev) }
func (r *recordingTrace) Close() error                     { return nil }

// TestPathWatchForwardsToTracer checks that a configured Tracer still sees
// every event and its own schemas.
func TestPathWatchForwardsToTracer(t *testing.T) {
	inner := &recordingTrace{}
	w := newPathWatch(inner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if w.AddProducer() != w {
		t.Fatal("the first producer must be the watch")
	}
	if w.AddProducer() != inner {
		t.Fatal("later producers must be the inner trace's")
	}
	sent(w, 0, floorDatagramLen)
	if len(inner.events) != 1 || inner.producers != 2 {
		t.Fatalf("inner trace saw %d events from %d producers, want 1 from 2", len(inner.events), inner.producers)
	}
	if !w.SupportsSchemas(qlog.EventSchema) || !w.SupportsSchemas("inner") || w.SupportsSchemas("other") {
		t.Fatal("schemas must be QUIC's and the inner trace's")
	}
}
