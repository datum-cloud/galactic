// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package connectip

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

// quic-go only ever grows its packet size and ignores ICMP Packet Too Big
// (quic-go issues 3955 and 5914), so a QUIC path that shrinks after the
// handshake drops large packets without any error the server could see.
// The server therefore pins the QUIC packet size, which turns every packet
// too large for it into a Packet Too Big, and watches each connection's
// acknowledgements for the case the pin cannot cover: a path that stops
// carrying packets of MinInnerMTU while later packets still arrive. That is
// the black hole of RFC 8899 section 4.3, which RFC 9484 section 10.1 asks a
// proxy to answer by ending the tunnel.
//
// The watch reads losses from the client's ACK frames rather than from
// quic-go's loss events: quic-go declares a tail packet lost on a probe
// timeout without reporting it, and with sparse traffic every loss is a
// tail loss. A packet is only decided by a later packet's acknowledgement.
// When the client receives nothing it must acknowledge, it sends no ACK,
// and quic-go's probe timeout restarts with every packet sent, so steady
// traffic toward a black hole could go undecided. The watch therefore sends
// its own small packets while a floor packet waits too long. On a path whose
// round trip exceeds pathProbeInterval that is one small packet per interval
// while floor packets flow.

const (
	// floorDatagramLen is the smallest DATAGRAM frame that carries a
	// MinInnerMTU packet: a quarter stream ID and a context ID of at least
	// one byte each precede the packet.
	floorDatagramLen = MinInnerMTU + 2
	// blackHoleLosses is how many floor-sized packets in a row must be lost
	// before a path counts as a black hole; MAX_PROBES in RFC 8899.
	blackHoleLosses = 3
	// maxOutstanding caps the floor-sized packets a watch waits on; the
	// oldest is forgotten beyond it.
	maxOutstanding = 4096
)

var (
	// blackHoleWindow is the shortest run of floor-sized losses, with no
	// floor-sized packet acknowledged meanwhile, that counts as a black
	// hole. Random loss cannot sustain such a run.
	blackHoleWindow = time.Second
	// pathProbeInterval spaces the probes a watch sends while it suspects a
	// black hole, and the probes of an admission.
	pathProbeInterval = 200 * time.Millisecond
	// pathProbeTimeout bounds how long admission waits for the path to
	// acknowledge or lose its probes.
	pathProbeTimeout = 3 * time.Second
)

var errPathMTU = errors.New("path toward the client does not carry the minimum inner MTU")

// pathWatch is the qlog trace the server installs on each QUIC connection.
// It records which 1-RTT packets carried floor-sized datagrams, then reads
// from each ACK frame whether they arrived. It forwards
// every event to the trace of a configured Tracer, if there is one.
type pathWatch struct {
	inner     qlogwriter.Trace
	innerRec  qlogwriter.Recorder
	producers atomic.Int32
	log       *slog.Logger

	mu   sync.Mutex
	conn *quic.Conn
	// stream is the quarter stream ID detection probes are sent on.
	stream   uint64
	lastSent int64
	// outstanding are the floor-sized packets sent and not yet decided,
	// oldest first.
	outstanding []floorPacket
	floorAcked  int64
	// ackedMax is the largest packet number any ACK acknowledged.
	ackedMax int64
	// lostFloor holds the most recently lost floor packets, newest last.
	lostFloor [blackHoleLosses]int64
	// runFirst is the first floor packet lost since a floor packet was last
	// acknowledged, or -1; runSince is when its loss was detected, and
	// runLosses counts the run.
	runFirst  int64
	runSince  time.Time
	runLosses int
	// declared is the last packet sent when the path was declared a black
	// hole, or -1. A floor packet sent later and acknowledged clears it.
	declared int64
	// lost is closed when the path is declared a black hole.
	lost chan struct{}
	// changed is closed and replaced whenever a floor packet's fate is known.
	changed chan struct{}
	// ptoPending is set while quic-go's probe timeout count is above zero.
	ptoPending bool
	probing    bool
}

// floorPacket is an undecided floor-sized packet and when it was sent.
type floorPacket struct {
	pn int64
	at time.Time
}

var (
	_ qlogwriter.Trace    = (*pathWatch)(nil)
	_ qlogwriter.Recorder = (*pathWatch)(nil)
)

func newPathWatch(inner qlogwriter.Trace, log *slog.Logger) *pathWatch {
	w := &pathWatch{
		inner:      inner,
		log:        log,
		lastSent:   -1,
		floorAcked: -1,
		ackedMax:   -1,
		runFirst:   -1,
		declared:   -1,
		lost:       make(chan struct{}),
		changed:    make(chan struct{}),
	}
	for i := range w.lostFloor {
		w.lostFloor[i] = -1
	}
	return w
}

// AddProducer returns the watch itself to the QUIC connection, which adds
// the first producer. Later producers, such as HTTP/3's, go to the inner
// trace only.
func (w *pathWatch) AddProducer() qlogwriter.Recorder {
	if w.producers.Add(1) == 1 {
		if w.inner != nil {
			w.innerRec = w.inner.AddProducer()
		}
		return w
	}
	if w.inner != nil {
		return w.inner.AddProducer()
	}
	return nopRecorder{}
}

// SupportsSchemas accepts the QUIC event schema, and whatever the inner
// trace accepts.
func (w *pathWatch) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema || (w.inner != nil && w.inner.SupportsSchemas(schema))
}

// RecordEvent is called on the connection's run loop for every event.
func (w *pathWatch) RecordEvent(ev qlogwriter.Event) {
	switch e := ev.(type) {
	case qlog.PacketSent:
		w.onSent(e)
	case qlog.PacketReceived:
		w.onReceived(e)
	case qlog.PTOCountUpdated:
		w.onPTO(e.PTOCount)
	}
	if w.innerRec != nil {
		w.innerRec.RecordEvent(ev)
	}
}

func (w *pathWatch) Close() error {
	if w.innerRec != nil {
		return w.innerRec.Close()
	}
	return nil
}

// isFloor reports whether a sent packet carries a DATAGRAM frame of at
// least floorDatagramLen.
func isFloor(e qlog.PacketSent) bool {
	for _, f := range e.Frames {
		if d, ok := f.Frame.(*qlog.DatagramFrame); ok && d.Length >= floorDatagramLen {
			return true
		}
	}
	return false
}

func (w *pathWatch) onSent(e qlog.PacketSent) {
	if e.Header.PacketType != qlog.PacketType1RTT {
		return
	}
	pn := int64(e.Header.PacketNumber)
	if !isFloor(e) {
		w.mu.Lock()
		w.lastSent = pn
		w.mu.Unlock()
		return
	}
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastSent = pn
	if len(w.outstanding) >= maxOutstanding {
		w.outstanding = w.outstanding[1:]
	}
	w.outstanding = append(w.outstanding, floorPacket{pn: pn, at: now})
	if w.waiting(now) {
		w.startProbing()
	}
}

func (w *pathWatch) onReceived(e qlog.PacketReceived) {
	if e.Header.PacketType != qlog.PacketType1RTT {
		return
	}
	for _, f := range e.Frames {
		if ack, ok := f.Frame.(*qlog.AckFrame); ok && len(ack.AckRanges) > 0 {
			w.onAck(ack.AckRanges)
		}
	}
}

// onAck decides every outstanding floor packet below the ACK's largest
// packet: acknowledged when a range holds it, lost otherwise. A receiver
// stops reporting only ranges it already reported in an ACK the sender
// processed, so a packet above every earlier ACK's largest that no range
// holds never arrived. One at or below it is forgotten undecided; it can only
// be outstanding there if an ACK frame was truncated. A packet that arrives
// reordered after a later one was acknowledged counts as lost, which can
// only delay a decision, since its acknowledgement clears the run.
func (w *pathWatch) onAck(ranges []qlog.AckRange) {
	largest := int64(ranges[0].Largest)
	lowest := int64(ranges[len(ranges)-1].Smallest)
	w.mu.Lock()
	defer w.mu.Unlock()
	var decided int
	var floorAcked, lost bool
	now := time.Now()
	for _, f := range w.outstanding {
		pn := f.pn
		if pn >= largest {
			break
		}
		decided++
		switch {
		case pn < lowest && pn <= w.ackedMax:
		case acknowledged(ranges, pn):
			if pn > w.floorAcked {
				w.floorAcked = pn
				floorAcked = true
			}
		default:
			w.lose(pn, now)
			lost = true
		}
	}
	// The largest packet is acknowledged by definition.
	if decided < len(w.outstanding) && w.outstanding[decided].pn == largest {
		decided++
		if largest > w.floorAcked {
			w.floorAcked = largest
			floorAcked = true
		}
	}
	w.outstanding = append(w.outstanding[:0], w.outstanding[decided:]...)
	w.ackedMax = max(w.ackedMax, largest)
	if floorAcked {
		if w.runFirst >= 0 && w.floorAcked > w.runFirst {
			w.runFirst, w.runLosses = -1, 0
		}
		if w.declared >= 0 && w.floorAcked > w.declared {
			w.declared = -1
			w.lost = make(chan struct{})
			w.log.Info("QUIC path carries the minimum inner MTU again")
		}
	}
	w.check(now)
	if floorAcked || lost {
		w.notifyLocked()
	}
}

// acknowledged reports whether ranges, sorted from the highest packet
// number down, hold pn.
func acknowledged(ranges []qlog.AckRange, pn int64) bool {
	// The first range starting at or below pn is the only one that can
	// hold it.
	i, _ := slices.BinarySearchFunc(ranges, pn, func(r qlog.AckRange, pn int64) int {
		return cmp.Compare(pn, int64(r.Smallest))
	})
	return i < len(ranges) && pn <= int64(ranges[i].Largest)
}

// lose records the loss of floor packet pn.
func (w *pathWatch) lose(pn int64, now time.Time) {
	if pn < w.floorAcked {
		return
	}
	copy(w.lostFloor[:], w.lostFloor[1:])
	w.lostFloor[len(w.lostFloor)-1] = pn
	if w.runFirst >= 0 {
		w.runLosses++
		return
	}
	w.runFirst, w.runSince, w.runLosses = pn, now, 1
	w.startProbing()
}

// onPTO starts probing when a probe timeout fires while floor packets are
// undecided.
func (w *pathWatch) onPTO(count uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ptoPending = count > 0
	if w.ptoPending && len(w.outstanding) > 0 {
		w.startProbing()
	}
}

// waiting reports whether the oldest undecided floor packet was sent at
// least pathProbeInterval before now.
func (w *pathWatch) waiting(now time.Time) bool {
	return len(w.outstanding) > 0 && now.Sub(w.outstanding[0].at) >= pathProbeInterval
}

func (w *pathWatch) startProbing() {
	if !w.probing && w.conn != nil && w.declared < 0 {
		w.probing = true
		go w.probeLoop()
	}
}

// check declares the path a black hole once a run of floor losses is long
// enough while small packets still arrive.
func (w *pathWatch) check(now time.Time) {
	if w.declared >= 0 || w.runFirst < 0 || w.runLosses < blackHoleLosses ||
		now.Sub(w.runSince) < blackHoleWindow {
		return
	}
	w.declared = w.lastSent
	w.runFirst, w.runLosses = -1, 0
	close(w.lost)
	w.log.Warn("QUIC path stopped carrying the minimum inner MTU", "minimum", MinInnerMTU)
}

func (w *pathWatch) notifyLocked() {
	close(w.changed)
	w.changed = make(chan struct{})
}

// attach binds the watch to its connection once HTTP/3 serves it.
func (w *pathWatch) attach(c *quic.Conn) {
	w.mu.Lock()
	w.conn = c
	w.mu.Unlock()
}

// useStream makes detection probes travel on the request stream id.
func (w *pathWatch) useStream(id quic.StreamID) {
	w.mu.Lock()
	w.stream = uint64(id / 4)
	w.mu.Unlock()
}

// pathLost returns a channel closed once the path is declared a black hole.
// A channel taken after the path recovered stays open until the next one.
func (w *pathWatch) pathLost() <-chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.lost
}

// probeLoop runs until the path is declared lost, or until no run of floor
// losses is open, no probe timeout is pending and no floor packet waits
// longer than pathProbeInterval. Every pathProbeInterval it
// sends a small probe, a later packet whose acknowledgement decides the
// floor packets before it, preceded during a run by a floor-sized probe, so
// a run is decided even when the tunnel carries nothing else.
func (w *pathWatch) probeLoop() {
	t := time.NewTicker(pathProbeInterval)
	defer t.Stop()
	for {
		w.mu.Lock()
		now := time.Now()
		if w.declared >= 0 || (w.runFirst < 0 && !w.ptoPending && !w.waiting(now)) {
			w.probing = false
			w.mu.Unlock()
			return
		}
		w.check(now)
		inRun := w.runFirst >= 0
		conn, stream := w.conn, w.stream
		w.mu.Unlock()
		if inRun {
			_ = sendProbe(conn, stream, MinInnerMTU)
		}
		_ = sendProbe(conn, stream, 0)
		select {
		case <-t.C:
		case <-conn.Context().Done():
			w.mu.Lock()
			w.probing = false
			w.mu.Unlock()
			return
		}
	}
}

// confirm checks that the path carries a MinInnerMTU packet toward the
// client: it sends up to blackHoleLosses floor-sized probes on the request
// stream id, one per pathProbeInterval, each followed by a small one whose
// acknowledgement decides it, and returns nil once a floor-sized packet sent
// after it began is acknowledged. It fails when that many are lost first,
// or after pathProbeTimeout.
func (w *pathWatch) confirm(ctx context.Context, id quic.StreamID) error {
	w.mu.Lock()
	mark, conn := w.lastSent, w.conn
	w.mu.Unlock()
	if conn == nil {
		return errors.New("request has no QUIC connection")
	}
	stream := uint64(id / 4)
	probe := func() error {
		if err := sendProbe(conn, stream, MinInnerMTU); err != nil {
			return err
		}
		return sendProbe(conn, stream, 0)
	}
	if err := probe(); err != nil {
		return err
	}
	sent := 1
	tick := time.NewTicker(pathProbeInterval)
	defer tick.Stop()
	deadline := time.NewTimer(pathProbeTimeout)
	defer deadline.Stop()
	for {
		w.mu.Lock()
		acked := w.floorAcked > mark
		var lost int
		for _, pn := range w.lostFloor {
			if pn > mark {
				lost++
			}
		}
		changed := w.changed
		w.mu.Unlock()
		switch {
		case acked:
			return nil
		case lost >= blackHoleLosses:
			return fmt.Errorf("%w: %d probes lost", errPathMTU, lost)
		}
		select {
		case <-changed:
		case <-tick.C:
			if sent < blackHoleLosses {
				if err := probe(); err != nil {
					return err
				}
				sent++
			}
		case <-deadline.C:
			return fmt.Errorf("%w: no probe acknowledged within %v", errPathMTU, pathProbeTimeout)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// sendProbe sends the client a datagram on quarter stream ID stream in
// probeContextID, which is never registered, so the client acknowledges
// the packet and drops the datagram. size zero bytes follow the context ID,
// so a probe of MinInnerMTU is as large as a MinInnerMTU packet.
func sendProbe(conn *quic.Conn, stream uint64, size int) error {
	probe := quicvarint.Append(nil, stream)
	probe = quicvarint.Append(probe, probeContextID)
	probe = append(probe, make([]byte, size)...)
	if err := conn.SendDatagram(probe); err != nil {
		if tooLarge, ok := errors.AsType[*quic.DatagramTooLargeError](err); ok {
			return fmt.Errorf("datagram of %d bytes exceeds the current maximum of %d bytes",
				len(probe), tooLarge.MaxDatagramPayloadSize)
		}
		return fmt.Errorf("could not send MTU probe: %w", err)
	}
	return nil
}

type nopRecorder struct{}

func (nopRecorder) RecordEvent(qlogwriter.Event) {}
func (nopRecorder) Close() error                 { return nil }
