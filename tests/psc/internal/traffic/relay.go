// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RelayConfig selects a producer relay or the shared responding service.
type RelayConfig struct {
	Mode, Transport, Listen, Target, StateDir string
}

// Serve handles UDP datagrams or framed TCP requests until ctx is canceled.
func Serve(ctx context.Context, cfg RelayConfig, output io.Writer) error {
	var ready sync.WaitGroup
	defer ready.Wait()
	listen := net.ListenConfig{Control: reuseAddress}
	if cfg.Transport == transportTCP {
		listener, err := listen.Listen(ctx, "tcp6", cfg.Listen)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stop()
		if _, err := fmt.Fprintf(output, "READY %s %s %s\n", cfg.Mode, cfg.Transport, listener.Addr()); err != nil {
			return err
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
			ready.Add(1)
			go func() { defer ready.Done(); serveTCP(ctx, cfg, conn) }()
		}
	}
	listener, err := listen.ListenPacket(ctx, "udp6", cfg.Listen)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	if _, err := fmt.Fprintf(output, "READY %s %s %s\n", cfg.Mode, cfg.Transport, listener.LocalAddr()); err != nil {
		return err
	}
	for {
		payload := make([]byte, maxFrameSize)
		n, peer, err := listener.ReadFrom(payload)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		received := time.Now()
		ready.Add(1)
		go func() {
			defer ready.Done()
			response, err := relayResponse(ctx, cfg, payload[:n], received)
			if err == nil {
				_, err = listener.WriteTo(response, peer)
			}
			if err != nil && ctx.Err() == nil {
				log.Printf("relay UDP: %v", err)
			}
		}()
	}
}

func serveTCP(ctx context.Context, cfg RelayConfig, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
			return
		}
		payload, err := readFrame(conn)
		if err != nil {
			return
		}
		response, err := relayResponse(ctx, cfg, payload, time.Now())
		if err != nil {
			log.Printf("relay TCP: %v", err)
			return
		}
		// Start the write deadline after any intentional response delay.
		if err := conn.SetWriteDeadline(time.Now().Add(4 * time.Second)); err != nil {
			return
		}
		if err := writeFrame(conn, response); err != nil {
			return
		}
	}
}

func relayResponse(ctx context.Context, cfg RelayConfig, payload []byte, received time.Time) ([]byte, error) {
	if cfg.Mode == modeRoot {
		host, _, err := net.SplitHostPort(cfg.Target)
		if err != nil {
			return nil, err
		}
		return json.Marshal(Reply{Destination: host, Payload: string(payload)})
	}
	response, _, err := exchange(ctx, cfg.Transport, cfg.Target, payload, &net.Dialer{Timeout: 3 * time.Second},
		3*time.Second)
	if err != nil {
		return nil, err
	}
	if err := delayResponse(ctx, cfg, received); err != nil {
		return nil, err
	}
	return response, nil
}

type delayDirective struct {
	Seconds float64 `json:"seconds"`
	Token   string  `json:"token"`
}

type delayTrace struct {
	Token              string  `json:"token"`
	Destination        string  `json:"destination"`
	Transport          string  `json:"transport"`
	RequestReceivedAt  float64 `json:"requestReceivedAt"`
	UpstreamResponseAt float64 `json:"upstreamResponseAt"`
	ReplyAttemptAt     float64 `json:"replyAttemptAt,omitempty"`
	Seconds            float64 `json:"seconds"`
}

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / float64(time.Second) }

func delayResponse(ctx context.Context, cfg RelayConfig, received time.Time) error {
	claim, err := os.CreateTemp(cfg.StateDir, "psc-delay-claim-*")
	if err != nil {
		return err
	}
	name := claim.Name()
	defer func() { _ = os.Remove(name) }()
	if err := claim.Close(); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(cfg.StateDir, "psc-delay.json"), name); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	var directive delayDirective
	if err := json.Unmarshal(raw, &directive); err != nil {
		return err
	}
	if directive.Seconds <= 0 || directive.Seconds > 30 {
		return errors.New("delay seconds must be in (0,30]")
	}
	destination, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return err
	}
	trace := delayTrace{Token: directive.Token, Destination: destination, Transport: cfg.Transport,
		RequestReceivedAt: unixSeconds(received), UpstreamResponseAt: unixSeconds(time.Now()), Seconds: directive.Seconds}
	if err := saveTrace(cfg.StateDir, trace); err != nil {
		return err
	}
	timer := time.NewTimer(time.Duration(directive.Seconds * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	trace.ReplyAttemptAt = unixSeconds(time.Now())
	return saveTrace(cfg.StateDir, trace)
}

func saveTrace(dir string, trace delayTrace) error {
	file, err := os.CreateTemp(dir, "psc-delay-trace-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if err := json.NewEncoder(file).Encode(trace); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(dir, "psc-delay-trace.json"))
}
