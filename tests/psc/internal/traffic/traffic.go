// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package traffic supplies the private service fixture's query and relay tools.
package traffic

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const maxFrameSize = 65535

// Reply identifies the producer destination and the original request payload.
type Reply struct {
	Destination string `json:"destination"`
	Payload     string `json:"payload"`
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[:]))
	_, err := io.ReadFull(r, payload)
	return payload, err
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameSize {
		return errors.New("service frame exceeds 65535 bytes")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(payload)))
	_, err := io.Copy(w, io.MultiReader(bytes.NewReader(header[:]), bytes.NewReader(payload)))
	return err
}

func exchange(ctx context.Context, transport, address string, payload []byte, dialer *net.Dialer,
	timeout time.Duration,
) ([]byte, string, error) {
	conn, err := dialer.DialContext(ctx, transport+"6", address)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, "", err
	}
	var response []byte
	if transport == transportTCP {
		if err := writeFrame(conn, payload); err != nil {
			return nil, "", err
		}
		response, err = readFrame(conn)
	} else {
		if _, err := conn.Write(payload); err != nil {
			return nil, "", err
		}
		response = make([]byte, maxFrameSize)
		var n int
		n, err = conn.Read(response)
		response = response[:n]
	}
	host, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String())
	if splitErr != nil {
		return nil, "", splitErr
	}
	return response, host, err
}

// QueryConfig defines one consumer request with a fixed source and frontend.
type QueryConfig struct {
	Transport, Frontend, Source, Expected, Payload string
	Timeout                                        time.Duration
}

// Query checks that the selected producer replies through the consumer frontend.
func Query(ctx context.Context, cfg QueryConfig) (Reply, string, error) {
	var local net.Addr
	var err error
	if cfg.Transport == transportTCP {
		local, err = net.ResolveTCPAddr("tcp6", cfg.Source)
	} else {
		local, err = net.ResolveUDPAddr("udp6", cfg.Source)
	}
	if err != nil {
		return Reply{}, "", err
	}
	dialer := &net.Dialer{LocalAddr: local, Timeout: cfg.Timeout, Control: reuseAddress}
	raw, peer, err := exchange(ctx, cfg.Transport, cfg.Frontend, []byte(cfg.Payload), dialer, cfg.Timeout)
	if err != nil {
		return Reply{}, peer, err
	}
	var reply Reply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return reply, peer, err
	}
	frontend, _, err := net.SplitHostPort(cfg.Frontend)
	if err != nil {
		return reply, peer, err
	}
	if !net.ParseIP(peer).Equal(net.ParseIP(frontend)) ||
		reply.Destination != cfg.Expected || reply.Payload != cfg.Payload {
		return reply, peer, fmt.Errorf("unexpected producer reply: %+v from %s", reply, peer)
	}
	return reply, peer, nil
}
