// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package frr reads FRR state for fabric-api over the daemons' vty sockets:
// a client for the socket protocol, a closed builder for the only commands
// fabric-api may send, a version gate, and typed parsers for their JSON.
//
// It never runs vtysh or a shell. A vty socket accepts any command its
// caller's privilege allows, so the command builder, not the socket, is what
// keeps fabric-api read-only; see command.go.
package frr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
)

// Daemon names an FRR daemon whose vty socket fabric-api reads.
type Daemon string

// Daemons fabric-api talks to.
const (
	DaemonBGP   Daemon = "bgpd"
	DaemonZebra Daemon = "zebra"
)

// FRR's per-command return codes, the byte after the three-NUL terminator.
const (
	cmdSuccess = 0
	cmdWarning = 1
)

// terminatorLen is the length of the end-of-output marker: three NUL bytes and
// the command's return code.
const terminatorLen = 4

// ErrorCode classifies a failure reading FRR.
type ErrorCode string

// FRR error codes, mapped onto the public diagnostic error codes.
const (
	// CodeUnavailable means the daemon's socket could not be reached.
	CodeUnavailable ErrorCode = "FRRUnavailable"
	// CodeCommandFailed means FRR rejected or failed the command.
	CodeCommandFailed ErrorCode = "CommandFailed"
	// CodeResponseTooLarge means the response exceeded the read cap.
	CodeResponseTooLarge ErrorCode = "ResponseTooLarge"
	// CodeMalformed means the response was incomplete or not the expected
	// JSON.
	CodeMalformed ErrorCode = "MalformedResponse"
	// CodeTimeout means the deadline passed before the response completed.
	CodeTimeout ErrorCode = "Timeout"
	// CodeVersionUnsupported means the running FRR is not a version the
	// parsers have fixtures for.
	CodeVersionUnsupported ErrorCode = "FRRVersionUnsupported"
)

// Error is a failure reading FRR, with a typed code.
type Error struct {
	Code    ErrorCode
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// CodeOf returns err's FRR error code, or "" if it carries none.
func CodeOf(err error) ErrorCode {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	return ""
}

// VTY sends commands to FRR daemons over their vty sockets. It dials a new
// connection per command, so a daemon restart costs one failed command and
// nothing else. The zero value is not usable; set SocketDir.
type VTY struct {
	// SocketDir holds the daemons' <daemon>.vty sockets, /run/frr in the
	// fabric-router pod.
	SocketDir string
	// MaxResponseBytes caps one response, terminator included. Zero selects
	// DefaultMaxResponseBytes.
	MaxResponseBytes int
	// DialTimeout bounds connecting to a socket. Zero selects 2s.
	DialTimeout time.Duration
}

// DefaultMaxResponseBytes is the read cap when VTY.MaxResponseBytes is zero.
const DefaultMaxResponseBytes = 4 << 20

// Response is one command's output.
type Response struct {
	// Output is the text before the terminator.
	Output []byte
	// Warning is true when FRR returned CMD_WARNING, which zebra uses for an
	// empty route lookup while still printing valid JSON.
	Warning bool
}

// Run sends cmd to its daemon and returns the output. The context's deadline
// bounds the whole exchange. A response over the read cap closes the
// connection and returns CodeResponseTooLarge without any partial output.
func (v *VTY) Run(ctx context.Context, cmd Command) (Response, error) {
	if cmd.text == "" {
		return Response{}, &Error{Code: CodeCommandFailed, Message: "empty command"}
	}
	dialTimeout := v.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 2 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	path := filepath.Join(v.SocketDir, string(cmd.daemon)+".vty")
	conn, err := (&net.Dialer{}).DialContext(dctx, "unix", path)
	if err != nil {
		if ctx.Err() != nil {
			return Response{}, &Error{Code: CodeTimeout, Message: "dial " + string(cmd.daemon), Err: ctx.Err()}
		}
		return Response{}, &Error{Code: CodeUnavailable, Message: "dial " + string(cmd.daemon), Err: err}
	}
	defer func() { _ = conn.Close() }()

	// Close the connection when ctx ends so a blocked read returns at once.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	if _, err := conn.Write(append([]byte(cmd.text), 0)); err != nil {
		return Response{}, v.ioError(ctx, cmd, "write", err)
	}
	return v.read(ctx, cmd, conn)
}

// read reads until the terminator, enforcing the read cap.
func (v *VTY) read(ctx context.Context, cmd Command, r io.Reader) (Response, error) {
	limit := v.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	var buf bytes.Buffer
	chunk := make([]byte, 64<<10)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if buf.Len()+n > limit {
				return Response{}, &Error{Code: CodeResponseTooLarge,
					Message: fmt.Sprintf("%s: response exceeds %d bytes", cmd, limit)}
			}
			buf.Write(chunk[:n])
			if out, ret, ok := terminated(buf.Bytes()); ok {
				return result(cmd, out, ret)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return Response{}, &Error{Code: CodeMalformed,
					Message: fmt.Sprintf("%s: connection closed after %d bytes without a terminator", cmd, buf.Len())}
			}
			return Response{}, v.ioError(ctx, cmd, "read", err)
		}
	}
}

func (v *VTY) ioError(ctx context.Context, cmd Command, op string, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return &Error{Code: CodeTimeout, Message: fmt.Sprintf("%s %s", op, cmd), Err: err}
	}
	return &Error{Code: CodeUnavailable, Message: fmt.Sprintf("%s %s", op, cmd), Err: err}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// terminated reports whether b ends with the three-NUL terminator and return
// code, returning the output before it.
func terminated(b []byte) (out []byte, ret byte, ok bool) {
	if len(b) < terminatorLen {
		return nil, 0, false
	}
	tail := b[len(b)-terminatorLen:]
	if tail[0] != 0 || tail[1] != 0 || tail[2] != 0 {
		return nil, 0, false
	}
	return b[:len(b)-terminatorLen], tail[3], true
}

// result maps FRR's return code onto a Response or an Error. A warning is
// returned as data; the parser decides whether its output is usable.
func result(cmd Command, out []byte, ret byte) (Response, error) {
	switch ret {
	case cmdSuccess:
		return Response{Output: out}, nil
	case cmdWarning:
		return Response{Output: out, Warning: true}, nil
	default:
		msg := bytes.TrimSpace(out)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return Response{}, &Error{Code: CodeCommandFailed,
			Message: fmt.Sprintf("%s: FRR returned code %d: %s", cmd, ret, msg)}
	}
}
