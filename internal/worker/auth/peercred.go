// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// PeerInfo is the AuthInfo of a connection on Worker's unix socket: the
// kernel's record of the connecting process (SO_PEERCRED).
type PeerInfo struct {
	credentials.CommonAuthInfo
	PID int32
	UID uint32
	GID uint32
}

// AuthType implements credentials.AuthInfo.
func (PeerInfo) AuthType() string { return "peercred" }

// PeerCredentials are server transport credentials for a unix socket. They
// secure nothing on the wire, which never leaves the host, and record the
// peer's credentials for each connection.
type PeerCredentials struct{}

var errNotUnix = errors.New("auth: peer credentials need a unix socket connection")

// ServerHandshake reads SO_PEERCRED from the accepted connection.
func (PeerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errNotUnix
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("auth: peer credentials: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, nil, fmt.Errorf("auth: peer credentials: %w", err)
	}
	if credErr != nil {
		return nil, nil, fmt.Errorf("auth: SO_PEERCRED: %w", credErr)
	}
	return conn, PeerInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		PID:            cred.Pid, UID: cred.Uid, GID: cred.Gid,
	}, nil
}

// ClientHandshake is not supported: these credentials are for the server.
func (PeerCredentials) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("auth: peer credentials are server-side only")
}

// Info implements credentials.TransportCredentials.
func (PeerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

// Clone implements credentials.TransportCredentials.
func (PeerCredentials) Clone() credentials.TransportCredentials { return PeerCredentials{} }

// OverrideServerName implements credentials.TransportCredentials.
//
//nolint:staticcheck // Required by the interface.
func (PeerCredentials) OverrideServerName(string) error { return nil }

// PeerFromContext returns the peer credentials of the call's connection.
func PeerFromContext(ctx context.Context) (PeerInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return PeerInfo{}, false
	}
	info, ok := p.AuthInfo.(PeerInfo)
	return info, ok
}

// PodResolver maps a process to the UID of the pod it runs in.
type PodResolver interface {
	PodUID(pid int32) (string, error)
}

// CgroupPodResolver finds a process's pod from its cgroup path, which the
// kubelet names after the pod UID under both cgroup drivers. Worker must share
// the host PID namespace and read the host's /proc: in any other PID
// namespace SO_PEERCRED reports PID 0 for a peer in another pod.
type CgroupPodResolver struct {
	// ProcRoot is the proc mount, "/proc" when empty.
	ProcRoot string
}

// podUID matches the pod segment of a kubelet cgroup path: "pod<uid>" with
// the cgroupfs driver and "pod<uid with _>.slice" with the systemd driver.
var podUID = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)

// PodUID implements PodResolver.
func (r CgroupPodResolver) PodUID(pid int32) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("auth: peer PID %d is not visible; Worker needs the host PID namespace", pid)
	}
	root := r.ProcRoot
	if root == "" {
		root = "/proc"
	}
	b, err := os.ReadFile(fmt.Sprintf("%s/%d/cgroup", root, pid))
	if err != nil {
		return "", fmt.Errorf("auth: read cgroup of PID %d: %w", pid, err)
	}
	return PodUIDFromCgroup(string(b))
}

// PodUIDFromCgroup returns the pod UID named in a /proc/<pid>/cgroup file.
func PodUIDFromCgroup(cgroup string) (string, error) {
	uid := ""
	for line := range strings.SplitSeq(cgroup, "\n") {
		m := podUID.FindAllStringSubmatch(line, -1)
		if len(m) == 0 {
			continue
		}
		found := strings.ReplaceAll(m[len(m)-1][1], "_", "-")
		if uid != "" && uid != found {
			return "", fmt.Errorf("auth: cgroup names two pods, %s and %s", uid, found)
		}
		uid = found
	}
	if uid == "" {
		return "", errors.New("auth: process is not in a pod cgroup")
	}
	return uid, nil
}
