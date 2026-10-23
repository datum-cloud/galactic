// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/hostattach"
	"go.datum.net/galactic/internal/plumbing/intf"
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// handleLen is the length of the per-attachment handle in link names: the
// host link name is E, nine characters of VPC and the handle, the 15
// characters a Linux interface name allows.
const handleLen = 5

// Pod-local routing tables of attachment VRFs come from
// [podTableBase, podTableBase+podTableSpan), clear of the kernel's reserved
// tables and of the small IDs a pod's own VRFs usually take.
const (
	podTableBase = 0x10000000
	podTableSpan = 0x01000000
)

// handle derives a short base62 handle and a pod table from the UID.
func handle(uid string) (string, uint32) {
	sum := sha256.Sum256([]byte(uid))
	n := binary.BigEndian.Uint64(sum[:8])
	var b strings.Builder
	for range handleLen {
		b.WriteByte(base62[n%62])
		n /= 62
	}
	return b.String(), podTableBase + binary.BigEndian.Uint32(sum[8:12])%podTableSpan
}

// desired builds the host state of an admitted, allocated attachment. The
// host link's name stays outside the CNI's G…H pattern, so datapath repair
// never takes it for a workload's.
func desired(att *galacticv1alpha1.EdgeAttachment, mtu int) (hostattach.Attachment, error) {
	addr, err := netip.ParseAddr(att.Status.Address)
	if err != nil {
		return hostattach.Attachment{}, fmt.Errorf("address %q: %w", att.Status.Address, err)
	}
	h, table := handle(string(att.UID))
	a := hostattach.Attachment{
		ID:       hostattach.LinkID(att.Status.VPC, string(att.UID)),
		HostVRF:  intf.GenerateInterfaceNameVRF(att.Status.VPC),
		HostLink: fmt.Sprintf("E%09s%s", att.Status.VPC, h),
		PodVRF:   "gv" + h,
		PodTable: table,
		PodLink:  "ge" + h,
		MTU:      mtu,
		Address:  addr,
	}
	if d := att.Spec.PacketDevice; d != nil {
		a.TUN = &hostattach.TUN{Name: "gt" + h, Owner: uint32(d.Owner), Group: uint32(d.Group)}
	}
	return a, nil
}

// NewOwner returns the ownership ID of a galactic-edge process on node that
// started at start, with random distinguishing processes started together.
func NewOwner(node string, start time.Time, random string) string {
	return fmt.Sprintf("%s%s/%020d.%s", ownerPrefix, node, start.UnixNano(), random)
}

// olderIncarnation reports whether owner is a galactic-edge process that
// started before self, so self may fence it. An owner of another writer, or
// a galactic-edge ID that cannot be ordered, is never taken over.
func olderIncarnation(owner, self string) bool {
	o, ok1 := incarnation(owner)
	s, ok2 := incarnation(self)
	return ok1 && ok2 && o < s
}

// incarnation returns the start-time-ordered part of an owner ID, which
// compares as a string because NewOwner zero-pads it.
func incarnation(owner string) (string, bool) {
	rest, ok := strings.CutPrefix(owner, ownerPrefix)
	if !ok {
		return "", false
	}
	i := strings.LastIndexByte(rest, '/')
	if i < 0 || len(rest)-i-1 < 20 {
		return "", false
	}
	return rest[i+1:], true
}
