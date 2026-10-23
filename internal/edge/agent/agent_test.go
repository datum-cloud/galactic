// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/ownership"
)

const (
	addr     = "fd00:aa::1"
	pod1UID  = "11111111-0000-0000-0000-000000000001"
	pod2UID  = "11111111-0000-0000-0000-000000000002"
	attA     = "22222222-0000-0000-0000-00000000000a"
	attB     = "22222222-0000-0000-0000-00000000000b"
	attP     = "22222222-0000-0000-0000-00000000000c"
	attAgain = "22222222-0000-0000-0000-00000000000d"
)

// routeVia returns the host-table route to dst in table, and the link it
// leaves through.
func (f *fixture) routeVia(table uint32, dst string) int {
	f.t.Helper()
	var index int
	in(f.t, f.host, func() error {
		routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: int(table)},
			netlink.RT_FILTER_TABLE)
		if err != nil {
			return err
		}
		for _, r := range routes {
			if r.Dst != nil && r.Dst.IP.Equal(net.ParseIP(dst)) {
				index = r.LinkIndex
			}
		}
		return nil
	})
	return index
}

// TestAttachDetach programs overlapping tenants, one pod holding both, then
// releases them. Each VPC's host table routes the shared address only to its
// own attachment, and each host link is registered under its own VPC's table.
func TestAttachDetach(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	f.pod(pod2UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	f.attach("b", attB, pod1UID, vpcB, addr, false)
	f.attach("p", attP, pod2UID, vpcA, "fd00:aa::2", true)
	f.reconcile(a)

	for name, vpc := range map[string]string{"a": vpcA, "b": vpcB, "p": vpcA} {
		f.programmed(name)
		link := f.hostLink(name)
		if got, ok := f.dp.table(link.Attrs().Index); !ok || got != vrfTables[vpc] {
			t.Errorf("%s registered under table %d (%t), want %d", name, got, ok, vrfTables[vpc])
		}
	}
	if s := f.get("p").Status; s.PacketDevice == "" || f.get("a").Status.PacketDevice != "" {
		t.Errorf("packet devices: p %q, a %q", s.PacketDevice, f.get("a").Status.PacketDevice)
	}
	if f.get("a").Status.PodVRF == f.get("b").Status.PodVRF {
		t.Error("two attachments in one pod share a pod VRF")
	}
	linkA, linkB := f.hostLink("a").Attrs().Index, f.hostLink("b").Attrs().Index
	if got := f.routeVia(vrfTables[vpcA], addr); got != linkA {
		t.Errorf("VPC A routes %s via ifindex %d, want its own attachment %d", addr, got, linkA)
	}
	if got := f.routeVia(vrfTables[vpcB], addr); got != linkB {
		t.Errorf("VPC B routes %s via ifindex %d, want its own attachment %d", addr, got, linkB)
	}

	// Repeated passes change nothing: no link is recreated, no status is
	// rewritten.
	rv := map[string]string{}
	for _, n := range []string{"a", "b", "p"} {
		rv[n] = f.get(n).ResourceVersion
	}
	for range 3 {
		f.reconcile(a)
	}
	for _, n := range []string{"a", "b", "p"} {
		if got := f.get(n).ResourceVersion; got != rv[n] {
			t.Errorf("%s status rewritten by an unchanged pass", n)
		}
	}
	if got := f.hostLink("a").Attrs().Index; got != linkA {
		t.Errorf("a's host link recreated: %d -> %d", linkA, got)
	}

	// Detach: deleting releases the host state and the datapath rows of
	// exactly the deleted attachments.
	ctx := context.Background()
	for _, n := range []string{"a", "p"} {
		if err := f.client.Delete(ctx, f.get(n)); err != nil {
			t.Fatal(err)
		}
	}
	f.reconcile(a)
	for _, n := range []string{"a", "p"} {
		if c := f.condition(n, galacticv1alpha1.EdgeAttachmentReleased); c == nil || c.Status != metav1.ConditionTrue {
			t.Errorf("%s not released: %+v", n, c)
		}
	}
	if l := f.links(); len(l) != 1 || l[0].HostIndex != linkB {
		t.Fatalf("links after detach %+v, want only b's", l)
	}
	if slices.Contains(f.dp.unregistered, uint32(linkB)) {
		t.Error("b's datapath rows removed")
	}
	if _, ok := f.dp.table(linkA); ok {
		t.Error("a's datapath rows left behind")
	}
}

// TestRestartAndFencing restarts the agent with live attachments: the new
// process takes the scopes over and keeps every link, and the old process,
// fenced, can no longer write.
func TestRestartAndFencing(t *testing.T) {
	f := newFixture(t)
	old := f.agent()
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	f.reconcile(old)
	index := f.hostLink("a").Attrs().Index

	restarted := f.agent()
	f.reconcile(restarted)
	if got := f.hostLink("a").Attrs().Index; got != index {
		t.Errorf("restart recreated the host link: %d -> %d", index, got)
	}
	f.programmed("a")

	// The old process's pass, delayed past the restart, is refused before it
	// touches the node.
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}
	if err := old.Reconcile(context.Background()); !errors.Is(err, ownership.ErrStale) &&
		!errors.Is(err, ownership.ErrNotOwner) {
		t.Fatalf("fenced process's pass = %v, want a stale ticket", err)
	}
	if len(f.links()) != 1 {
		t.Fatal("fenced process changed the node")
	}
	f.reconcile(restarted)
	if len(f.links()) != 0 {
		t.Fatal("current process did not release")
	}
	if old.Healthy(nil) == nil {
		t.Error("a fenced process reports healthy")
	}
	if restarted.Healthy(nil) != nil {
		t.Error("the current process reports unhealthy")
	}
}

// TestPartialProvisionRecovers leaves a provision half done, as a crash or a
// failed step would, and checks the next pass finishes it and that a link
// left by an attachment that is gone altogether is released.
func TestPartialProvisionRecovers(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	podPath := f.pod(pod1UID)
	att := f.attach("p", attP, pod1UID, vpcA, addr, true)
	spec, err := desired(att, mtu)
	if err != nil {
		t.Fatal(err)
	}
	// A foreign device holds the TUN's name, so provisioning fails after the
	// host link exists.
	in(t, podPath, func() error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: spec.TUN.Name}})
	})
	f.reconcile(a)
	if c := f.condition("p", galacticv1alpha1.EdgeAttachmentProgrammed); c == nil || c.Status != metav1.ConditionFalse ||
		c.Reason != ReasonProvisionFailed {
		t.Fatalf("failed provision reported %+v", c)
	}
	if l := f.links(); len(l) != 1 {
		t.Fatalf("partial link not left discoverable: %+v", l)
	}
	in(t, podPath, func() error {
		l, err := netlink.LinkByName(spec.TUN.Name)
		if err != nil {
			return err
		}
		return netlink.LinkDel(l)
	})
	f.reconcile(a)
	f.programmed("p")

	// The attachment disappears without a release, as when its object was
	// removed by hand: the stamped link is still released.
	obj := f.get("p")
	obj.Finalizers = nil
	if err := f.client.Update(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	if err := f.client.Delete(context.Background(), obj); err != nil {
		t.Fatal(err)
	}
	f.reconcile(a)
	if l := f.links(); len(l) != 0 {
		t.Fatalf("orphaned link not released: %+v", l)
	}
}

// TestNamespaceReplacement replaces a pod's sandbox: the attachment moves to
// the new namespace. A pod with no sandbox fails closed.
func TestNamespaceReplacement(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	f.reconcile(a)
	old := f.hostLink("a").Attrs().Index

	f.pods.set(pod1UID, "")
	f.reconcile(a)
	if c := f.condition("a", galacticv1alpha1.EdgeAttachmentProgrammed); c.Status != metav1.ConditionFalse ||
		c.Reason != ReasonNamespaceUnavailable {
		t.Fatalf("pod without sandbox reported %+v", c)
	}

	f.pod(pod1UID)
	f.reconcile(a)
	f.programmed("a")
	if got := f.hostLink("a").Attrs().Index; got == old {
		t.Error("attachment still on the replaced sandbox's link")
	}
	if l := f.links(); len(l) != 1 {
		t.Fatalf("links after replacement %+v", l)
	}

	// Missing tenant state: no canonical VRF for the VPC on this node.
	f.attach("orphan", attB, pod1UID, "00000000c", "fd00:aa::3", false)
	f.reconcile(a)
	if c := f.condition("orphan", galacticv1alpha1.EdgeAttachmentProgrammed); c.Status != metav1.ConditionFalse {
		t.Fatalf("attachment without a host VRF reported %+v", c)
	}
	if l := f.links(); len(l) != 1 {
		t.Fatalf("attachment without a host VRF left a link: %+v", l)
	}
}

// TestStaleDeletionPreservesReplacement deletes an attachment while its
// replacement, on the same pod and VPC, is created: releasing the old one
// leaves the replacement's link and datapath rows alone, and the workload
// link sharing the VRF too.
func TestStaleDeletionPreservesReplacement(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	var workload int
	in(t, f.host, func() error {
		vrf, err := netlink.LinkByName("G" + vpcA + "V")
		if err != nil {
			return err
		}
		if err := netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "G" + vpcA + "001H", MasterIndex: vrf.Attrs().Index},
			PeerName:  "workload",
		}); err != nil {
			return err
		}
		l, err := netlink.LinkByName("G" + vpcA + "001H")
		workload = l.Attrs().Index
		return err
	})
	f.attach("old", attA, pod1UID, vpcA, addr, false)
	f.reconcile(a)
	oldIndex := f.hostLink("old").Attrs().Index

	if err := f.client.Delete(context.Background(), f.get("old")); err != nil {
		t.Fatal(err)
	}
	f.attach("new", attAgain, pod1UID, vpcA, "fd00:aa::2", false)
	f.reconcile(a)
	f.programmed("new")
	if c := f.condition("old", galacticv1alpha1.EdgeAttachmentReleased); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("old not released: %+v", c)
	}
	newIndex := f.hostLink("new").Attrs().Index
	if _, ok := f.dp.table(newIndex); !ok {
		t.Error("replacement's datapath rows removed")
	}
	if !slices.Equal(f.dp.unregistered, []uint32{uint32(oldIndex)}) {
		t.Errorf("unregistered %v, want only the old link %d", f.dp.unregistered, oldIndex)
	}
	in(t, f.host, func() error {
		_, err := netlink.LinkByIndex(workload)
		return err
	})

	// The old attachment's release, run again from a late event, finds
	// nothing of its own and leaves the replacement alone.
	f.reconcile(a)
	f.programmed("new")
	if got := f.hostLink("new").Attrs().Index; got != newIndex {
		t.Errorf("replacement recreated: %d -> %d", newIndex, got)
	}
}

// TestProgrammingDisabled refuses to program until the maintenance writers
// are fenced, but still releases.
func TestProgrammingDisabled(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	f.reconcile(a)
	f.programmed("a")

	disabled := f.agent()
	disabled.Program = false
	f.attach("b", attB, pod1UID, vpcB, addr, false)
	f.reconcile(disabled)
	if c := f.condition("b", galacticv1alpha1.EdgeAttachmentProgrammed); c.Reason != ReasonMaintenanceNotFenced {
		t.Fatalf("disabled agent reported %+v", c)
	}
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}
	f.reconcile(disabled)
	if l := f.links(); len(l) != 0 {
		t.Fatalf("disabled agent left links: %+v", l)
	}
}

// TestFailedReleaseIsRetried fails a release, first in the datapath and then
// in the runtime: the attachment is not reported Released, its link and
// datapath rows stay, and a later pass finishes the release.
func TestFailedReleaseIsRetried(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, true)
	f.reconcile(a)
	index := f.hostLink("a").Attrs().Index
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}

	f.dp.failUnregister = 1
	f.attach("b", attB, pod1UID, vpcA, "fd00:aa::2", false)
	if err := a.Reconcile(context.Background()); err == nil {
		t.Fatal("pass with a failed release reported no error")
	}
	if c := f.condition("b", galacticv1alpha1.EdgeAttachmentProgrammed); c != nil && c.Status == metav1.ConditionTrue {
		t.Fatal("reported Programmed from a snapshot that did not complete")
	}
	if c := f.condition("a", galacticv1alpha1.EdgeAttachmentReleased); c != nil {
		t.Fatalf("released after a failed unregister: %+v", c)
	}
	if _, ok := f.dp.table(index); !ok || f.hostLink("a").Attrs().Index != index {
		t.Fatal("link or datapath rows removed after a failed unregister")
	}

	f.pods.down = true
	if err := a.Reconcile(context.Background()); err == nil {
		t.Fatal("pass with an unreachable runtime reported no error")
	}
	if c := f.condition("a", galacticv1alpha1.EdgeAttachmentReleased); c != nil {
		t.Fatalf("released without reaching the pod's runtime: %+v", c)
	}

	f.pods.down = false
	f.reconcile(a)
	if c := f.condition("a", galacticv1alpha1.EdgeAttachmentReleased); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("not released once the failures cleared: %+v", c)
	}
	f.programmed("b")
	if _, ok := f.dp.table(index); ok || len(f.links()) != 1 {
		t.Fatal("release left the link or its rows")
	}
}

// TestScopeOwnership keeps a fenced process fenced, and never takes a scope
// from a writer that is not galactic-edge.
func TestScopeOwnership(t *testing.T) {
	f := newFixture(t)
	old, current := f.agent(), f.agent()
	f.pod(pod1UID)
	f.attach("a", attA, pod1UID, vpcA, addr, false)
	f.reconcile(current)
	for range 2 {
		if err := old.Reconcile(context.Background()); err == nil {
			t.Fatal("an older process took the scope from a newer one")
		}
	}
	f.reconcile(current)
	f.programmed("a")

	auth, err := ownership.New(f.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Claim("vpc-"+vpcB, "galactic-cni/test"); err != nil {
		t.Fatal(err)
	}
	f.attach("b", attB, pod1UID, vpcB, addr, false)
	if err := current.Reconcile(context.Background()); !errors.Is(err, ownership.ErrNotOwner) {
		t.Fatalf("pass over another writer's scope = %v", err)
	}
	if c := f.condition("b", galacticv1alpha1.EdgeAttachmentProgrammed); c == nil ||
		c.Reason != ReasonOwnershipUnavailable {
		t.Fatalf("attachment in another writer's scope reported %+v", c)
	}
	if rec, _ := auth.Read("vpc-" + vpcB); rec.Owner != "galactic-cni/test" || rec.Transitioning {
		t.Fatalf("another writer's scope was taken: %+v", rec)
	}
}

// TestUnstampedLinkOfAGonePod leaves the pair a provision interrupted before
// stamping creates. While the pod's namespace exists but its sandbox cannot
// be found, the link cannot be proven the attachment's and the release is
// retried; once the namespace is gone, so is the pair, and the release
// completes.
func TestUnstampedLinkOfAGonePod(t *testing.T) {
	f := newFixture(t)
	a := f.agent()
	podPath := f.pod(pod1UID)
	att := f.attach("a", attA, pod1UID, vpcA, addr, false)
	spec, err := desired(att, mtu)
	if err != nil {
		t.Fatal(err)
	}
	host, err := netns.GetFromPath(f.host)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Close() }()
	in(t, podPath, func() error {
		return netlink.LinkAdd(&netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: spec.PodLink}, PeerName: spec.HostLink,
			PeerNamespace: netlink.NsFd(int(host)),
		})
	})
	if err := f.client.Delete(context.Background(), f.get("a")); err != nil {
		t.Fatal(err)
	}
	f.pods.set(pod1UID, "")
	if err := a.Reconcile(context.Background()); err == nil {
		t.Fatal("released an unstamped link it could not prove")
	}
	if c := f.condition("a", galacticv1alpha1.EdgeAttachmentReleased); c != nil {
		t.Fatalf("reported released with the link still there: %+v", c)
	}
	if err := netns.DeleteNamed(filepath.Base(podPath)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the pod's link to go with its namespace", func() bool {
		var gone bool
		in(t, f.host, func() error {
			_, err := netlink.LinkByName(spec.HostLink)
			gone = err != nil
			return nil
		})
		return gone
	})
	f.reconcile(a)
	if c := f.condition("a", galacticv1alpha1.EdgeAttachmentReleased); c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("not released once the pod's namespace was gone: %+v", c)
	}
}

// eventually polls cond for up to five seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
