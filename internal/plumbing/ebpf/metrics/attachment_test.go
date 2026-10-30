// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/vishvananda/netlink"
)

const (
	attachmentReceiveName  = "galactic_vpc_attachment_receive_bytes_total"
	attachmentTransmitName = "galactic_vpc_attachment_transmit_bytes_total"

	// linkG and linkH are host-side link names for attachments G and H of
	// VPC jU.
	linkG = "G0000000jU00GH"
	linkH = "G0000000jU00HH"
)

func hostLink(name string, rx, tx uint64) netlink.Link {
	return &netlink.Veth{LinkAttrs: netlink.LinkAttrs{
		Name: name, Statistics: &netlink.LinkStatistics{RxBytes: rx, TxBytes: tx},
	}}
}

// gatherAttachments gathers a collector listing links (or failing with err)
// through a pedantic registry.
func gatherAttachments(t *testing.T, links []netlink.Link, err error) ([]*dto.MetricFamily, error) {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewAttachmentCollector(func() ([]netlink.Link, error) { return links, err }))
	return reg.Gather()
}

// mustGatherAttachments gathers like gatherAttachments and fails the test on a
// gather error.
func mustGatherAttachments(t *testing.T, links []netlink.Link) []*dto.MetricFamily {
	t.Helper()
	families, err := gatherAttachments(t, links, nil)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	return families
}

// attachmentSeries returns the metrics of the family named name.
func attachmentSeries(families []*dto.MetricFamily, name string) []*dto.Metric {
	for _, f := range families {
		if f.GetName() == name {
			return f.GetMetric()
		}
	}
	return nil
}

func TestAttachmentCollector_EmitsPerAttachmentDirectionFromInstanceSide(t *testing.T) {
	families := mustGatherAttachments(t, []netlink.Link{hostLink(linkG, 100, 250)})

	for _, tc := range []struct {
		name string
		want float64
	}{
		{attachmentReceiveName, 250},
		{attachmentTransmitName, 100},
	} {
		got := attachmentSeries(families, tc.name)
		if len(got) != 1 {
			t.Fatalf("%s: got %d series, want 1", tc.name, len(got))
		}
		m := got[0]
		if m.GetCounter() == nil {
			t.Errorf("%s: not a counter", tc.name)
		}
		for label, want := range map[string]string{
			labelVPC: "jU", labelVPCAttachment: "G", "host_interface": linkG,
		} {
			if v := labelValue(m, label); v != want {
				t.Errorf("%s: label %s = %q, want %q", tc.name, label, v, want)
			}
		}
		if v := metricValue(m); v != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, v, tc.want)
		}
	}
}

func TestAttachmentCollector_SeparatesAttachmentsInOneVPC(t *testing.T) {
	families := mustGatherAttachments(t, []netlink.Link{
		hostLink(linkG, 1, 2),
		hostLink(linkH, 3, 4),
	})

	got := map[string]float64{}
	for _, m := range attachmentSeries(families, attachmentReceiveName) {
		if v := labelValue(m, labelVPC); v != "jU" {
			t.Errorf("vpc = %q, want jU", v)
		}
		got[labelValue(m, labelVPCAttachment)] = metricValue(m)
	}
	want := map[string]float64{"G": 2, "H": 4}
	if len(got) != len(want) || got["G"] != want["G"] || got["H"] != want["H"] {
		t.Errorf("receive series by attachment = %v, want %v", got, want)
	}
}

func TestAttachmentCollector_IgnoresOtherLinks(t *testing.T) {
	tap := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{
		Name: linkG, Statistics: &netlink.LinkStatistics{RxBytes: 7, TxBytes: 9},
	}}
	families := mustGatherAttachments(t, []netlink.Link{
		hostLink("G0000000jUV", 1, 1),
		hostLink("G0000000jU00GG", 1, 1),
		hostLink("eth0", 1, 1),
		hostLink("lo", 1, 1),
		tap,
	})

	for _, name := range []string{attachmentReceiveName, attachmentTransmitName} {
		got := attachmentSeries(families, name)
		if len(got) != 1 {
			t.Fatalf("%s: got %d series, want only the tap's", name, len(got))
		}
		if v := labelValue(got[0], "host_interface"); v != linkG {
			t.Errorf("%s: host_interface = %q, want the tap", name, v)
		}
	}
}

func TestAttachmentCollector_SkipsNilStatistics(t *testing.T) {
	families := mustGatherAttachments(t, []netlink.Link{
		&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: linkG}},
		hostLink(linkH, 1, 2),
	})

	got := attachmentSeries(families, attachmentReceiveName)
	if len(got) != 1 {
		t.Fatalf("got %d receive series, want 1", len(got))
	}
	if v := labelValue(got[0], labelVPCAttachment); v != "H" {
		t.Errorf("vpc_attachment = %q, want H", v)
	}
}

func TestAttachmentCollector_OmitsRemovedLinks(t *testing.T) {
	links := []netlink.Link{hostLink(linkG, 1, 2), hostLink(linkH, 3, 4)}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewAttachmentCollector(func() ([]netlink.Link, error) { return links, nil }))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("first gather: %v", err)
	}
	if n := len(attachmentSeries(families, attachmentReceiveName)); n != 2 {
		t.Fatalf("first gather: got %d receive series, want 2", n)
	}

	links = links[:1]
	families, err = reg.Gather()
	if err != nil {
		t.Fatalf("second gather: %v", err)
	}
	if n := len(attachmentSeries(families, attachmentReceiveName)); n != 1 {
		t.Errorf("second gather: got %d receive series, want 1", n)
	}
}

func TestAttachmentCollector_ListErrorReportsInvalidMetric(t *testing.T) {
	_, err := gatherAttachments(t, nil, errors.New("netlink down"))
	if err == nil {
		t.Fatal("gather succeeded, want an error from the failed link list")
	}
	if !strings.Contains(err.Error(), "list links") {
		t.Errorf("gather error = %v, want it to mention list links", err)
	}
}

func TestAttachmentCollector_PassesLint(t *testing.T) {
	c := NewAttachmentCollector(func() ([]netlink.Link, error) {
		return []netlink.Link{hostLink(linkG, 1, 2), hostLink(linkH, 3, 4)}, nil
	})
	problems, err := testutil.CollectAndLint(c)
	if err != nil {
		t.Fatalf("CollectAndLint: %v", err)
	}
	for _, p := range problems {
		t.Errorf("lint problem in %s: %s", p.Metric, p.Text)
	}
}
