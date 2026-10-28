// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package node

import (
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"go.miloapis.com/instrumentation/labels"

	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
)

// Label names.
const (
	labelAttachment = "attachment"
	labelDirection  = "direction"
	labelAction     = "action"
	labelReason     = "reason"
)

var (
	interfaceLabelNames = []string{labels.ResourceNamespace, "vpc", labelAttachment, "interface", "interface_uid"}
	ruleLabels          = append(slices.Clone(interfaceLabelNames), labelDirection, "policy", "policy_uid", "rule",
		labelAction)
	fallbackLabels = append(slices.Clone(interfaceLabelNames), labelDirection, labelReason)

	ruleHitsDesc = prometheus.NewDesc("galactic_cni_traffic_policy_rule_hits_total",
		"Packets evaluated with this rule as the winning rule, one per interface and direction evaluation. "+
			"A GSO packet counts once. Not forwarded traffic: an allowed packet dropped later still counts.",
		ruleLabels, nil)
	ruleBytesDesc = prometheus.NewDesc("galactic_cni_traffic_policy_rule_bytes_total",
		"Tenant IP bytes evaluated with this rule as the winning rule, without Ethernet or outer SRv6.",
		ruleLabels, nil)
	fallbackPacketsDesc = prometheus.NewDesc("galactic_cni_traffic_policy_fallback_packets_total",
		"Packets denied without a winning rule, by reason: no_match, policy_unavailable, parse_error or "+
			"classification_error.",
		fallbackLabels, nil)
	fallbackBytesDesc = prometheus.NewDesc("galactic_cni_traffic_policy_fallback_bytes_total",
		"Tenant IP bytes denied without a winning rule, by reason; a packet whose IP boundary could not be "+
			"found adds none.",
		fallbackLabels, nil)
	unattributedDesc = prometheus.NewDesc("galactic_cni_traffic_policy_unattributed_drops_total",
		"Policy denials on this node whose interface or fallback row could not be resolved.",
		[]string{labelDirection, labelReason}, nil)
	accountingErrorsDesc = prometheus.NewDesc("galactic_cni_traffic_policy_accounting_errors_total",
		"Verdicts whose rule counter row was missing; the verdict stood, the count was lost.",
		[]string{labelDirection, labelAction, labelReason}, nil)
	readErrorsDesc = prometheus.NewDesc("galactic_cni_traffic_policy_counter_read_errors",
		"Counter rows the last scrape could not read and left out, rather than reporting zero.",
		nil, nil)
)

var directionNames = [2]string{"ingress", "egress"}

// Describe implements prometheus.Collector.
func (r *Reconciler) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{ruleHitsDesc, ruleBytesDesc, fallbackPacketsDesc, fallbackBytesDesc,
		unattributedDesc, accountingErrorsDesc, readErrorsDesc} {
		ch <- d
	}
}

// Collect implements prometheus.Collector. It reads every installed rule's
// row, and every known interface's fallback rows, from the per-CPU counters,
// labeled from what this reconciler installed, never from packet fields. Only
// the interface an attachment currently has is exported, so a direction left
// bound on an old ifindex never duplicates its labels. A row it cannot read
// is left out rather than reported as zero, and counted in
// counter_read_errors.
func (r *Reconciler) Collect(ch chan<- prometheus.Metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maps == nil {
		return
	}
	readErrors := 0
	for key, a := range r.state {
		if cur, ok := r.ifaces[a.attachment]; !ok || cur.ifindex != key.ifindex {
			continue
		}
		for i, rule := range a.rules {
			packets, bytes, err := r.maps.RuleCounter(a.rows[i])
			if err != nil {
				readErrors++
				continue
			}
			l := append(a.labels.values(), directionNames[key.dir], a.policy.Name, a.policy.UID, rule.name,
				actionName(rule.allow))
			ch <- prometheus.MustNewConstMetric(ruleHitsDesc, prometheus.CounterValue, float64(packets), l...)
			ch <- prometheus.MustNewConstMetric(ruleBytesDesc, prometheus.CounterValue, float64(bytes), l...)
		}
	}
	for _, i := range r.ifaces {
		for dir, dirName := range directionNames {
			for reason, reasonName := range tpmap.ReasonNames {
				packets, bytes, err := r.maps.FallbackCounter(i.ifindex, i.token, uint32(dir), uint8(reason)) //nolint:gosec // tiny
				if err != nil {
					readErrors++
					continue
				}
				l := append(i.labels.values(), dirName, reasonName)
				ch <- prometheus.MustNewConstMetric(fallbackPacketsDesc, prometheus.CounterValue, float64(packets), l...)
				ch <- prometheus.MustNewConstMetric(fallbackBytesDesc, prometheus.CounterValue, float64(bytes), l...)
			}
		}
	}
	for dir, dirName := range directionNames {
		for reason, reasonName := range tpmap.ReasonNames {
			packets, _, err := r.maps.UnattributedCounter(uint32(dir), uint8(reason)) //nolint:gosec // tiny
			if err != nil {
				readErrors++
				continue
			}
			ch <- prometheus.MustNewConstMetric(unattributedDesc, prometheus.CounterValue, float64(packets),
				dirName, reasonName)
		}
		for _, allow := range []bool{false, true} {
			n, err := r.maps.AccountingErrors(uint32(dir), allow) //nolint:gosec // tiny
			if err != nil {
				readErrors++
				continue
			}
			ch <- prometheus.MustNewConstMetric(accountingErrorsDesc, prometheus.CounterValue, float64(n),
				dirName, actionName(allow), "missing_rule_counter")
		}
	}
	ch <- prometheus.MustNewConstMetric(readErrorsDesc, prometheus.GaugeValue, float64(readErrors))
}

func actionName(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// values are the interface labels, in label order, with an empty value
// spelled out so it stays distinguishable in queries.
func (l interfaceLabels) values() []string {
	out := []string{l.namespace, l.vpc, l.attachment, l.iface, l.ifaceUID}
	for i, v := range out {
		if strings.TrimSpace(v) == "" {
			out[i] = "unknown"
		}
	}
	return out
}
