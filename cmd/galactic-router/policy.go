// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	cloudv1alpha1 "go.datum.net/galactic/api/cloud/v1alpha1"
	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/plumbing/ebpf/attach"
	"go.datum.net/galactic/internal/plumbing/ebpf/tpmap"
	"go.datum.net/galactic/internal/trafficpolicy"
	tpnode "go.datum.net/galactic/internal/trafficpolicy/node"
)

// newPolicyCommand builds the "policy" subcommand group, the traffic policy
// diagnostics.
func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Explain a TrafficPolicy's verdict or show what this node applies",
	}
	cmd.AddCommand(newPolicyExplainCommand(), newPolicyShowCommand())
	return cmd
}

// explainFlags is a packet tuple and the policy to decide it against.
type explainFlags struct {
	file, policy                      string
	path, src, dst, proto             string
	srcPort, dstPort, icmpType, icmpC uint16
}

func newPolicyExplainCommand() *cobra.Command {
	var f explainFlags
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Decide one packet against a TrafficPolicy",
		Long: `explain decides a packet tuple against a TrafficPolicy with the Go evaluator
and against the entries it compiles to, and prints the winning rule. It reads
the policy from a file (--file) or from the cluster (--policy namespace/name),
and never touches this node's datapath or counters. The two results always
agree; a disagreement is a compiler bug and fails the command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec, name, err := loadPolicy(cmd.Context(), f)
			if err != nil {
				return err
			}
			pkt, err := f.packet()
			if err != nil {
				return err
			}
			return explain(cmd.OutOrStdout(), name, spec, pkt)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.file, "file", "", "a TrafficPolicy manifest")
	fl.StringVar(&f.policy, "policy", "", "a TrafficPolicy in the cluster, as namespace/name")
	fl.StringVar(&f.path, "path", "", "the packet's path: Private, PublicNAT, PublicService, or empty for unknown")
	fl.StringVar(&f.src, "src", "", "source address (required)")
	fl.StringVar(&f.dst, "dst", "", "destination address (required)")
	fl.StringVar(&f.proto, "proto", "tcp", "protocol: tcp, udp, icmp, icmpv6 or a number")
	fl.Uint16Var(&f.srcPort, "sport", 0, "TCP or UDP source port")
	fl.Uint16Var(&f.dstPort, "dport", 0, "TCP or UDP destination port")
	fl.Uint16Var(&f.icmpType, "icmp-type", 0, "ICMP type")
	fl.Uint16Var(&f.icmpC, "icmp-code", 0, "ICMP code")
	cmd.MarkFlagsMutuallyExclusive("file", "policy")
	cmd.MarkFlagsOneRequired("file", "policy")
	return cmd
}

// loadPolicy reads the policy f names and returns its spec and a display name.
func loadPolicy(ctx context.Context, f explainFlags) (galacticv1alpha1.TrafficPolicySpec, string, error) {
	if f.file != "" {
		raw, err := os.ReadFile(f.file)
		if err != nil {
			return galacticv1alpha1.TrafficPolicySpec{}, "", err
		}
		var p galacticv1alpha1.TrafficPolicy
		if err := yaml.UnmarshalStrict(raw, &p); err != nil {
			return galacticv1alpha1.TrafficPolicySpec{}, "", fmt.Errorf("parse %s: %w", f.file, err)
		}
		return p.Spec, p.Name, nil
	}
	key, err := parseNamespacedName(f.policy)
	if err != nil {
		return galacticv1alpha1.TrafficPolicySpec{}, "", err
	}
	c, err := policyClient()
	if err != nil {
		return galacticv1alpha1.TrafficPolicySpec{}, "", err
	}
	var p galacticv1alpha1.TrafficPolicy
	if err := c.Get(ctx, key, &p); err != nil {
		return galacticv1alpha1.TrafficPolicySpec{}, "", err
	}
	return p.Spec, p.Name, nil
}

func (f explainFlags) packet() (trafficpolicy.Packet, error) {
	var pkt trafficpolicy.Packet
	switch f.path {
	case "":
		pkt.Path = trafficpolicy.PathUnknown
	case string(galacticv1alpha1.PathPrivate):
		pkt.Path = trafficpolicy.PathPrivate
	case string(galacticv1alpha1.PathPublicNAT):
		pkt.Path = trafficpolicy.PathPublicNAT
	case string(galacticv1alpha1.PathPublicService):
		pkt.Path = trafficpolicy.PathPublicService
	default:
		return pkt, fmt.Errorf("unknown path %q", f.path)
	}
	var err error
	if pkt.Src, err = netip.ParseAddr(f.src); err != nil {
		return pkt, fmt.Errorf("--src: %w", err)
	}
	if pkt.Dst, err = netip.ParseAddr(f.dst); err != nil {
		return pkt, fmt.Errorf("--dst: %w", err)
	}
	pkt.Src, pkt.Dst = pkt.Src.Unmap(), pkt.Dst.Unmap()
	if pkt.Src.Is4() != pkt.Dst.Is4() {
		return pkt, errors.New("--src and --dst must be the same address family")
	}
	if pkt.Proto, err = parseProto(f.proto); err != nil {
		return pkt, err
	}
	if f.icmpType > 255 || f.icmpC > 255 {
		return pkt, errors.New("--icmp-type and --icmp-code must be at most 255")
	}
	pkt.SrcPort, pkt.DstPort = f.srcPort, f.dstPort
	pkt.ICMPType, pkt.ICMPCode = uint8(f.icmpType), uint8(f.icmpC) //nolint:gosec // checked above
	return pkt, nil
}

func parseProto(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return trafficpolicy.ProtoTCP, nil
	case "udp":
		return trafficpolicy.ProtoUDP, nil
	case "icmp":
		return trafficpolicy.ProtoICMP, nil
	case "icmpv6":
		return trafficpolicy.ProtoICMPv6, nil
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("unknown protocol %q", s)
	}
	return uint8(n), nil
}

// explain prints spec's verdict for pkt, from the evaluator and from the
// compiled entries, and fails when they disagree.
func explain(w io.Writer, name string, spec galacticv1alpha1.TrafficPolicySpec, pkt trafficpolicy.Packet) error {
	model, errs := trafficpolicy.FromAPI(spec, field.NewPath("spec"))
	if len(errs) > 0 {
		return fmt.Errorf("policy %s is invalid: %w", name, errs.ToAggregate())
	}
	want := trafficpolicy.Evaluate(model, pkt)
	entries, err := trafficpolicy.Compile(model)
	if err != nil {
		return err
	}
	got := trafficpolicy.EvaluateEntries(entries, pkt)

	action := "deny"
	if want.Allow {
		action = "allow"
	}
	rule := "-"
	if want.Rule >= 0 {
		rule = fmt.Sprintf("%s (#%d)", model.Rules[want.Rule].Name, want.Rule)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := &printer{w: tw}
	out.printf("policy\t%s\n", name)
	out.printf("path\t%s\n", pkt.Path)
	out.printf("verdict\t%s\n", action)
	out.printf("reason\t%s\n", want.Reason)
	out.printf("rule\t%s\n", rule)
	out.printf("compiled entries\t%d\n", len(entries))
	if err := out.flush(tw); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("the compiled entries decide %+v but the evaluator decides %+v: report this as a bug",
			got, want)
	}
	return nil
}

func newPolicyShowCommand() *cobra.Command {
	var pinDir string
	cmd := &cobra.Command{
		Use:   "show <namespace>/<attachment>",
		Short: "Show what this node applies to one VPCAttachment's interface",
		Long: `show prints a VPCAttachment's binding, this node's status entry for it, and
the snapshot each direction of its interface holds in this node's datapath,
with every rule's counters. Run it in the galactic-router pod on the node
the attachment is on.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := parseNamespacedName(args[0])
			if err != nil {
				return err
			}
			c, err := policyClient()
			if err != nil {
				return err
			}
			maps, err := tpmap.OpenPinned(pinDir)
			if err != nil {
				return fmt.Errorf("open traffic policy maps: %w", err)
			}
			defer maps.Close()
			return show(cmd.Context(), cmd.OutOrStdout(), c, maps, key)
		},
	}
	cmd.Flags().StringVar(&pinDir, "pin-dir", attach.PinDir,
		"bpffs directory the uSID datapath's maps are pinned under")
	return cmd
}

func show(ctx context.Context, w io.Writer, c client.Client, maps *tpmap.Maps, key types.NamespacedName) error {
	var att cloudv1alpha1.VPCAttachment
	if err := c.Get(ctx, key, &att); err != nil {
		return err
	}
	if att.Status.HostInterface == "" {
		return fmt.Errorf("VPCAttachment %s has no host interface yet", key)
	}
	link, err := netlink.LinkByName(att.Status.HostInterface)
	if err != nil {
		return fmt.Errorf("interface %s is not on this node (VPCAttachment is on %q): %w",
			att.Status.HostInterface, att.Status.Node, err)
	}
	ifindex := uint32(link.Attrs().Index) //nolint:gosec // a kernel ifindex
	var binding galacticv1alpha1.TrafficPolicyBinding
	bindingFound := c.Get(ctx, key, &binding) == nil

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := &printer{w: tw}
	out.printf("attachment\t%s (uid %s)\n", key, att.UID)
	out.printf("interface\t%s (ifindex %d)\n", att.Status.HostInterface, ifindex)
	for _, d := range []struct {
		dir  uint32
		name string
		ref  *galacticv1alpha1.LocalPolicyReference
		st   func(galacticv1alpha1.NodeBindingStatus) *galacticv1alpha1.AppliedPolicy
	}{
		{tpmap.DirIngress, "ingress", binding.Spec.IngressPolicyRef,
			func(n galacticv1alpha1.NodeBindingStatus) *galacticv1alpha1.AppliedPolicy { return n.Ingress }},
		{tpmap.DirEgress, "egress", binding.Spec.EgressPolicyRef,
			func(n galacticv1alpha1.NodeBindingStatus) *galacticv1alpha1.AppliedPolicy { return n.Egress }},
	} {
		bound := galacticv1alpha1.DefaultPolicyName + " (built in)"
		if bindingFound && d.ref != nil {
			bound = d.ref.Name
		}
		out.printf("\n%s\tbound to %s\n", d.name, bound)
		for _, n := range binding.Status.Nodes {
			if a := d.st(n); n.Node == att.Status.Node && a != nil {
				out.printf("  status\t%s %s\n", a.State, a.Message)
			}
		}
		snap, ok, err := maps.ReadSnapshot(ifindex, d.dir)
		if err != nil {
			return err
		}
		if !ok {
			out.printf("  snapshot\tnone: denies as policy_unavailable\n")
			continue
		}
		out.printf("  snapshot\tpolicy uid %s, generation %d, %d entries\n",
			snapshotUID(snap.PolicyUID), snap.Generation, len(snap.Entries))
		names := ruleNames(ctx, c, key.Namespace, d.ref, snap)
		seen := map[uint32]bool{}
		for _, e := range snap.Entries {
			row := snap.CounterBase + uint32(e.Rule)
			if seen[row] {
				continue
			}
			seen[row] = true
			packets, bytes, err := maps.RuleCounter(row)
			if err != nil {
				return err
			}
			action := "deny"
			if e.Flags&trafficpolicy.FlagAllow != 0 {
				action = "allow"
			}
			name, ok := names[row]
			if !ok {
				name = fmt.Sprintf("row %d", row)
			}
			out.printf("  rule %s\t%s: %d packets, %d bytes\n", name, action, packets, bytes)
		}
		for reason, rn := range tpmap.ReasonNames {
			packets, bytes, err := maps.FallbackCounter(ifindex, snap.Token, d.dir, uint8(reason)) //nolint:gosec // tiny
			if err == nil && packets > 0 {
				out.printf("  fallback %s\t%d packets, %d bytes\n", rn, packets, bytes)
			}
		}
	}
	return out.flush(tw)
}

// ruleNames names a snapshot's counter rows by rule when the snapshot holds
// exactly what the policy now in the cluster compiles to, and returns nothing
// otherwise, so a stale snapshot is never labeled with today's rule names.
func ruleNames(ctx context.Context, c client.Client, ns string, ref *galacticv1alpha1.LocalPolicyReference,
	snap tpmap.Snapshot,
) map[uint32]string {
	identity := galacticv1alpha1.DefaultPolicyUID
	model := trafficpolicy.Default()
	if ref != nil {
		var p galacticv1alpha1.TrafficPolicy
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: ref.Name}, &p); err != nil ||
			p.Generation != snap.Generation {
			return nil
		}
		var errs field.ErrorList
		if model, errs = trafficpolicy.FromAPI(p.Spec, field.NewPath("spec")); len(errs) > 0 {
			return nil
		}
		identity = string(p.UID)
	}
	if tpnode.PolicyUIDBytes(identity) != snap.PolicyUID {
		return nil
	}
	entries, err := trafficpolicy.Compile(model)
	if err != nil {
		return nil
	}
	rows, ok := tpnode.RuleRows(entries, snap, len(model.Rules))
	if !ok {
		return nil
	}
	names := map[uint32]string{}
	for i, row := range rows {
		if row != tpnode.NoRow {
			names[row] = model.Rules[i].Name
		}
	}
	return names
}

// snapshotUID prints a snapshot's recorded policy identity.
func snapshotUID(b [16]byte) string {
	if b == tpnode.PolicyUIDBytes(galacticv1alpha1.DefaultPolicyUID) {
		return galacticv1alpha1.DefaultPolicyUID
	}
	return uuid.UUID(b).String()
}

func parseNamespacedName(s string) (types.NamespacedName, error) {
	ns, name, ok := strings.Cut(s, "/")
	if !ok || ns == "" || name == "" {
		return types.NamespacedName{}, fmt.Errorf("%q is not namespace/name", s)
	}
	return types.NamespacedName{Namespace: ns, Name: name}, nil
}

func policyClient() (client.Client, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}
	scheme := runtime.NewScheme()
	if err := galacticv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := cloudv1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: scheme})
}

// printer writes formatted lines and keeps the first error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

func (p *printer) flush(tw *tabwriter.Writer) error {
	if p.err != nil {
		return p.err
	}
	return tw.Flush()
}
