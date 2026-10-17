// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package ops

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// FleetStatus writes one line per deployment: its node, source, the epoch
// and revision it should run, what its agent applied, whether a candidate
// is waiting, its conditions that need attention, and how old its last
// report is.
func FleetStatus(ctx context.Context, c client.Client, namespace string, now time.Time, w io.Writer) error {
	list := &networkv1alpha1.FabricRouterDeploymentList{}
	if err := c.List(ctx, list, client.InNamespace(namespace)); err != nil {
		return err
	}
	slices.SortFunc(list.Items, func(a, b networkv1alpha1.FabricRouterDeployment) int {
		return compare(a.Name,
			b.Name)
	})
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "DEPLOYMENT\tNODE\tSOURCE\tEPOCH\tACTIVE\tAPPLIED\tCANDIDATE\tATTENTION\tREPORTED")
	for _, d := range list.Items {
		active, candidate := "-", "-"
		if d.Spec.ActiveRevisionRef != nil {
			active = d.Spec.ActiveRevisionRef.Name
		}
		if d.Spec.CandidateRevisionRef != nil && d.Spec.CandidateRevisionRef.Name != active {
			candidate = d.Spec.CandidateRevisionRef.Name
		}
		applied := "-"
		if d.Status.AppliedRevision != "" {
			applied = fmt.Sprintf("%s@%d", d.Status.AppliedRevision, d.Status.AppliedEpoch)
		}
		reported := "never"
		if hb := d.Status.HeartbeatTime; hb != nil {
			reported = now.Sub(hb.Time).Round(time.Second).String() + " ago"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", d.Name, d.Spec.Target.NodeName,
			sourceOf(&d), d.Spec.ActivationEpoch, active, applied, candidate, attention(&d), reported)
	}
	return tw.Flush()
}

func sourceOf(d *networkv1alpha1.FabricRouterDeployment) string {
	s := string(d.Spec.Source)
	if eff := d.Status.EffectiveSource; eff != "" && eff != d.Spec.Source {
		s += "(" + string(eff) + ")"
	}
	if d.Spec.Suspended {
		s += ",suspended"
	}
	return s
}

// attention lists the conditions an operator acts on.
func attention(d *networkv1alpha1.FabricRouterDeployment) string {
	var out []string
	for _, t := range []string{networkv1alpha1.FabricConditionDegraded,
		networkv1alpha1.FabricConditionRecoveryConflict} {
		if c := meta.FindStatusCondition(d.Status.Conditions, t); c != nil && c.Status == "True" {
			out = append(out, t+":"+c.Reason)
		}
	}
	// A deployment with nothing promoted to it is as it should be.
	if c := meta.FindStatusCondition(d.Status.Conditions, networkv1alpha1.FabricConditionAccepted); c != nil &&
		c.Status == "False" && c.Reason != networkv1alpha1.FabricReasonWaitingForPromotion {
		out = append(out, "NotAccepted:"+c.Reason)
	}
	if len(out) == 0 {
		return "-"
	}
	return strings.Join(out, ",")
}

// ReleaseStatus writes a release's phase and, per target, where it stands.
func ReleaseStatus(ctx context.Context, c client.Client, namespace, name string, w io.Writer) error {
	auth := &networkv1alpha1.FabricReleaseAuthorization{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, auth); err != nil {
		return err
	}
	phase := string(auth.Status.Phase)
	if phase == "" {
		phase = "Pending"
	}
	_, _ = fmt.Fprintf(w, "release %s (%s, sequence %d, domain %s): %s\n", auth.Name, auth.Spec.Type,
		auth.Spec.FleetSequence, auth.Spec.RoutingDomain, phase)
	if cnd := meta.FindStatusCondition(auth.Status.Conditions, "Progressing"); cnd != nil {
		_, _ = fmt.Fprintf(w, "  %s: %s\n", cnd.Reason, cnd.Message)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  DEPLOYMENT\tREVISION\tEPOCH\tSTAGE")
	for _, t := range auth.Spec.Deployments {
		d := &networkv1alpha1.FabricRouterDeployment{}
		stage, epoch := "deployment missing", "-"
		if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: t.Deployment}, d); err == nil {
			stage, epoch = targetStage(d, auth, t)
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", t.Deployment, t.Revision, epoch, stage)
	}
	return tw.Flush()
}

// targetStage describes one target from its deployment.
func targetStage(d *networkv1alpha1.FabricRouterDeployment, auth *networkv1alpha1.FabricReleaseAuthorization,
	t networkv1alpha1.FabricReleaseTarget) (stage, epoch string) {
	ref := d.Spec.AuthorizationRef
	if ref == nil || ref.UID != string(auth.UID) || d.Spec.ActiveRevisionRef == nil ||
		d.Spec.ActiveRevisionRef.Name != t.Revision {
		if d.Status.AppliedRevision == t.Revision && d.Status.AppliedDigest == t.ActivationDependencyDigest {
			return "already running", strconv.FormatInt(d.Status.AppliedEpoch, 10)
		}
		return "waiting", "-"
	}
	epoch = strconv.FormatInt(d.Spec.ActivationEpoch, 10)
	for _, e := range d.Status.Epochs {
		if e.Epoch == d.Spec.ActivationEpoch {
			if e.Detail != "" {
				return string(e.Stage) + ": " + e.Detail, epoch
			}
			return string(e.Stage), epoch
		}
	}
	return "promoted, not yet reported", epoch
}
