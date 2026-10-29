// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package masque

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	galacticv1alpha1 "go.datum.net/galactic/api/v1alpha1"
	"go.datum.net/galactic/internal/edge/connectip"
	"go.datum.net/galactic/internal/edge/provider"
)

// attachment is the pod's EdgeAttachment to one EdgeService, shared by every
// request whose grant names that service.
type attachment struct {
	svc  ServiceRef
	name string
	// prep serializes preparing, checking and deleting this attachment. It
	// is held across API calls and never taken while Adapter.mu is held.
	prep prepLock

	// The fields below are guarded by Adapter.mu.

	// uid is the object's UID once read.
	uid types.UID
	// refs counts the requests holding or preparing the attachment.
	refs int
	// idleSince is when refs last fell to zero, on the lease clock.
	idleSince time.Duration
	// gen increments whenever the device is closed; a request serves only
	// the generation it was admitted on.
	gen uint64
	// vpcID and programmed identify the host state backend was opened on.
	vpcID      string
	programmed string
	backend    *connectip.TUNBackend
}

// serving reports whether e still serves generation gen. The caller holds
// Adapter.mu.
func (e *attachment) serving(gen uint64) bool { return e.backend != nil && e.gen == gen }

// acquireAttachment returns g's attachment, serving its packet device, with
// a reference the caller releases with releaseAttachment.
func (a *Adapter) acquireAttachment(ctx context.Context, g *Grant) (*attachment, error) {
	name := provider.AttachmentName(g.Service.UID, a.cfg.Pod.UID)
	a.mu.Lock()
	e := a.attachments[g.Service.UID]
	if e == nil {
		e = &attachment{svc: g.Service, name: name, prep: newPrepLock()}
		a.attachments[g.Service.UID] = e
	}
	if e.svc != g.Service {
		a.mu.Unlock()
		return nil, fmt.Errorf("service UID %s is attached as %s/%s, not %s/%s", g.Service.UID, e.svc.Namespace,
			e.svc.Name, g.Service.Namespace, g.Service.Name)
	}
	e.refs++
	a.mu.Unlock()

	if err := e.prep.lock(ctx); err != nil {
		a.releaseAttachment(e)
		return nil, err
	}
	err := a.prepare(ctx, e, g)
	e.prep.unlock()
	if err != nil {
		a.releaseAttachment(e)
		return nil, err
	}
	return e, nil
}

// releaseAttachment drops one reference to e.
func (a *Adapter) releaseAttachment(e *attachment) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e.refs--
	if e.refs == 0 {
		e.idleSince = a.cfg.Claims.Clock()
	}
}

// prepare waits until e serves g: core admitted the attachment for g's VPC
// on this pod's node, galactic-edge programmed it, and its packet device is
// open and reported Ready. Every refusal fails closed. The caller holds
// e.prep.
func (a *Adapter) prepare(ctx context.Context, e *attachment, g *Grant) error {
	for {
		a.mu.Lock()
		open, vpcID := e.backend != nil, e.vpcID
		a.mu.Unlock()
		if open {
			if vpcID != g.VPCID {
				return fmt.Errorf("attachment %s serves VPC %s, not the grant's %s", e.name, vpcID, g.VPCID)
			}
			return nil
		}
		state, err := a.prepareOnce(ctx, e, g)
		if err != nil || state == "" {
			return err
		}
		if err := a.wait(ctx, state); err != nil {
			return err
		}
	}
}

// prepareOnce makes one pass of prepare. It returns the state it waits on,
// or "" once the device is open.
func (a *Adapter) prepareOnce(ctx context.Context, e *attachment, g *Grant) (string, error) {
	var att galacticv1alpha1.EdgeAttachment
	err := a.cfg.Client.Get(ctx, client.ObjectKey{Namespace: a.cfg.Pod.Namespace, Name: e.name}, &att)
	switch {
	case apierrors.IsNotFound(err):
		if a.isClosing() {
			return "", errors.New("the provider is shutting down")
		}
		created, err := provider.CreateAttachment(ctx, a.cfg.Client, a.attachmentRequest(g, e.name))
		if err != nil {
			// A name held by another pod or a request the API server or
			// its admission policies refuse cannot succeed on retry.
			if errors.Is(err, provider.ErrNameTaken) || apierrors.IsInvalid(err) || apierrors.IsForbidden(err) {
				return "", fmt.Errorf("request attachment %s: %w", e.name, err)
			}
			return "attachment not created: " + err.Error(), nil
		}
		a.log.Info("attachment requested", "attachment", created.Name, "serviceName", g.Service.Name)
		return "attachment requested", nil
	case err != nil:
		return "attachment not read: " + err.Error(), nil
	}
	if err := a.verify(&att, g); err != nil {
		return "", err
	}
	a.mu.Lock()
	e.uid = att.UID
	a.mu.Unlock()
	if att.DeletionTimestamp != nil {
		return "the previous attachment is being released", nil
	}
	if c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentAdmitted); c != nil &&
		c.Status == metav1.ConditionFalse {
		return "", fmt.Errorf("attachment %s refused: %s: %s", att.Name, c.Reason, c.Message)
	}
	if meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentDraining) {
		return "", fmt.Errorf("attachment %s is draining", att.Name)
	}
	if !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed) {
		return "waiting for galactic-edge to program attachment " + att.Name, nil
	}
	switch {
	case att.Status.PacketDevice == "":
		err = fmt.Errorf("attachment %s is programmed without a packet device", att.Name)
	case att.Status.VPC != g.VPCID:
		err = fmt.Errorf("attachment %s is admitted to VPC %s, not the grant's %s", att.Name, att.Status.VPC, g.VPCID)
	case att.Status.NodeName != a.cfg.Pod.Node:
		err = fmt.Errorf("attachment %s is on node %q, not this pod's", att.Name, att.Status.NodeName)
	}
	if err != nil {
		_ = a.setReady(ctx, &att, false, "DataPlaneFailed", err.Error())
		return "", err
	}
	if a.isClosing() {
		return "", errors.New("the provider is shutting down")
	}
	b, err := a.openBackend(att.Status.PacketDevice, g.VPC)
	if err != nil {
		_ = a.setReady(ctx, &att, false, "DataPlaneFailed", err.Error())
		return "", err
	}
	a.mu.Lock()
	e.backend, e.vpcID, e.programmed = b, att.Status.VPC, programmedKey(&att)
	a.mu.Unlock()
	if err := a.setReady(ctx, &att, true, "Serving", "the provider is serving the attachment"); err != nil {
		a.closeAttachment(e, reasonNotReady)
		return "", fmt.Errorf("report attachment %s Ready: %w", att.Name, err)
	}
	a.log.Info("serving attachment", "attachment", att.Name, "uid", att.UID, "device", att.Status.PacketDevice)
	return "", nil
}

// verify checks the immutable references of an attachment read under g's
// derived name. Anything else holding the name is provider.ErrNameTaken.
func (a *Adapter) verify(att *galacticv1alpha1.EdgeAttachment, g *Grant) error {
	s := att.Spec
	if s.PodUID != a.cfg.Pod.UID || s.ProviderRef.Name != a.cfg.Provider || s.InstanceRef.Name != a.inst.Name ||
		s.ServiceRef.UID != g.Service.UID || s.ServiceRef.Namespace != g.Service.Namespace ||
		s.ServiceRef.Name != g.Service.Name {
		return fmt.Errorf("%w: EdgeAttachment %s names pod %q, instance %q and service %s/%s (%s)",
			provider.ErrNameTaken, att.Name, s.PodUID, s.InstanceRef.Name, s.ServiceRef.Namespace, s.ServiceRef.Name,
			s.ServiceRef.UID)
	}
	return nil
}

func (a *Adapter) attachmentRequest(g *Grant, name string) *galacticv1alpha1.EdgeAttachment {
	return &galacticv1alpha1.EdgeAttachment{
		ObjectMeta: metav1.ObjectMeta{Namespace: a.cfg.Pod.Namespace, Name: name},
		Spec: galacticv1alpha1.EdgeAttachmentSpec{
			ProviderRef: galacticv1alpha1.EdgeProviderReference{Name: a.cfg.Provider},
			ServiceRef: galacticv1alpha1.EdgeServiceReference{Namespace: g.Service.Namespace, Name: g.Service.Name,
				UID: g.Service.UID},
			InstanceRef:     galacticv1alpha1.EdgeInstanceReference{Name: a.inst.Name},
			PodUID:          a.cfg.Pod.UID,
			ContractVersion: ContractVersion,
			Capabilities:    []galacticv1alpha1.EdgeCapability{{Name: PacketAccess, Version: "v1"}},
			PacketDevice: &galacticv1alpha1.EdgePacketDevice{Owner: a.cfg.Pod.RunAsUser,
				Group: a.cfg.Pod.RunAsGroup},
		},
	}
}

// programmedKey identifies the host state an attachment is programmed with.
func programmedKey(att *galacticv1alpha1.EdgeAttachment) string {
	return att.Status.HostLink + "/" + att.Status.PacketDevice + "/" + att.Status.Address
}

func (a *Adapter) openBackend(device, vpc string) (*connectip.TUNBackend, error) {
	f, err := a.cfg.OpenDevice(device)
	if err != nil {
		return nil, fmt.Errorf("open packet device %s: %w", device, err)
	}
	b, err := connectip.NewTUNBackend(f, vpc)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("serve packet device %s: %w", device, err)
	}
	return b, nil
}

// setReady writes att's Ready condition, the only one a provider sets, when
// it differs, rereading att on a conflict. Only a failure to report Ready
// is returned; reporting not Ready is best effort.
func (a *Adapter) setReady(ctx context.Context, att *galacticv1alpha1.EdgeAttachment, ready bool, reason,
	msg string) error {
	status := metav1.ConditionFalse
	if ready {
		status = metav1.ConditionTrue
	}
	uid := att.UID
	var err error
	for range 3 {
		if c := meta.FindStatusCondition(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentReady); c != nil &&
			c.Status == status && c.Reason == reason && c.ObservedGeneration == att.Generation {
			return nil
		}
		meta.SetStatusCondition(&att.Status.Conditions, metav1.Condition{Type: galacticv1alpha1.EdgeAttachmentReady,
			Status: status, Reason: reason, Message: msg, ObservedGeneration: att.Generation})
		if err = a.cfg.Client.Status().Update(ctx, att); !apierrors.IsConflict(err) {
			break
		}
		if err = a.cfg.Client.Get(ctx, client.ObjectKeyFromObject(att), att); err != nil {
			break
		}
		if att.UID != uid {
			err = fmt.Errorf("attachment %s was replaced", att.Name)
			break
		}
	}
	if err != nil && !ready {
		a.log.Debug("could not report attachment not Ready", "attachment", att.Name, "error", err)
		return nil
	}
	return err
}

// closeAttachment stops serving e's packet device and ends the requests on
// it. The object is kept; it is served again on the next request or deleted
// once idle.
func (a *Adapter) closeAttachment(e *attachment, reason string) {
	a.mu.Lock()
	b := e.backend
	if b == nil {
		a.mu.Unlock()
		return
	}
	e.backend, e.programmed, e.vpcID = nil, "", ""
	e.gen++
	for _, s := range a.sessions {
		if s.att == e {
			s.end(reason)
		}
	}
	a.mu.Unlock()
	_ = b.Close()
	a.log.Info("attachment closed", "attachment", e.name, "reason", reason)
}

// checkAttachment closes e when it is no longer the attachment its requests
// were admitted on, and deletes it when it has been idle for cfg.Idle.
func (a *Adapter) checkAttachment(ctx context.Context, e *attachment) {
	if !e.prep.tryLock() {
		return
	}
	defer e.prep.unlock()
	a.mu.Lock()
	refs, idle, uid, programmed, open := e.refs, a.cfg.Claims.Clock()-e.idleSince, e.uid, e.programmed,
		e.backend != nil
	a.mu.Unlock()
	if refs == 0 && idle >= a.cfg.Idle {
		a.closeAttachment(e, reasonIdle)
		if err := a.deleteAttachment(ctx, e); err != nil {
			a.log.Warn("could not delete idle attachment", "attachment", e.name, "error", err)
		}
		return
	}
	if !open {
		return
	}
	var att galacticv1alpha1.EdgeAttachment
	err := a.cfg.Client.Get(ctx, client.ObjectKey{Namespace: a.cfg.Pod.Namespace, Name: e.name}, &att)
	if apierrors.IsNotFound(err) {
		a.closeAttachment(e, reasonAttachmentDeleted)
		return
	}
	if err != nil {
		return
	}
	var reason string
	switch {
	case att.UID != uid:
		reason = reasonAttachmentReplaced
	case att.DeletionTimestamp != nil:
		reason = reasonAttachmentDeleted
	case meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentDraining):
		reason = reasonAttachmentDraining
	case !meta.IsStatusConditionTrue(att.Status.Conditions, galacticv1alpha1.EdgeAttachmentProgrammed):
		reason = reasonAttachmentUnprogrammed
	case programmedKey(&att) != programmed:
		reason = reasonAttachmentReprogrammed
	default:
		return
	}
	a.closeAttachment(e, reason)
	if att.UID == uid && att.DeletionTimestamp == nil {
		_ = a.setReady(ctx, &att, false, "NotServing", reason)
	}
}

// deleteAttachment deletes e's object, with its UID as a precondition so a
// replacement of the same name survives, and forgets e unless a request
// took it meanwhile. An object e has not read yet is read first, and left
// alone unless it names this pod. Core holds the object until its node
// releases the host state. The caller holds e.prep.
func (a *Adapter) deleteAttachment(ctx context.Context, e *attachment) error {
	key := client.ObjectKey{Namespace: a.cfg.Pod.Namespace, Name: e.name}
	a.mu.Lock()
	uid := e.uid
	a.mu.Unlock()
	if uid == "" {
		var cur galacticv1alpha1.EdgeAttachment
		switch err := a.cfg.Client.Get(ctx, key, &cur); {
		case apierrors.IsNotFound(err):
			a.forget(e)
			return nil
		case err != nil:
			return fmt.Errorf("read attachment %s: %w", e.name, err)
		case cur.Spec.PodUID != a.cfg.Pod.UID:
			a.forget(e)
			return nil
		}
		uid = cur.UID
	}
	att := &galacticv1alpha1.EdgeAttachment{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}}
	err := a.cfg.Client.Delete(ctx, att, client.Preconditions{UID: &uid})
	switch {
	case apierrors.IsConflict(err):
		// Another object of this pod holds the name now: track it instead,
		// idle from now, so it is deleted in turn unless a request takes it.
		var cur galacticv1alpha1.EdgeAttachment
		err := a.cfg.Client.Get(ctx, key, &cur)
		switch {
		case apierrors.IsNotFound(err), err == nil && cur.Spec.PodUID != a.cfg.Pod.UID:
			a.forget(e)
			return nil
		case err != nil:
			return fmt.Errorf("read attachment %s: %w", e.name, err)
		}
		a.mu.Lock()
		e.uid, e.idleSince = cur.UID, a.cfg.Claims.Clock()
		a.mu.Unlock()
		a.log.Info("attachment was replaced; not deleting the replacement", "attachment", e.name)
		return nil
	case client.IgnoreNotFound(err) != nil:
		return fmt.Errorf("delete attachment %s: %w", e.name, err)
	case err == nil:
		a.log.Info("attachment deleted", "attachment", e.name, "uid", uid)
	}
	a.forget(e)
	return nil
}

// forget drops e from the adapter unless a request holds it.
func (a *Adapter) forget(e *attachment) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e.refs == 0 && a.attachments[e.svc.UID] == e {
		delete(a.attachments, e.svc.UID)
	}
}
