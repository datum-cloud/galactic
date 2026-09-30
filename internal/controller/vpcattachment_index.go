// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package controller

import (
	"sort"
	"sync"

	cloudv1alpha1 "go.datum.net/cloud/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
)

// VPCAttachmentIndex indexes Cloud API attachments by their observed node.
//
// VPCAttachmentStatus.Node is the source of truth. This index is deliberately
// in-memory: it is a read optimization for node-local Galactic reconcilers, not
// a second API-level ownership field.
type VPCAttachmentIndex struct {
	mu     sync.RWMutex
	byNode map[string]map[types.NamespacedName]*cloudv1alpha1.VPCAttachment
	byKey  map[types.NamespacedName]string
}

// NewVPCAttachmentIndex creates an empty attachment index.
func NewVPCAttachmentIndex() *VPCAttachmentIndex {
	return &VPCAttachmentIndex{
		byNode: make(map[string]map[types.NamespacedName]*cloudv1alpha1.VPCAttachment),
		byKey:  make(map[types.NamespacedName]string),
	}
}

// Upsert records the latest attachment state. An attachment with no observed
// node is retained nowhere because it cannot be programmed by a node-local
// dataplane controller yet.
func (i *VPCAttachmentIndex) Upsert(attachment *cloudv1alpha1.VPCAttachment) {
	if attachment == nil {
		return
	}

	key := types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.removeLocked(key)

	node := attachment.Status.Node
	if node == "" {
		return
	}
	if i.byNode[node] == nil {
		i.byNode[node] = make(map[types.NamespacedName]*cloudv1alpha1.VPCAttachment)
	}
	i.byNode[node][key] = attachment.DeepCopy()
	i.byKey[key] = node
}

// Delete removes an attachment from the index.
func (i *VPCAttachmentIndex) Delete(attachment *cloudv1alpha1.VPCAttachment) {
	if attachment == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.removeLocked(types.NamespacedName{Namespace: attachment.Namespace, Name: attachment.Name})
}

// ForNode returns a deterministic snapshot of attachments currently assigned
// to node. Callers may safely mutate returned objects.
func (i *VPCAttachmentIndex) ForNode(node string) []*cloudv1alpha1.VPCAttachment {
	i.mu.RLock()
	defer i.mu.RUnlock()

	attachments := make([]*cloudv1alpha1.VPCAttachment, 0, len(i.byNode[node]))
	for _, attachment := range i.byNode[node] {
		attachments = append(attachments, attachment.DeepCopy())
	}
	sort.Slice(attachments, func(a, b int) bool {
		return types.NamespacedName{Namespace: attachments[a].Namespace, Name: attachments[a].Name}.String() <
			types.NamespacedName{Namespace: attachments[b].Namespace, Name: attachments[b].Name}.String()
	})
	return attachments
}

func (i *VPCAttachmentIndex) removeLocked(key types.NamespacedName) {
	node, ok := i.byKey[key]
	if !ok {
		return
	}
	delete(i.byKey, key)
	delete(i.byNode[node], key)
	if len(i.byNode[node]) == 0 {
		delete(i.byNode, node)
	}
}
