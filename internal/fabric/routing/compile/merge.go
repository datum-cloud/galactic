// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"reflect"

	networkv1alpha1 "go.datum.net/galactic/api/network/v1alpha1"
)

// effectiveFamily is a peer's settings for family f: each field the peer
// sets, otherwise the profile's. There is no deeper inheritance.
func effectiveFamily(
	p *networkv1alpha1.BGPPeer, profile *networkv1alpha1.BGPPeerProfile, f family,
) networkv1alpha1.BGPPeerFamilySettings {
	out := networkv1alpha1.BGPPeerFamilySettings{AFI: f.afi, SAFI: f.safi}
	if profile != nil {
		if pf := profileFamily(profile, f); pf != nil {
			out = *pf.DeepCopy()
		}
	}
	if own := ownFamilySettings(p, f); own != nil {
		overlay(&out, own)
	}
	return out
}

// overlay copies every field own sets onto dst.
func overlay(dst, own *networkv1alpha1.BGPPeerFamilySettings) {
	d, o := reflect.ValueOf(dst).Elem(), reflect.ValueOf(own).Elem()
	for i := range o.NumField() {
		if field := o.Field(i); field.Kind() == reflect.Pointer && !field.IsNil() {
			d.Field(i).Set(field)
		}
	}
}

// overriddenFamily is the part of a peer's own settings that differs from
// the profile's, which is all that renders on the neighbor.
func overriddenFamily(own, inherited *networkv1alpha1.BGPPeerFamilySettings) *networkv1alpha1.BGPPeerFamilySettings {
	out := &networkv1alpha1.BGPPeerFamilySettings{AFI: own.AFI, SAFI: own.SAFI}
	if inherited == nil {
		overlay(out, own)
		return out
	}
	o, in, dst := reflect.ValueOf(own).Elem(), reflect.ValueOf(inherited).Elem(), reflect.ValueOf(out).Elem()
	for i := range o.NumField() {
		field := o.Field(i)
		if field.Kind() != reflect.Pointer || field.IsNil() {
			continue
		}
		if !reflect.DeepEqual(field.Interface(), in.Field(i).Interface()) {
			dst.Field(i).Set(field)
		}
	}
	return out
}
