// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package frr

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
)

// Version is an FRR release.
type Version struct {
	Major, Minor, Patch int
	// Raw is the version string FRR printed, e.g. "10.7.1_git".
	Raw string
}

func (v Version) String() string { return v.Raw }

// SupportedReleases lists the major.minor FRR releases the parsers have
// fixtures for: the fabric-router image's FRR_VERSION. Supporting another
// release means capturing its fixtures into testdata/frr-<major>.<minor>/ and
// adding it here, before the image's FRR_VERSION moves to it.
var SupportedReleases = []string{"10.7"}

// versionLine matches the first line of `show version`, e.g.
// "FRRouting 10.7.1_git (host) on Linux(...)".
var versionLine = regexp.MustCompile(`^FRRouting (([0-9]+)\.([0-9]+)(?:\.([0-9]+))?[^ ]*)`)

// ParseVersion parses the output of `show version`.
func ParseVersion(out []byte) (Version, error) {
	m := versionLine.FindSubmatch(out)
	if m == nil {
		return Version{}, &Error{Code: CodeMalformed, Message: "show version output has no FRRouting version line"}
	}
	v := Version{Raw: string(m[1])}
	v.Major, _ = strconv.Atoi(string(m[2]))
	v.Minor, _ = strconv.Atoi(string(m[3]))
	if len(m[4]) > 0 {
		v.Patch, _ = strconv.Atoi(string(m[4]))
	}
	return v, nil
}

// Supported reports whether v's major.minor release is in SupportedReleases.
func (v Version) Supported() bool {
	return slices.Contains(SupportedReleases, fmt.Sprintf("%d.%d", v.Major, v.Minor))
}

// CheckSupported returns a CodeVersionUnsupported error unless v is
// supported, so an unknown release reports diagnostics unavailable rather
// than parsing on a guess.
func CheckSupported(v Version) error {
	if v.Supported() {
		return nil
	}
	return &Error{Code: CodeVersionUnsupported,
		Message: fmt.Sprintf("FRR %s is not a supported release %v", v.Raw, SupportedReleases)}
}
