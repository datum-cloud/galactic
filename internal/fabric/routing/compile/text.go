// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"regexp"
	"strings"
	"unicode"
)

// Every string the renderer writes is checked here, whatever admission did:
// the compiler also runs offline, on objects admission never saw, and on
// objects stored before a schema tightened. A newline or space inside a
// value would otherwise add lines or arguments to the configuration.

var (
	// frrToken is one FRR argument: a name, address, interface or value.
	frrToken = regexp.MustCompile(`^[A-Za-z0-9_.:/@-]+$`)
	// nodeName is a Kubernetes Node name, which becomes the hostname.
	nodeName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
)

// token checks a value rendered as one FRR argument.
func (c *compiler) token(obj, field, value string) {
	if !frrToken.MatchString(value) {
		c.problems.add(ReasonInvalid, obj, field, "%q is not a single FRR argument", value)
	}
}

// text checks free text rendered to the end of a line, such as a
// description: spaces are allowed, line breaks and control characters not.
func (c *compiler) text(obj, field, value string) {
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		c.problems.add(ReasonInvalid, obj, field, "contains a line break or control character")
	}
}
