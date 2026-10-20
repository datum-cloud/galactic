// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package compile

import (
	"fmt"
	"sort"
	"strings"
)

// Reason classifies why a router's configuration could not be compiled. The
// values double as condition reasons on the router.
type Reason string

const (
	// ReasonUnsupportedField means an object sets a field the FRR fabric
	// implementation does not implement. It is refused, never ignored.
	ReasonUnsupportedField Reason = "UnsupportedField"

	// ReasonUnresolvedRef means a referenced object does not exist. The
	// router keeps its running configuration until it does.
	ReasonUnresolvedRef Reason = "UnresolvedRef"

	// ReasonInvalid means the objects are individually valid but conflict
	// with each other or with the router.
	ReasonInvalid Reason = "Invalid"
)

// Problem is one reason a router cannot be compiled.
type Problem struct {
	Reason Reason
	// Object is "Kind/name".
	Object string
	// Field is the JSON path of the offending field, when there is one.
	Field   string
	Message string
}

func (p Problem) String() string {
	if p.Field == "" {
		return fmt.Sprintf("%s: %s: %s", p.Reason, p.Object, p.Message)
	}
	return fmt.Sprintf("%s: %s %s: %s", p.Reason, p.Object, p.Field, p.Message)
}

// RefusalError is the full set of problems that refused a compile, in a
// stable order.
type RefusalError []Problem

func (ps RefusalError) Error() string {
	lines := make([]string, len(ps))
	for i, p := range ps {
		lines[i] = p.String()
	}
	return strings.Join(lines, "; ")
}

// Has reports whether any problem carries reason.
func (ps RefusalError) Has(reason Reason) bool {
	for _, p := range ps {
		if p.Reason == reason {
			return true
		}
	}
	return false
}

type problems struct{ list RefusalError }

func (ps *problems) add(reason Reason, object, field, format string, args ...any) {
	ps.list = append(ps.list, Problem{
		Reason: reason, Object: object, Field: field, Message: fmt.Sprintf(format, args...),
	})
}

func (ps *problems) unsupported(object, field, why string) {
	ps.add(ReasonUnsupportedField, object, field, "%s", why)
}

func (ps *problems) sorted() RefusalError {
	sort.SliceStable(ps.list, func(i, j int) bool {
		a, b := ps.list[i], ps.list[j]
		if a.Object != b.Object {
			return a.Object < b.Object
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Message < b.Message
	})
	return ps.list
}
