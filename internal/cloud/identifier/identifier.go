/*
Copyright © 2026 Datum Technology, Inc. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Package identifier allocates the VPC and VPC attachment identifiers the
// galactic data plane keys on. Identifiers are generated as hex and published
// as base62, which is what keeps a kernel interface name inside 15 characters.
package identifier

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/kenshaw/baseconv"
)

const (
	// MaxVPC is the largest VPC identifier: 48 bits, nine base62 characters.
	MaxVPC uint64 = 0xFFFFFFFFFFFF

	// MaxVPCAttachment is the largest attachment identifier: 16 bits, three
	// base62 characters.
	MaxVPCAttachment uint64 = 0xFFFF
)

// Hex renders value as a zero-padded hex string wide enough to hold max.
// Zero and max are reserved.
func Hex(value, max uint64) (string, error) {
	if value == 0 || value == max {
		return "", fmt.Errorf("%d is a reserved identifier value", value)
	}
	if value > max {
		return "", fmt.Errorf("%d exceeds the maximum identifier value %d", value, max)
	}
	return fmt.Sprintf("%0*x", len(strconv.FormatUint(max, 16)), value), nil
}

// Random returns a random hex identifier in (0, max).
func Random(max uint64) (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-1)))
	if err != nil {
		return "", fmt.Errorf("draw random identifier: %w", err)
	}
	return Hex(n.Uint64()+1, max)
}

// RandomVPCAttachment returns a random 16-bit attachment identifier in hex.
func RandomVPCAttachment() (string, error) {
	return Random(MaxVPCAttachment)
}

// HexToBase62 converts a hex identifier to the base62 form the CNI chain reads.
func HexToBase62(value string) (string, error) {
	return baseconv.Convert(strings.ToLower(value), baseconv.DigitsHex, baseconv.Digits62)
}

// Base62ToHex converts a base62 identifier back to lowercase hex.
func Base62ToHex(value string) (string, error) {
	return baseconv.Convert(value, baseconv.Digits62, baseconv.DigitsHex)
}

// VPCBase62 renders a VPC identifier in base62, with the reserved-value guards
// and the width that keeps a kernel interface name inside fifteen characters.
func VPCBase62(value uint64) (string, error) {
	hex, err := Hex(value, MaxVPC)
	if err != nil {
		return "", err
	}
	return HexToBase62(hex)
}

// RandomVPCAttachmentBase62 returns a random attachment identifier in base62.
func RandomVPCAttachmentBase62() (string, error) {
	hex, err := RandomVPCAttachment()
	if err != nil {
		return "", err
	}
	return HexToBase62(hex)
}
