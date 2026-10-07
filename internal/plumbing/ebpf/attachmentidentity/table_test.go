// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package attachmentidentity

import (
	"bytes"
	"errors"
	"testing"
)

func TestRotateSkipsZeroAndStoresNonzeroToken(t *testing.T) {
	original := randomReader
	t.Cleanup(func() { randomReader = original })
	randomReader = bytes.NewReader([]byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		8, 7, 6, 5, 4, 3, 2, 1,
	})
	table := &testTable{}
	token, err := Rotate(table, 42)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if token != 0x0102030405060708 {
		t.Fatalf("token = %#x, want %#x", token, uint64(0x0102030405060708))
	}
	if table.key != uint32(42) || table.value != token {
		t.Fatalf("Put(%v, %v), want (42, %v)", table.key, table.value, token)
	}
}

func TestRotatePropagatesRandomAndPutErrors(t *testing.T) {
	original := randomReader
	t.Cleanup(func() { randomReader = original })
	wantRandom := errors.New("random failed")
	randomReader = errorReader{wantRandom}
	if _, err := Rotate(&testTable{}, 1); !errors.Is(err, wantRandom) {
		t.Fatalf("Rotate random error = %v, want %v", err, wantRandom)
	}

	randomReader = bytes.NewReader([]byte{1, 0, 0, 0, 0, 0, 0, 0})
	wantPut := errors.New("put failed")
	if _, err := Rotate(&testTable{putErr: wantPut}, 1); !errors.Is(err, wantPut) {
		t.Fatalf("Rotate put error = %v, want %v", err, wantPut)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type testTable struct {
	key    any
	value  any
	putErr error
}

func (t *testTable) Put(key, value any) error { t.key, t.value = key, value; return t.putErr }
