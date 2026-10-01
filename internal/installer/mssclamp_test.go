// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package installer

import (
	"errors"
	"testing"

	"go.datum.net/galactic/internal/config"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
)

type fakeMSSClampTable struct {
	puts []prog.UsidMssClampValue
	err  error
}

func (f *fakeMSSClampTable) Put(_, value any) error {
	if f.err != nil {
		return f.err
	}
	f.puts = append(f.puts, value.(prog.UsidMssClampValue))
	return nil
}

// TestMSSClampState_ReadsSetting checks the environment setting reaches the
// map: a fixed MTU writes that MTU's values, and "off" writes zero.
func TestMSSClampState_ReadsSetting(t *testing.T) {
	for setting, want := range map[string]prog.UsidMssClampValue{
		"1496": {MssIpv4: 1416, MssIpv6: 1396},
		"off":  {},
	} {
		t.Run(setting, func(t *testing.T) {
			t.Setenv(config.EnvCNITCPMSSClamp, setting)
			var table fakeMSSClampTable
			newMSSClampState(&table).reconcile()
			if len(table.puts) != 1 || table.puts[0] != want {
				t.Errorf("%s=%q wrote %v, want exactly [%+v]", config.EnvCNITCPMSSClamp, setting, table.puts, want)
			}
		})
	}
}

// TestMSSClampState_InvalidSettingWritesNothing checks a typo in the setting
// leaves the map alone, rather than writing a guess. The datapath then keeps
// clamping off, its behavior before the clamp existed.
func TestMSSClampState_InvalidSettingWritesNothing(t *testing.T) {
	t.Setenv(config.EnvCNITCPMSSClamp, "1500b")
	var table fakeMSSClampTable
	s := newMSSClampState(&table)
	s.reconcile()
	s.reconcile()
	if len(table.puts) != 0 {
		t.Errorf("invalid setting wrote %v, want nothing", table.puts)
	}
	if s.lastErr == "" {
		t.Error("lastErr is empty after a failed reconcile, want the error recorded so it is logged once")
	}
}

// TestMSSClampState_RecoversAfterWriteFailure checks a failure clears once a
// later tick succeeds.
func TestMSSClampState_RecoversAfterWriteFailure(t *testing.T) {
	t.Setenv(config.EnvCNITCPMSSClamp, "1500")
	table := fakeMSSClampTable{err: errors.New("map closed")}
	s := newMSSClampState(&table)
	s.reconcile()
	table.err = nil
	s.reconcile()
	if len(table.puts) != 1 || s.lastErr != "" {
		t.Errorf("after recovery: %d puts, lastErr %q; want one put and the error cleared", len(table.puts), s.lastErr)
	}
}

// TestMSSClampState_NilIsInert covers Run with a test-fake datapath, which
// leaves the state nil. The health tick still calls reconcile on it.
func TestMSSClampState_NilIsInert(t *testing.T) {
	var s *mssClampState
	s.reconcile() // must not panic
}
