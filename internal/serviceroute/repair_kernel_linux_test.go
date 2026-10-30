//go:build linux

// Copyright 2026 Datum Cloud, Inc.
// SPDX-License-Identifier: AGPL-3.0-or-later

package serviceroute

import (
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func TestInterfaceChurnKernelContinuity(t *testing.T) {
	const transientDevice = "transient"
	lab := newSpreadLab(t)
	stable := lab.apply(t, nil, spreadProducer("p1", false), spreadProducer("p2", false))
	identities, err := ebpf.LoadPinnedMap(filepath.Join(lab.programmer.PinDir, "attachment_identity_table"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = identities.Close() }()
	create := func() error {
		link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: transientDevice}}
		if err := netlink.LinkAdd(link); err != nil {
			return err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
		return identities.Put(uint32(link.Index), uint64(link.Index))
	}
	mustInNS(t, lab.node, create)
	changing := stable
	changing.Attachment.Name = transientDevice
	changing.ConsumerDevice = transientDevice
	mustInNS(t, lab.node, func() error { return lab.programmer.Apply(changing) })
	udp := lab.udpClient(t)
	lab.waitReady(t, udp)
	tcp := lab.tcpClient(t)
	var count, failures, slow atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, query := range []func(string) (string, error){udp.query, tcp.query} {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				start := time.Now()
				_, err := query(fmt.Sprintf("churn%d", i))
				count.Add(1)
				if err != nil {
					failures.Add(1)
				}
				if time.Since(start) >= time.Second {
					slow.Add(1)
				}
			}
		})
	}
	// Register cleanup before mutating topology so a failing setup never leaves
	// query goroutines accessing sockets after the test finishes.
	var once sync.Once
	finish := func() { once.Do(func() { close(stop) }); wg.Wait() }
	defer finish()
	time.Sleep(20 * time.Millisecond)
	for range 40 {
		mustInNS(t, lab.node, func() error {
			link, err := netlink.LinkByName(transientDevice)
			if err != nil {
				return err
			}
			if err := netlink.LinkDel(link); err != nil {
				return err
			}
			if err := lab.programmer.Initialize(); err != nil {
				return err
			}
			if err := create(); err != nil {
				return err
			}
			return lab.programmer.Initialize()
		})
	}
	time.Sleep(20 * time.Millisecond)
	finish()
	t.Logf("queries=%d failures=%d responses>=1s=%d during 40 unrelated interface replacements",
		count.Load(), failures.Load(), slow.Load())
	if count.Load() == 0 || failures.Load() != 0 || slow.Load() != 0 {
		t.Fatal("unrelated service traffic interrupted")
	}
}
