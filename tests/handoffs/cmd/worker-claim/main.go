// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command worker-claim requests, observes and releases one Galactic Worker
// claim, for lab checks of the Local and Fabric modules. It is test code: it
// runs inside a lab pod, as a service agent would, with a token bound to that
// pod.
//
// Usage:
//
//	worker-claim -node N -vpc V -attachment UID -handoff tap|veth_pair|routed_link|socket \
//	    -dest UID[,UID...] [-generation G] [-wait D] [-release]
//	worker-claim -hold D
//
// It prints the claim's last status snapshot as one line of JSON, after the
// status describes the generation and is Programmed, or once -wait passes.
// With -release it releases the claim at -generation and waits until Worker
// reports it released, printing Release's own answer when no snapshot follows.
// It exits 0 whatever the status says, and 1 only when it cannot reach Worker
// or Worker refuses the call.
//
// Worker withdraws a caller's claims once the caller has held no session for
// its lease, so a check that outlasts the lease runs -hold, which keeps one
// session of the caller open for D, or until it is stopped.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	workerv1alpha1 "go.datum.net/galactic/api/galactic/worker/v1alpha1"
	"go.datum.net/galactic/pkg/workerclient"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "worker-claim:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		socket     = flag.String("socket", workerv1alpha1.DefaultSocketPath, "Worker's socket")
		tokenFile  = flag.String("token-file", workerclient.DefaultTokenFile, "the pod's Worker token")
		node       = flag.String("node", "", "this node")
		vpc        = flag.String("vpc", "", "the claim's VPC, as its attachment's status records it")
		attachment = flag.String("attachment", "", "the claim's attachment UID")
		handoff    = flag.String("handoff", "tap", "tap, veth_pair, routed_link or socket")
		dests      = flag.String("dest", "", "comma-separated destination attachment UIDs")
		generation = flag.Uint64("generation", 1, "the claim generation")
		wait       = flag.Duration("wait", 60*time.Second, "how long to wait for the status to settle")
		release    = flag.Bool("release", false, "release the claim instead of requesting it")
		hold       = flag.Duration("hold", 0, "keep a session open this long, renewing the caller's claims")
	)
	flag.Parse()
	if *hold > 0 {
		return holdSession(*socket, *tokenFile, *hold)
	}
	h, ok := workerv1alpha1.Handoff_value["HANDOFF_"+strings.ToUpper(*handoff)]
	if !ok || *node == "" || *vpc == "" || *attachment == "" {
		return errors.New("-node, -vpc, -attachment and a known -handoff are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *wait+30*time.Second)
	defer cancel()
	c, err := workerclient.Dial(ctx, workerclient.Options{SocketPath: *socket, TokenFile: *tokenFile})
	if err != nil {
		return fmt.Errorf("dial Worker: %w", err)
	}
	defer c.Close() //nolint:errcheck // the claims outlive the session
	key := &workerv1alpha1.ClaimKey{Node: *node, Vpc: *vpc, AttachmentUid: *attachment}
	obs, err := c.Observe(ctx, key)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	var released *workerv1alpha1.ClaimStatus
	if *release {
		st, err := c.Release(ctx, key, *generation)
		if err != nil {
			return fmt.Errorf("release: %w", err)
		}
		released = st
		if released == nil {
			// No such claim: nothing is left to release.
			released = &workerv1alpha1.ClaimStatus{Key: key, Released: true}
		}
	} else {
		spec := &workerv1alpha1.ClaimSpec{Handoff: workerv1alpha1.Handoff(h)}
		for _, uid := range strings.Split(*dests, ",") {
			if uid = strings.TrimSpace(uid); uid != "" {
				spec.Destinations = append(spec.Destinations, &workerv1alpha1.Destination{
					Target: &workerv1alpha1.Destination_Attachment{Attachment: &workerv1alpha1.AttachmentRef{Uid: uid}}})
			}
		}
		if _, err := c.Request(ctx, key, *generation, spec); err != nil {
			return fmt.Errorf("request: %w", err)
		}
	}
	last := settle(ctx, obs, *generation, *release, *wait)
	if last == nil || (*release && !last.GetReleased()) {
		if released != nil {
			last = released
		}
	}
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(last)
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// holdSession keeps one session of the caller open for d, or until the
// process is stopped, and with it the caller's claims.
func holdSession(socket, tokenFile string, d time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	c, err := workerclient.Dial(ctx, workerclient.Options{SocketPath: socket, TokenFile: tokenFile})
	if err != nil {
		return fmt.Errorf("dial Worker: %w", err)
	}
	defer c.Close() //nolint:errcheck // the claims outlive the session
	fmt.Println("holding session", c.Session())
	<-ctx.Done()
	return nil
}

// settle returns the last snapshot once it describes generation and is
// Programmed, or released, or when wait passes.
func settle(ctx context.Context, obs *workerclient.Observer, generation uint64, release bool,
	wait time.Duration) *workerv1alpha1.ClaimStatus {
	deadline := time.Now().Add(wait)
	var last *workerv1alpha1.ClaimStatus
	got := make(chan *workerv1alpha1.ClaimStatus)
	go func() {
		defer close(got)
		for {
			st, err := obs.Recv()
			if err != nil {
				return
			}
			select {
			case got <- st:
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case st, ok := <-got:
			if !ok {
				return last
			}
			last = st
			if release && st.GetReleased() {
				return last
			}
			if !release && st.GetObservedGeneration() == generation && programmed(st) {
				// One more snapshot settles readiness when it follows soon.
				select {
				case st2, ok := <-got:
					if ok {
						last = st2
					}
				case <-time.After(3 * time.Second):
				}
				return last
			}
		case <-time.After(time.Until(deadline)):
			return last
		}
	}
}

func programmed(st *workerv1alpha1.ClaimStatus) bool {
	for _, c := range st.GetConditions() {
		if c.GetType() == workerv1alpha1.ConditionProgrammed {
			return c.GetStatus() == workerv1alpha1.ConditionStatus_CONDITION_STATUS_TRUE
		}
	}
	return false
}
