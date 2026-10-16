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

package leaderelection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

type remoteAddrRecorder struct {
	mu    sync.Mutex
	addrs []string
}

func (r *remoteAddrRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.addrs = append(r.addrs, req.RemoteAddr)
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{}`))
}

func (r *remoteAddrRecorder) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.addrs[len(r.addrs)-1]
}

func restClientFor(t *testing.T, cfg *rest.Config) *rest.RESTClient {
	t.Helper()
	cfg = rest.CopyConfig(cfg)
	cfg.GroupVersion = &schema.GroupVersion{Group: "coordination.k8s.io", Version: "v1"}
	cfg.APIPath = "/apis"
	cfg.NegotiatedSerializer = clientgoscheme.Codecs.WithoutConversion()
	c, err := rest.RESTClientFor(cfg)
	if err != nil {
		t.Fatalf("building REST client: %v", err)
	}
	return c
}

func getLease(ctx context.Context, c *rest.RESTClient) error {
	return c.Get().Namespace("default").Resource("leases").Name("lease").Do(ctx).Error()
}

func TestLeaderElectionRestConfigDoesNotMutateBase(t *testing.T) {
	limiter := flowcontrol.NewTokenBucketRateLimiter(1, 1)
	base := &rest.Config{Host: "https://example.invalid", QPS: 50, Burst: 100, RateLimiter: limiter}

	cfg := RestConfig(base)

	if cfg.RateLimiter != nil {
		t.Errorf("leader election config reuses the base rate limiter")
	}
	if cfg.QPS != QPS || cfg.Burst != Burst {
		t.Errorf("got QPS %v Burst %d, want %v and %d", cfg.QPS, cfg.Burst, QPS, Burst)
	}
	if cfg.Dial == nil {
		t.Errorf("leader election config has no dialer of its own")
	}
	if base.RateLimiter != limiter || base.QPS != 50 || base.Burst != 100 || base.Dial != nil {
		t.Errorf("base config was mutated: %+v", base)
	}
}

func TestLeaderElectionIgnoresSaturatedMainLimiter(t *testing.T) {
	srv := httptest.NewServer(&remoteAddrRecorder{})
	defer srv.Close()

	base := &rest.Config{
		Host:        srv.URL,
		RateLimiter: flowcontrol.NewTokenBucketRateLimiter(0.001, 1),
	}
	mainClient := restClientFor(t, base)

	if err := getLease(context.Background(), mainClient); err != nil {
		t.Fatalf("first request on main client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := getLease(ctx, mainClient); err == nil {
		t.Fatalf("expected the main client to be throttled")
	}

	leaderClient := restClientFor(t, RestConfig(base))
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := getLease(ctx, leaderClient); err != nil {
		t.Fatalf("leader election request was throttled by the main limiter: %v", err)
	}
}

func TestLeaderElectionUsesItsOwnConnection(t *testing.T) {
	rec := &remoteAddrRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	base := &rest.Config{Host: srv.URL, QPS: -1}
	mainClient := restClientFor(t, base)
	ctx := context.Background()

	if err := getLease(ctx, mainClient); err != nil {
		t.Fatalf("main client request: %v", err)
	}
	mainAddr := rec.last()

	if err := getLease(ctx, restClientFor(t, base)); err != nil {
		t.Fatalf("second main client request: %v", err)
	}
	if rec.last() != mainAddr {
		t.Fatalf("clients built from the same config did not share a connection, so this test cannot tell connections apart")
	}

	if err := getLease(ctx, restClientFor(t, RestConfig(base))); err != nil {
		t.Fatalf("leader election request: %v", err)
	}
	if rec.last() == mainAddr {
		t.Errorf("leader election reused the main client's connection %s", mainAddr)
	}
}
