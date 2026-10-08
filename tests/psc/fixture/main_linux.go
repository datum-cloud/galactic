// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command psc-fixture runs the production service route
// reconciler against a real edge API and an isolated Linux packet fixture.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	cloudapi "go.datum.net/cloud/api/v1alpha1"
	"go.datum.net/galactic/internal/controller"
	"go.datum.net/galactic/internal/plumbing/ebpf/prog"
	"go.datum.net/galactic/internal/serviceroute"
	networkapi "go.datum.net/network/api/v1alpha1"
)

//go:embed relay.py query.py
var scripts embed.FS

type fixtureConfig struct {
	Role        string `json:"role"`
	NodeID      int32  `json:"nodeID"`
	Locator     string `json:"locator"`
	RouterName  string `json:"routerName"`
	PeerAddress string `json:"peerAddress"`
	PeerMAC     string `json:"peerMAC"`

	Kubeconfig string        `json:"kubeconfig"`
	Namespace  string        `json:"namespace"`
	NodeName   string        `json:"nodeName"`
	State      string        `json:"state"`
	Cases      []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Project            string `json:"project"`
	VPCName            string `json:"vpcName"`
	VPCUID             string `json:"vpcUID"`
	VPCIdentity        string `json:"vpcIdentity"`
	Destination        string `json:"destination"`
	ConsumerAttachment string `json:"consumerAttachment"`
	ProducerAttachment string `json:"producerAttachment"`
}

type fixture struct {
	objects *prog.UsidObjects
	block   uint64

	cfg                      fixtureConfig
	api                      client.Client
	scheme                   *runtime.Scheme
	labs                     []labState
	pinDir                   string
	mu                       sync.Mutex
	cancel                   context.CancelFunc
	done                     chan error
	reconciler               *controller.ServiceRoutePolicyReconciler
	running                  bool
	revision                 int
	cleanup                  []func()
	relayMu                  sync.Mutex
	destinations             map[string]bool
	rootSource, rootDevice   string
	producerNS, producerHost string
}

func main() {
	configPath := flag.String("config", "/runtime/psc-fixture.json", "fixture configuration JSON")
	flag.Parse()
	if err := run(*configPath); err != nil {
		log.Fatal(err)
	}
}

func run(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f := &fixture{destinations: make(map[string]bool)}
	if err := json.Unmarshal(raw, &f.cfg); err != nil {
		return err
	}
	if len(f.cfg.Cases) != 2 || f.cfg.NodeName == "" || f.cfg.Namespace == "" {
		return errors.New("two cases, namespace, and nodeName required")
	}
	if f.cfg.State == "" {
		f.cfg.State = "/runtime/psc-fixture-state.json"
	}
	if err := os.MkdirAll(filepath.Dir(f.cfg.State), 0755); err != nil {
		return err
	}
	for _, name := range []string{"relay.py", "query.py"} {
		data, err := scripts.ReadFile(name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(f.cfg.State), "psc-"+name), data, 0600); err != nil {
			return err
		}
	}
	f.scheme = runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, cloudapi.AddToScheme, networkapi.AddToScheme} {
		if err := add(f.scheme); err != nil {
			return err
		}
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", f.cfg.Kubeconfig)
	if err != nil {
		return err
	}
	cfg.QPS, cfg.Burst = 50, 100
	f.api, err = client.New(cfg, client.Options{Scheme: f.scheme})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer func() {
		cancel()
		f.close()
	}()
	if err := f.setupNetwork(ctx); err != nil {
		return err
	}
	if err := f.startController(ctx); err != nil {
		return err
	}
	// Keep retired destinations listening while testing authorization withdrawal.
	go f.followDestinations(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", f.handleStatus)
	mux.HandleFunc("/delay", f.handleDelay)
	for _, action := range []string{"pause", "resume", "restart", "reconcile"} {
		mux.HandleFunc("/"+action, f.handleControl(ctx, action))
	}
	httpServer := &http.Server{Addr: "127.0.0.1:18081", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = httpServer.Shutdown(context.Background()) }()
	log.Printf("fixture ready: state=%s control=%s", f.cfg.State, httpServer.Addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (f *fixture) startController(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.running {
		return nil
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", f.cfg.Kubeconfig)
	if err != nil {
		return err
	}
	cfg.QPS, cfg.Burst = 50, 100
	// The fixture fully stops each manager before replacing it in this process.
	skipNameValidation := true
	manager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: f.scheme, Metrics: server.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
		Controller: controllerconfig.Controller{SkipNameValidation: &skipNameValidation},
	})
	if err != nil {
		return err
	}
	programmer := &serviceroute.EBPFRouteProgrammer{PinDir: f.pinDir}
	if err := programmer.Initialize(); err != nil {
		return err
	}
	r := &controller.ServiceRoutePolicyReconciler{Client: manager.GetClient(), Scheme: f.scheme,
		NodeName: f.cfg.NodeName, BGPNamespace: f.cfg.Namespace, Programmer: programmer, FrontendEnabled: true}
	if err := r.SetupWithManager(manager); err != nil {
		return err
	}
	child, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- manager.Start(child) }()
	syncCtx, syncCancel := context.WithTimeout(child, 30*time.Second)
	defer syncCancel()
	if !manager.GetCache().WaitForCacheSync(syncCtx) {
		cancel()
		return errors.New("edge API cache failed to synchronize")
	}
	f.cancel, f.done, f.reconciler, f.running = cancel, done, r, true
	f.revision++
	return f.writeStateLocked()
}

func (f *fixture) pauseController() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running {
		return nil
	}
	f.cancel()
	select {
	case err := <-f.done:
		if err != nil {
			return err
		}
	case <-time.After(15 * time.Second):
		return errors.New("controller failed to stop")
	}
	f.running = false
	f.reconciler = nil
	return f.writeStateLocked()
}

func (f *fixture) reconcile(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.running {
		return errors.New("controller is paused")
	}
	policies := &networkapi.ServiceRoutePolicyList{}
	if err := f.api.List(ctx, policies, client.InNamespace(f.cfg.Namespace)); err != nil {
		return err
	}
	for _, policy := range policies.Items {
		request := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&policy)}
		if _, err := f.reconciler.Reconcile(ctx, request); err != nil {
			return err
		}
	}
	return nil
}

func (f *fixture) handleControl(ctx context.Context, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var err error
		switch action {
		case "pause":
			err = f.pauseController()
		case "resume":
			err = f.startController(ctx)
		case "restart":
			err = f.pauseController()
			if err == nil {
				err = f.startController(ctx)
			}
		case "reconcile":
			err = f.reconcile(r.Context())
		}
		if err != nil {
			log.Printf("controller control %s: %v", action, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.handleStatus(w, r)
	}
}

func (f *fixture) stateLocked() map[string]any {
	state := map[string]any{"nodeName": f.cfg.NodeName, "pinDir": f.pinDir, "running": f.running,
		"revision": f.revision, "pid": os.Getpid(), "labs": f.labs, "cases": f.labs, "producerNS": f.producerNS,
		"role":              f.cfg.Role,
		"fixtureAssistance": "Attachment lifecycle, VRF/CNI/SRv6 maps, BGP desired inputs and one-hop underlay",

		"readinessSource": "production ServiceRoutePolicyReconciler after kernel programming"}
	if f.objects != nil {
		maps := map[string]*ebpf.Map{"routes": f.objects.ServiceRouteTable, "remoteGrants": f.objects.ServiceRemoteGrantTable,
			"reverse": f.objects.ServiceReverseTable, "identities": f.objects.AttachmentIdentityTable}
		ids := map[string]uint32{}
		counts := map[string]int{}
		for name, kernelMap := range maps {
			info, err := kernelMap.Info()
			if err == nil {
				if id, ok := info.ID(); ok {
					ids[name] = uint32(id)
				}
			}
			key, value := make([]byte, kernelMap.KeySize()), make([]byte, kernelMap.ValueSize())
			iterator := kernelMap.Iterate()
			for iterator.Next(&key, &value) {
				counts[name]++
			}
			if err := iterator.Err(); err != nil {
				log.Printf("read fixture map %s: %v", name, err)
			}
		}
		state["mapIDs"], state["mapRows"] = ids, counts
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(f.cfg.State), "psc-delay-trace.json"))
	if err == nil {
		var trace map[string]any
		if err := json.Unmarshal(raw, &trace); err == nil {
			state["delayTrace"] = trace
		}
	}
	return state
}

func (f *fixture) writeStateLocked() error {
	raw, err := json.MarshalIndent(f.stateLocked(), "", "  ")
	if err != nil {
		return err
	}
	temp := f.cfg.State + ".tmp"
	if err := os.WriteFile(temp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(temp, f.cfg.State)
}

func (f *fixture) handleStatus(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(f.stateLocked()); err != nil {
		log.Printf("write fixture state: %v", err)
	}
}

func (f *fixture) close() {
	if err := f.pauseController(); err != nil {
		log.Printf("stop controller: %v", err)
	}
	f.relayMu.Lock()
	defer f.relayMu.Unlock()
	for i := len(f.cleanup) - 1; i >= 0; i-- {
		f.cleanup[i]()
	}
}

func (f *fixture) handleDelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var delay struct {
		Seconds float64 `json:"seconds"`
		Token   string  `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&delay); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if delay.Seconds <= 0 || delay.Seconds > 30 {
		http.Error(w, "seconds must be in (0,30]", http.StatusBadRequest)
		return
	}
	delay.Token = strconv.FormatInt(time.Now().UnixNano(), 10)
	raw, err := json.Marshal(delay)
	if err == nil {
		path := filepath.Join(filepath.Dir(f.cfg.State), "psc-delay.json")
		tracePath := filepath.Join(filepath.Dir(f.cfg.State), "psc-delay-trace.json")
		if removeErr := os.Remove(tracePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = removeErr
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		err = os.WriteFile(path+".tmp", raw, 0600)
		if err == nil {
			err = os.Rename(path+".tmp", path)
		}
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	state := f.stateLocked()
	state["delayToken"] = delay.Token
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(state); err != nil {
		log.Printf("write delay state: %v", err)
	}
}
