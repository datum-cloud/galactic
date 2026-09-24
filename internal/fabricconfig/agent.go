// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package fabricconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/events"
)

// Event reasons the agent raises, on the source ConfigMap when there is one
// and on the agent's own Pod otherwise.
const (
	ReasonApplied          = "Applied"
	ReasonRejected         = "Rejected"
	ReasonReloadFailed     = "ReloadFailed"
	ReasonConfigMissing    = "ConfigMissing"
	ReasonRestartRequired  = "RestartRequired"
	ReasonDeprecatedSource = "DeprecatedConfigSource"
)

const (
	defaultRetryInterval    = 10 * time.Second
	defaultMaxRetryInterval = 30 * time.Second

	// maxNoteLen keeps an event note within the events API's 1 KiB limit.
	maxNoteLen = 1000
)

// errRejected marks a configuration that failed validation. Retrying it
// cannot succeed until the ConfigMap changes.
var errRejected = errors.New("configuration rejected")

// Agent installs and maintains one node's FRR configuration.
type Agent struct {
	// Client reads ConfigMaps.
	Client kubernetes.Interface
	// Recorder emits events. Nil disables events.
	Recorder events.EventRecorder
	// FRR validates and applies configuration.
	FRR FRR

	// Namespace holds the configuration ConfigMaps.
	Namespace string
	// NodeName is the node whose configuration is installed.
	NodeName string
	// Pod is the agent's own Pod, the subject of events that have no source
	// ConfigMap. Nil disables those events.
	Pod *corev1.Pod
	// LegacyConfigMap names the shared legacy ConfigMap consulted when the
	// node has no ConfigMap of its own. Empty disables the fallback.
	LegacyConfigMap string

	// ConfigDir is the FRR configuration directory.
	ConfigDir string
	// DefaultsDir holds the image's default daemons and vtysh.conf.
	DefaultsDir string

	// RetryInterval is the initial delay before retrying a failed attempt;
	// MaxRetryInterval caps its exponential growth. Zero selects defaults.
	RetryInterval    time.Duration
	MaxRetryInterval time.Duration

	// applied holds the contents of each file last written to ConfigDir.
	applied map[string]string
	// rejected is the hash of the last frr.conf that failed validation.
	rejected string
	// reported is the hash of the frr.conf last reported as running.
	reported string
	// lastWarning is the last warning emitted, to avoid repeating it.
	lastWarning string
	// warnedLegacy records that the deprecated-source warning was emitted.
	warnedLegacy bool
}

// Init waits until configuration for the node exists and validates, then
// writes it to ConfigDir alongside the image defaults for any file the
// configuration does not override. It retries missing or invalid
// configuration and transient API errors until ctx is done, and returns an
// error only when ctx ends or the configuration directory cannot be written.
func (a *Agent) Init(ctx context.Context) error {
	delay := a.retryInterval()
	for {
		err := a.initOnce(ctx)
		if err == nil {
			return nil
		}
		if !retryable(err) {
			return err
		}
		slog.Warn("fabric-router configuration not installed yet; retrying", "error", err, "retryIn", delay)
		select {
		case <-ctx.Done():
			return fmt.Errorf("install configuration: %w", errors.Join(ctx.Err(), err))
		case <-time.After(delay):
		}
		delay = min(delay*2, a.maxRetryInterval())
	}
}

// initOnce makes a single attempt to fetch, validate and install the node's
// configuration.
func (a *Agent) initOnce(ctx context.Context) error {
	perNode, err := a.get(ctx, ConfigMapName(a.NodeName))
	if err != nil {
		return err
	}
	var legacy *corev1.ConfigMap
	if perNode == nil && a.LegacyConfigMap != "" {
		if legacy, err = a.get(ctx, a.LegacyConfigMap); err != nil {
			return err
		}
	}
	src, err := a.resolve(perNode, legacy)
	if err != nil {
		return err
	}

	if err := seedDefaults(a.DefaultsDir, a.ConfigDir, src.Files); err != nil {
		return fatal(err)
	}
	for _, k := range []string{KeyDaemons, KeyVtyshConf} {
		if v, ok := src.Files[k]; ok {
			if err := writeFile(a.ConfigDir, k, v); err != nil {
				return fatal(err)
			}
		}
	}
	if err := a.stage(ctx, src); err != nil {
		return err
	}
	if err := a.promote(); err != nil {
		return fatal(err)
	}
	// No Applied event here: this process exits right after, before the
	// asynchronous event sink would deliver it. Watch reports the running
	// configuration's hash once it starts.
	slog.Info("installed fabric-router configuration",
		"configMap", src.ConfigMap.Name, "hash", Hash(src.Files[KeyFRRConf]))
	return nil
}

// Watch keeps the running FRR configuration converged on the node's
// ConfigMap until ctx is done. A validated change to frr.conf is applied with
// Reload and only then written to ConfigDir; an invalid one leaves the running
// configuration untouched. Missing configuration also leaves it untouched.
// Watch returns nil when ctx ends, and an error only when the ConfigMap
// informers fail to sync.
func (a *Agent) Watch(ctx context.Context) error {
	if err := a.loadApplied(); err != nil {
		return err
	}

	trigger := make(chan struct{}, 1)
	nudge := func() {
		select {
		case trigger <- struct{}{}:
		default:
		}
	}
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { nudge() },
		UpdateFunc: func(any, any) { nudge() },
		DeleteFunc: func(any) { nudge() },
	}

	perNode, err := a.startInformer(ctx, ConfigMapName(a.NodeName), handler)
	if err != nil {
		return err
	}
	var legacy cache.Store
	if a.LegacyConfigMap != "" {
		if legacy, err = a.startInformer(ctx, a.LegacyConfigMap, handler); err != nil {
			return err
		}
	}
	slog.Info("watching fabric-router configuration", "configMap", ConfigMapName(a.NodeName))

	delay := a.retryInterval()
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
		case <-retry:
		}
		retry = nil
		err := a.converge(ctx, a.fromStore(perNode, ConfigMapName(a.NodeName)), a.fromStore(legacy, a.LegacyConfigMap))
		if err != nil {
			slog.Error("could not apply fabric-router configuration; retrying", "error", err, "retryIn", delay)
			retry = time.After(delay)
			delay = min(delay*2, a.maxRetryInterval())
			continue
		}
		delay = a.retryInterval()
	}
}

// converge brings ConfigDir and the running FRR instance in line with the
// configuration resolved from perNode and legacy. It returns an error only for
// failures worth retrying without a ConfigMap change: a failed reload or a
// failed file write.
func (a *Agent) converge(ctx context.Context, perNode, legacy *corev1.ConfigMap) error {
	src, err := a.resolve(perNode, legacy)
	if err != nil {
		// Already reported by resolve. The running configuration stays.
		return nil
	}

	for _, k := range []string{KeyDaemons, KeyVtyshConf} {
		want, err := a.desiredAuxFile(src, k)
		if err != nil {
			return err
		}
		if want == a.applied[k] {
			continue
		}
		if err := writeFile(a.ConfigDir, k, want); err != nil {
			return err
		}
		a.applied[k] = want
		if k == KeyDaemons {
			a.event(src.ConfigMap, corev1.EventTypeWarning, ReasonRestartRequired, "Apply",
				"%s changed on node %s; it takes effect only when the fabric-router pod restarts",
				KeyDaemons, a.NodeName)
		}
	}

	want := src.Files[KeyFRRConf]
	hash := Hash(want)
	if want == a.applied[KeyFRRConf] {
		a.rejected = ""
		if a.reported != hash {
			a.reported = hash
			a.event(src.ConfigMap, corev1.EventTypeNormal, ReasonApplied, "Report",
				"running %s %s on node %s", KeyFRRConf, hash, a.NodeName)
		}
		return nil
	}
	if hash == a.rejected {
		return nil
	}
	if err := a.stage(ctx, src); err != nil {
		if errors.Is(err, errRejected) {
			a.rejected = hash
			return nil
		}
		return err
	}
	if err := a.FRR.Reload(ctx, filepath.Join(a.ConfigDir, candidateName)); err != nil {
		a.event(src.ConfigMap, corev1.EventTypeWarning, ReasonReloadFailed, "Reload",
			"could not reload %s %s on node %s: %v", KeyFRRConf, hash, a.NodeName, err)
		return fmt.Errorf("reload %s %s: %w", KeyFRRConf, hash, err)
	}
	if err := a.promote(); err != nil {
		return err
	}
	a.applied[KeyFRRConf] = want
	a.reported = hash
	a.rejected = ""
	a.lastWarning = ""
	a.event(src.ConfigMap, corev1.EventTypeNormal, ReasonApplied, "Reload",
		"applied %s %s on node %s", KeyFRRConf, hash, a.NodeName)
	slog.Info("applied fabric-router configuration", "configMap", src.ConfigMap.Name, "hash", hash)
	return nil
}

// resolve resolves the node's configuration and reports a missing, invalid or
// deprecated source as an event. Its errors wrap ErrNotFound or ErrInvalid.
func (a *Agent) resolve(perNode, legacy *corev1.ConfigMap) (*Source, error) {
	src, err := Resolve(a.NodeName, perNode, legacy)
	switch {
	case errors.Is(err, ErrNotFound):
		a.warn(a.podObject(), ReasonConfigMissing, "Resolve", "%v", err)
		return nil, err
	case errors.Is(err, ErrInvalid):
		a.warn(perNode, ReasonRejected, "Resolve", "%v", err)
		return nil, err
	case err != nil:
		return nil, err
	}
	if src.Legacy && !a.warnedLegacy {
		a.warnedLegacy = true
		a.event(a.podObject(), corev1.EventTypeWarning, ReasonDeprecatedSource, "Resolve",
			"node %s is configured from key %s%s of the shared ConfigMap %s; move it to its own ConfigMap %s",
			a.NodeName, legacyFRRConfKeyPrefix, a.NodeName, src.ConfigMap.Name, ConfigMapName(a.NodeName))
	}
	return src, nil
}

// stage writes src's frr.conf to the candidate file and validates it. On a
// validation failure it removes the candidate, reports it, and returns an
// error wrapping errRejected.
func (a *Agent) stage(ctx context.Context, src *Source) error {
	conf := src.Files[KeyFRRConf]
	if err := writeFile(a.ConfigDir, candidateName, conf); err != nil {
		return fatal(err)
	}
	if err := a.FRR.Check(ctx, filepath.Join(a.ConfigDir, candidateName)); err != nil {
		_ = os.Remove(filepath.Join(a.ConfigDir, candidateName))
		a.warn(src.ConfigMap, ReasonRejected, "Validate", "%s %s for node %s failed validation: %v",
			KeyFRRConf, Hash(conf), a.NodeName, err)
		return fmt.Errorf("%w: %w", errRejected, err)
	}
	return nil
}

// promote renames the validated candidate over frr.conf.
func (a *Agent) promote() error {
	if err := os.Rename(filepath.Join(a.ConfigDir, candidateName), filepath.Join(a.ConfigDir, KeyFRRConf)); err != nil {
		return fmt.Errorf("rename %s into place: %w", KeyFRRConf, err)
	}
	return nil
}

// desiredAuxFile returns the contents file k should have: src's override when
// present, and otherwise the image default, so removing an override reverts
// to it.
func (a *Agent) desiredAuxFile(src *Source, k string) (string, error) {
	if v, ok := src.Files[k]; ok {
		return v, nil
	}
	return readFile(a.DefaultsDir, k)
}

// loadApplied records the files currently in ConfigDir as applied.
func (a *Agent) loadApplied() error {
	a.applied = make(map[string]string, len(knownKeys))
	for _, k := range knownKeys {
		v, err := readFile(a.ConfigDir, k)
		if err != nil {
			return err
		}
		a.applied[k] = v
	}
	return nil
}

// get returns the named ConfigMap, or nil when it does not exist.
func (a *Agent) get(ctx context.Context, name string) (*corev1.ConfigMap, error) {
	cm, err := a.Client.CoreV1().ConfigMaps(a.Namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get ConfigMap %s/%s: %w", a.Namespace, name, err)
	}
	return cm, nil
}

// startInformer starts an informer over the single named ConfigMap, waits for
// it to sync, and returns its store.
func (a *Agent) startInformer(ctx context.Context, name string, h cache.ResourceEventHandler) (cache.Store, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(a.Client, 0,
		informers.WithNamespace(a.Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("metadata.name", name).String()
		}))
	inf := factory.Core().V1().ConfigMaps().Informer()
	if _, err := inf.AddEventHandler(h); err != nil {
		return nil, fmt.Errorf("add event handler for ConfigMap %s: %w", name, err)
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.HasSynced) {
		return nil, fmt.Errorf("sync informer for ConfigMap %s/%s", a.Namespace, name)
	}
	return inf.GetStore(), nil
}

// fromStore returns the named ConfigMap from store, or nil when store is nil
// or does not hold it.
func (a *Agent) fromStore(store cache.Store, name string) *corev1.ConfigMap {
	if store == nil {
		return nil
	}
	obj, ok, err := store.GetByKey(a.Namespace + "/" + name)
	if err != nil || !ok {
		return nil
	}
	cm, _ := obj.(*corev1.ConfigMap)
	return cm
}

// warn emits a warning event unless it repeats the previous warning.
func (a *Agent) warn(regarding runtime.Object, reason, action, format string, args ...any) {
	note := fmt.Sprintf(format, args...)
	if note == a.lastWarning {
		return
	}
	a.lastWarning = note
	slog.Warn(note, "reason", reason)
	a.event(regarding, corev1.EventTypeWarning, reason, action, "%s", note)
}

// event emits an event regarding the given object, when both it and the
// recorder are set.
func (a *Agent) event(regarding runtime.Object, eventType, reason, action, format string, args ...any) {
	if a.Recorder == nil || isNil(regarding) {
		return
	}
	note := fmt.Sprintf(format, args...)
	if len(note) > maxNoteLen {
		note = note[:maxNoteLen]
	}
	a.Recorder.Eventf(regarding, nil, eventType, reason, action, "%s", note)
}

// podObject returns the agent's Pod as an event subject, or nil when unset.
func (a *Agent) podObject() runtime.Object {
	if a.Pod == nil {
		return nil
	}
	return a.Pod
}

func (a *Agent) retryInterval() time.Duration {
	if a.RetryInterval > 0 {
		return a.RetryInterval
	}
	return defaultRetryInterval
}

func (a *Agent) maxRetryInterval() time.Duration {
	if a.MaxRetryInterval > 0 {
		return a.MaxRetryInterval
	}
	return defaultMaxRetryInterval
}

// fatalError marks an error Init must not retry.
type fatalError struct{ err error }

func (e fatalError) Error() string { return e.err.Error() }
func (e fatalError) Unwrap() error { return e.err }

func fatal(err error) error { return fatalError{err: err} }

// retryable reports whether Init should retry after err.
func retryable(err error) bool {
	var f fatalError
	return !errors.As(err, &f)
}

// isNil reports whether obj is nil, including a typed nil pointer.
func isNil(obj runtime.Object) bool {
	switch o := obj.(type) {
	case nil:
		return true
	case *corev1.ConfigMap:
		return o == nil
	case *corev1.Pod:
		return o == nil
	}
	return false
}
