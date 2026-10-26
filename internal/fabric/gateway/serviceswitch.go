// Copyright 2026 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package gateway

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ServiceSwitchKey is the key of the service ConfigMap that turns Looking
// Glass execution on: only ServiceSwitchEnabled does.
const (
	ServiceSwitchKey      = "service"
	ServiceSwitchEnabled  = "enabled"
	ServiceSwitchDisabled = "disabled"
)

// ServiceSwitchInterval is how often Watch reads the service ConfigMap, and
// so how soon a change takes effect.
const ServiceSwitchInterval = time.Second

// serviceSwitchReadTimeout bounds one read of the service ConfigMap.
const serviceSwitchReadTimeout = time.Second

// errServiceDisabled is the cause with which a service request's execution
// is cancelled when the service is turned off.
var errServiceDisabled = errors.New("the Looking Glass service was disabled")

// ServiceSwitch turns Looking Glass service execution on and off while the
// gateway runs. Its zero value is off. Turning it off cancels the context
// State handed every running request, so their routers stop; turning it
// back on admits new requests and resumes nothing. It never touches
// operator or FabricQuery work, or the limiter's state.
type ServiceSwitch struct {
	mu     sync.Mutex
	on     bool
	ctx    context.Context
	cancel context.CancelCauseFunc
}

// State reports whether the service executes and, when it does, a context
// that ends when it is turned off. A nil switch is off.
func (w *ServiceSwitch) State() (bool, context.Context) {
	if w == nil {
		return false, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.on, w.ctx
}

// Set turns the service on or off.
func (w *ServiceSwitch) Set(on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if on == w.on {
		return
	}
	w.on = on
	if on {
		w.ctx, w.cancel = context.WithCancelCause(context.Background())
	} else {
		w.cancel(errServiceDisabled)
		w.ctx, w.cancel = nil, nil
	}
	slog.Info("Looking Glass service execution switched", "enabled", on)
}

// Watch reads key ServiceSwitchKey of ConfigMap namespace/name with reader,
// which should read uncached, every interval until ctx ends, and sets the
// switch from it. The service is on only while the read succeeds and the key
// is exactly ServiceSwitchEnabled: a missing ConfigMap or key, the value
// ServiceSwitchDisabled, a failed read or any other value turns it off,
// the last two with a warning when the problem first appears. It turns the
// service off when ctx ends.
func (w *ServiceSwitch) Watch(ctx context.Context, reader client.Reader, namespace, name string,
	interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var last string
	for {
		on, problem := readServiceSwitch(ctx, reader, namespace, name)
		if ctx.Err() != nil {
			w.Set(false)
			return
		}
		if problem != "" && problem != last {
			slog.Warn("Looking Glass execution is off: "+problem, "configmap", name, "key", ServiceSwitchKey)
		}
		last = problem
		w.Set(on)
		select {
		case <-ctx.Done():
			w.Set(false)
			return
		case <-t.C:
		}
	}
}

// readServiceSwitch reads the switch's ConfigMap and reports whether it
// turns the service on, and what is wrong with it when it cannot be read or
// holds an invalid value.
func readServiceSwitch(ctx context.Context, reader client.Reader, namespace, name string) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, serviceSwitchReadTimeout)
	defer cancel()
	var cm corev1.ConfigMap
	if err := reader.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return false, ""
		}
		return false, "the service ConfigMap could not be read"
	}
	switch cm.Data[ServiceSwitchKey] {
	case ServiceSwitchEnabled:
		return true, ""
	case ServiceSwitchDisabled, "":
		return false, ""
	}
	return false, "the service ConfigMap's value is neither " + ServiceSwitchEnabled + " nor " + ServiceSwitchDisabled
}
