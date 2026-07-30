// Copyright 2025 Datum Cloud, Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// --- Webhook defaults --------------------------------------------------

const (
	DefaultWebhookPort          = 9443 // matches controller-runtime's webhook.Server default
	DefaultWebhookMetricsPort   = 8080
	DefaultWebhookHealthPort    = 8081
	DefaultWebhookCertDir       = "/etc/webhook/certs" // populated by the cert-manager-issued Secret volume mount
	DefaultWebhookMTU           = 1500
	DefaultWebhookInterfaceType = "veth"
)

// --- Webhook environment variable keys -----------------------------------

const (
	EnvWebhookPort          = "GALACTIC_WEBHOOK_PORT"
	EnvWebhookMetricsPort   = "GALACTIC_WEBHOOK_METRICS_PORT"
	EnvWebhookHealthPort    = "GALACTIC_WEBHOOK_HEALTH_PORT"
	EnvWebhookCertDir       = "GALACTIC_WEBHOOK_CERT_DIR"
	EnvWebhookMTU           = "GALACTIC_WEBHOOK_MTU"
	EnvWebhookInterfaceType = "GALACTIC_WEBHOOK_INTERFACE_TYPE"
)

// WebhookConfig resolves galactic-webhook configuration with three-tier
// precedence: CLI flag > env var > compiled-in default. Create once via
// NewWebhookConfig(), call BindFlags() to layer CLI flags, then read the
// exported fields.
type WebhookConfig struct {
	v      *viper.Viper
	prefix string

	// Resolved fields.
	Port          int
	MetricsPort   int
	HealthPort    int
	CertDir       string
	MTU           int
	InterfaceType string
}

// NewWebhookConfig creates a webhook config resolver with the
// GALACTIC_WEBHOOK env prefix and AutomaticEnv enabled.
func NewWebhookConfig() *WebhookConfig {
	v := viper.New()
	v.SetEnvPrefix("GALACTIC_WEBHOOK")
	v.AutomaticEnv()

	v.SetDefault("port", DefaultWebhookPort)
	v.SetDefault("metrics_port", DefaultWebhookMetricsPort)
	v.SetDefault("health_port", DefaultWebhookHealthPort)
	v.SetDefault("cert_dir", DefaultWebhookCertDir)
	v.SetDefault("mtu", DefaultWebhookMTU)
	v.SetDefault("interface_type", DefaultWebhookInterfaceType)

	cfg := &WebhookConfig{
		v:      v,
		prefix: "GALACTIC_WEBHOOK",
	}
	cfg.readFields()
	return cfg
}

// BindFlags binds Cobra/pflag flags to the config resolver and re-reads the
// exported fields.
func (c *WebhookConfig) BindFlags(flags *pflag.FlagSet) {
	bindings := []struct {
		flag string
		key  string
	}{
		{"port", "port"},
		{"metrics-port", "metrics_port"},
		{"health-port", "health_port"},
		{"cert-dir", "cert_dir"},
		{"mtu", "mtu"},
		{"interface-type", "interface_type"},
	}
	for _, b := range bindings {
		if flags.Changed(b.flag) {
			c.v.Set(b.key, flags.Lookup(b.flag).Value.String())
		} else {
			//nolint:errcheck // controlled keys, BindPFlag cannot fail here
			c.v.BindPFlag(b.key, flags.Lookup(b.flag))
		}
	}
	c.readFields()
}

// readFields populates the exported fields from the current Viper state.
func (c *WebhookConfig) readFields() {
	c.Port = c.v.GetInt("port")
	c.MetricsPort = c.v.GetInt("metrics_port")
	c.HealthPort = c.v.GetInt("health_port")
	c.CertDir = c.v.GetString("cert_dir")
	c.MTU = c.v.GetInt("mtu")
	c.InterfaceType = c.v.GetString("interface_type")
}

// Validate checks that the required configuration fields are set and valid.
func (c *WebhookConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("webhook port must be between 1 and 65535")
	}
	if c.MetricsPort < 1 || c.MetricsPort > 65535 {
		return errors.New("metrics port must be between 1 and 65535")
	}
	if c.HealthPort < 1 || c.HealthPort > 65535 {
		return errors.New("health port must be between 1 and 65535")
	}
	if c.CertDir == "" {
		return errors.New("cert dir must not be empty")
	}
	switch c.InterfaceType {
	case "veth", "tap":
	default:
		return errors.New("interface type must be \"veth\" or \"tap\"")
	}
	return nil
}
