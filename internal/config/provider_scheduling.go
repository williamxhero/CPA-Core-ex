package config

import (
	"slices"
	"strings"
	"time"
)

const (
	ProviderSchedulingOff     = "off"
	ProviderSchedulingShadow  = "shadow"
	ProviderSchedulingEnforce = "enforce"

	defaultProviderSchedulingWait = 3 * time.Second
)

// ProviderSchedulingResource defines a trusted funding classification and slot cap.
type ProviderSchedulingResource struct {
	Funding       string `yaml:"funding,omitempty" json:"funding,omitempty"`
	MaxConcurrent int    `yaml:"max-concurrent,omitempty" json:"max-concurrent,omitempty"`
}

// ProviderSchedulingConfig scopes rollout of the unified request scheduler.
type ProviderSchedulingConfig struct {
	Resources             map[string]ProviderSchedulingResource `yaml:"resources,omitempty" json:"resources,omitempty"`
	AllowedFunding        []string                              `yaml:"allowed-funding,omitempty" json:"allowed-funding,omitempty"`
	CallerFunding         map[string][]string                   `yaml:"caller-funding,omitempty" json:"caller-funding,omitempty"`
	Mode                  string                                `yaml:"mode,omitempty" json:"mode,omitempty"`
	Models                []string                              `yaml:"models,omitempty" json:"models,omitempty"`
	Callers               []string                              `yaml:"callers,omitempty" json:"callers,omitempty"`
	MaxActiveWait         string                                `yaml:"max-active-wait,omitempty" json:"max-active-wait,omitempty"`
	PersistentRetryModels []string                              `yaml:"persistent-retry-models,omitempty" json:"persistent-retry-models,omitempty"`
}

// ProviderSchedulingMode matches the public model and opaque authenticated caller reference against rollout scope.
func (c *Config) ProviderSchedulingMode(model, caller string) string {
	if c == nil {
		return ProviderSchedulingOff
	}
	rollout := c.Routing.ProviderScheduling
	mode := strings.ToLower(strings.TrimSpace(rollout.Mode))
	if mode != ProviderSchedulingEnforce && mode != ProviderSchedulingShadow {
		return ProviderSchedulingOff
	}
	if len(rollout.Models) > 0 && !slices.Contains(rollout.Models, model) {
		return ProviderSchedulingOff
	}
	if len(rollout.Callers) > 0 && (caller == "" || !slices.Contains(rollout.Callers, caller)) {
		return ProviderSchedulingOff
	}
	return mode
}

// ProviderSchedulingWait caps cumulative deliberate waiting, independently of inference duration.
func (c *Config) ProviderSchedulingWait() time.Duration {
	if c == nil || c.Routing.ProviderScheduling.MaxActiveWait == "" {
		return defaultProviderSchedulingWait
	}
	d, err := time.ParseDuration(strings.TrimSpace(c.Routing.ProviderScheduling.MaxActiveWait))
	if err != nil || d < 0 {
		return 0
	}
	return d
}
