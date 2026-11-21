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

// ProviderSchedulingConfig scopes rollout of the unified request scheduler.
type ProviderSchedulingConfig struct {
	Mode          string   `yaml:"mode,omitempty" json:"mode,omitempty"`
	Models        []string `yaml:"models,omitempty" json:"models,omitempty"`
	Callers       []string `yaml:"callers,omitempty" json:"callers,omitempty"`
	MaxActiveWait string   `yaml:"max-active-wait,omitempty" json:"max-active-wait,omitempty"`
}

// ProviderSchedulingMode evaluates the model and the authenticated caller against rollout scope.
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
