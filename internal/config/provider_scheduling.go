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
	PersistentRetry       PersistentRetryConfig                 `yaml:"persistent-retry,omitempty" json:"persistent-retry,omitempty"`
}

// PersistentRetryConfig changes only the enforced Codex HTTP SSE pilot.
type PersistentRetryConfig struct {
	ProbeBackoff        []string `yaml:"probe-backoff,omitempty" json:"probe-backoff,omitempty"`
	MinuteBackoff       string   `yaml:"minute-backoff,omitempty" json:"minute-backoff,omitempty"`
	LongBackoff         string   `yaml:"long-backoff,omitempty" json:"long-backoff,omitempty"`
	JitterPercent       *int     `yaml:"jitter-percent,omitempty" json:"jitter-percent,omitempty"`
	MaxWaiters          int      `yaml:"max-waiters,omitempty" json:"max-waiters,omitempty"`
	MaxWaitersPerCaller int      `yaml:"max-waiters-per-caller,omitempty" json:"max-waiters-per-caller,omitempty"`
}

const PersistentRetryMaxWaiters = 512

type PersistentRetryWaiterCapacity struct {
	Total     int `json:"total"`
	PerCaller int `json:"per_caller"`
}

func (c PersistentRetryConfig) WaiterCapacity() PersistentRetryWaiterCapacity {
	total, caller := c.MaxWaiters, c.MaxWaitersPerCaller
	if total <= 0 {
		total = 128
	}
	if caller <= 0 {
		caller = 16
	}
	total = min(total, PersistentRetryMaxWaiters)
	return PersistentRetryWaiterCapacity{Total: total, PerCaller: min(total, caller)}
}

// PersistentRetryCadence is the validated, effective policy exposed to admins.
type PersistentRetryCadence struct {
	ProbeBackoff  [4]string `json:"probe_backoff"`
	MinuteBackoff string    `json:"minute_backoff"`
	LongBackoff   string    `json:"long_backoff"`
	JitterPercent int       `json:"jitter_percent"`
}

func (c PersistentRetryConfig) Cadence() PersistentRetryCadence {
	p := PersistentRetryCadence{[4]string{"1s", "2s", "4s", "8s"}, "60s", "300s", 20}
	valid := func(s string) bool {
		d, err := time.ParseDuration(strings.TrimSpace(s))
		return err == nil && d > 0 && d <= 24*time.Hour
	}
	if len(c.ProbeBackoff) == len(p.ProbeBackoff) {
		for i, s := range c.ProbeBackoff {
			if valid(s) {
				p.ProbeBackoff[i] = strings.TrimSpace(s)
			}
		}
	}
	if valid(c.MinuteBackoff) {
		p.MinuteBackoff = strings.TrimSpace(c.MinuteBackoff)
	}
	if valid(c.LongBackoff) {
		p.LongBackoff = strings.TrimSpace(c.LongBackoff)
	}
	if c.JitterPercent != nil && *c.JitterPercent >= 0 && *c.JitterPercent <= 20 {
		p.JitterPercent = *c.JitterPercent
	}
	return p
}

// Delay returns the base interval and its tier for a real failure ordinal.
func (p PersistentRetryCadence) Delay(step int) (time.Duration, string) {
	var value, tier string
	switch {
	case step <= 4:
		value, tier = p.ProbeBackoff[max(1, step)-1], "short"
	case step <= 8:
		value, tier = p.MinuteBackoff, "minute"
	default:
		value, tier = p.LongBackoff, "long"
	}
	d, _ := time.ParseDuration(value)
	return d, tier
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
