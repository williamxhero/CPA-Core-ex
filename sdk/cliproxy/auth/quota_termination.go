package auth

import (
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

const quotaObservationMaxAge = time.Hour

// QuotaAvailability is the knowledge state of one resource class.
// Unknown is deliberately non-terminal: a missing, stale, expired, or failed
// quota read must never be interpreted as zero.
type QuotaAvailability uint8

const (
	QuotaUnknown QuotaAvailability = iota
	QuotaAvailable
	QuotaExhausted
)

// QuotaTermination records the two independent resources used by a request.
// A request may terminate for resource exhaustion only when both are known to
// be exhausted.
type QuotaTermination struct {
	Plan     QuotaAvailability
	Recharge QuotaAvailability
}

// ShouldTerminate reports the SPEC resource stop condition.
func (q QuotaTermination) ShouldTerminate() bool {
	return q.Plan == QuotaExhausted && q.Recharge == QuotaExhausted
}

// AggregatePlanQuota applies AND semantics across all applicable plan windows.
// Any available window keeps the plan available. An unknown or expired window
// prevents a terminal decision.
func AggregatePlanQuota(windows ...QuotaAvailability) QuotaAvailability {
	if len(windows) == 0 {
		return QuotaUnknown
	}
	unknown := false
	for _, window := range windows {
		switch window {
		case QuotaAvailable:
			return QuotaAvailable
		case QuotaUnknown:
			unknown = true
		}
	}
	if unknown {
		return QuotaUnknown
	}
	return QuotaExhausted
}

// quotaTerminationFromSignals translates provider quota watermarks into the
// domain decision used by the retry coordinator. It is intentionally
// conservative and returns Unknown when the provider did not expose enough
// evidence to prove a resource is zero.
func quotaTerminationFromSignals(provider string, signals map[string]string) QuotaTermination {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if len(signals) == 0 {
		return QuotaTermination{}
	}
	plan := planAvailabilityFromSignals(provider, signals)
	recharge := rechargeAvailabilityFromSignals(provider, signals)
	return QuotaTermination{Plan: plan, Recharge: recharge}
}

func quotaTerminationFromState(provider string, quota QuotaState) QuotaTermination {
	// A snapshot without an observation timestamp is not evidence. This also
	// covers restored/expired state whose passive watermark was discarded.
	if quota.ObservedAt.IsZero() || len(quota.Signals) == 0 || time.Since(quota.ObservedAt) > quotaObservationMaxAge || quota.ObservedAt.After(time.Now().Add(time.Minute)) {
		return QuotaTermination{}
	}
	return quotaTerminationFromSignals(provider, quota.Signals)
}

func planAvailabilityFromSignals(provider string, signals map[string]string) QuotaAvailability {
	var windows []QuotaAvailability
	for key, value := range signals {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "used-percent") {
			if remaining, ok := numericValue(value); ok {
				if remaining >= 100 {
					windows = append(windows, QuotaExhausted)
				} else if remaining >= 0 {
					windows = append(windows, QuotaAvailable)
				} else {
					windows = append(windows, QuotaUnknown)
				}
			} else {
				windows = append(windows, QuotaUnknown)
			}
		}
		if strings.Contains(lower, "-status") && strings.Contains(lower, "ratelimit-unified-") {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "allowed", "available", "ok":
				windows = append(windows, QuotaAvailable)
			case "rejected", "exhausted", "blocked", "denied":
				windows = append(windows, QuotaExhausted)
			default:
				windows = append(windows, QuotaUnknown)
			}
		}
		if provider == "codex" && strings.HasSuffix(lower, "-limit-reached") {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "true", "1", "yes":
				windows = append(windows, QuotaExhausted)
			case "false", "0", "no":
				windows = append(windows, QuotaAvailable)
			default:
				windows = append(windows, QuotaUnknown)
			}
		}
	}
	return AggregatePlanQuota(windows...)
}

func rechargeAvailabilityFromSignals(provider string, signals map[string]string) QuotaAvailability {
	var available bool
	var exhausted bool
	for key, value := range signals {
		lower := strings.ToLower(key)
		if provider == "codex" && strings.HasSuffix(lower, "credits-unlimited") {
			if isTruthy(value) {
				available = true
			}
		}
		if strings.HasSuffix(lower, "credits-balance") {
			if balance, ok := numericValue(value); ok {
				if balance > 0 {
					available = true
				}
				if balance == 0 {
					exhausted = true
				}
			}
		}
		if strings.HasSuffix(lower, "credits-has-credits") {
			if isTruthy(value) {
				available = true
			}
			if strings.EqualFold(strings.TrimSpace(value), "false") || strings.TrimSpace(value) == "0" || strings.EqualFold(strings.TrimSpace(value), "no") {
				exhausted = true
			}
		}
		if strings.HasSuffix(lower, "overage-limit-reached") {
			if isTruthy(value) {
				exhausted = true
			}
			if !isTruthy(value) {
				available = true
			}
		}
		if strings.Contains(lower, "overage-status") {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "allowed", "available", "ok":
				available = true
			case "rejected", "exhausted", "blocked", "denied":
				exhausted = true
			}
		}
	}
	if available {
		return QuotaAvailable
	}
	if exhausted {
		return QuotaExhausted
	}
	return QuotaUnknown
}

func numericValue(raw string) (float64, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	return value, err == nil
}

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "y":
		return true
	default:
		return false
	}
}

func (m *Manager) allCandidatesQuotaTerminated(providers []string, models ...string) bool {
	if m == nil || len(providers) == 0 {
		return false
	}
	providerSet := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		providerSet[strings.ToLower(strings.TrimSpace(provider))] = struct{}{}
	}
	found := false
	model := ""
	if len(models) > 0 {
		model = strings.TrimSpace(models[0])
	}
	registryRef := registry.GetGlobalRegistry()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, auth := range m.auths {
		if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
			continue
		}
		provider := canonicalSchedulingProvider(executorKeyFromAuth(auth))
		if _, ok := providerSet[strings.ToLower(strings.TrimSpace(provider))]; !ok {
			continue
		}
		if model != "" && !m.authSupportsRouteModel(registryRef, auth, model) {
			continue
		}
		found = true
		if !quotaTerminationFromState(auth.Provider, auth.Quota).ShouldTerminate() {
			return false
		}
	}
	return found
}
