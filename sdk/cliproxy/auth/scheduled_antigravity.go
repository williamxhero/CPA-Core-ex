package auth

import (
	"context"
	"errors"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type scheduledAntigravityFailure struct {
	authID  string
	model   string
	baseURL string
}

func scheduledAntigravity429(err error) *executor.AntigravityResourceExhausted {
	var facts *executor.AntigravityResourceExhausted
	if errors.As(err, &facts) && hasUpstreamExecutionAttempt(err) {
		return facts
	}
	return nil
}

func noteScheduledAntigravityFailure(ctx context.Context, err error, a *Auth, provider, model string) bool {
	facts := scheduledAntigravity429(err)
	if facts == nil || canonicalSchedulingProvider(provider) != "antigravity" || !RequestBudgetEnforced(ctx) {
		return false
	}
	b := requestBudgetFromContext(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.antigravityFailure = scheduledAntigravityFailure{authID: a.ID, model: model, baseURL: antigravityAuthBaseURL(a)}
	b.UpstreamCategory = "antigravity_resource_exhausted"
	b.UpstreamRetryAt = facts.RetryAt
	b.UpstreamRetrySource = facts.RetrySource
	if !b.antigravityWaitUsed {
		b.UpstreamDecision = "terminal"
	}
	return true
}

func scheduledAntigravityExcludes(ctx context.Context, authID, provider string) bool {
	b := requestBudgetFromContext(ctx)
	if b == nil || canonicalSchedulingProvider(provider) != "antigravity" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	target, retrying := ctx.Value(scheduledAntigravityRepeatKey{}).(scheduledAntigravityFailure)
	return b.antigravityFailure.authID != "" && (!retrying || authID != target.authID)
}

func (m *Manager) scheduledHomeExclusion(ctx context.Context, a *Auth, provider string) string {
	if !RequestBudgetEnforced(ctx) {
		return ""
	}
	if scheduledAntigravityExcludes(ctx, a.ID, provider) {
		return "request_excluded"
	}
	if !m.scheduledFundingAllows(ctx, a) {
		return "funding_ineligible"
	}
	return ""
}

type scheduledAntigravityRepeatKey struct{}

func (b *requestBudget) scheduledAntigravityRepeat(ctx context.Context, opts executor.Options) (context.Context, executor.Options) {
	b.mu.Lock()
	target := b.antigravityFailure
	b.mu.Unlock()
	opts.Metadata = cloneRequestMetadata(opts.Metadata)
	opts.Metadata[executor.PinnedAuthMetadataKey] = target.authID
	ctx = withStreamReplayExcludedAuthIDs(ctx, nil)
	return context.WithValue(ctx, scheduledAntigravityRepeatKey{}, target), opts
}

// antigravityAdmit is the last guard before a business send. Home may not
// honor the pin, or the credential may have been remapped since the 429.
func (b *requestBudget) antigravityAdmit(ctx context.Context, a *Auth, model string) bool {
	if target, retrying := ctx.Value(scheduledAntigravityRepeatKey{}).(scheduledAntigravityFailure); retrying {
		return b.RoundAttempts == 0 && canonicalSchedulingProvider(a.Provider) == "antigravity" &&
			a.ID == target.authID && model == target.model && antigravityAuthBaseURL(a) == target.baseURL
	}
	return b.antigravityFailure.authID == "" || canonicalSchedulingProvider(a.Provider) != "antigravity"
}

func antigravityAuthBaseURL(a *Auth) string {
	if v := a.Attributes["base_url"]; v != "" {
		return v
	}
	v, _ := a.Metadata["base_url"].(string)
	return v
}

// RequestBudgetNow is the scheduler's clock for transport recovery facts.
func RequestBudgetNow(ctx context.Context) time.Time {
	if b := requestBudgetFromContext(ctx); b != nil {
		b.mu.Lock()
		now := b.now
		b.mu.Unlock()
		if now != nil {
			return now()
		}
	}
	return time.Now()
}

// ObserveScheduledServedModel records an upstream-reported model ID, rather
// than the requested model or logical alias. Keep raw provider text out.
func ObserveScheduledServedModel(ctx context.Context, model string) {
	b := requestBudgetFromContext(ctx)
	if b == nil || len(model) == 0 || len(model) > 128 {
		return
	}
	for _, c := range model {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '-' || c == '_' || c == '.' || c == ':') {
			return
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.enforced {
		b.ServedModel = model
	}
}

func scheduledAntigravityTerminal(ctx context.Context, facts *executor.AntigravityResourceExhausted) error {
	// Home's round wrapper can contain an aggregate dispatch deadline;
	// this branch exposes only the matching upstream response's hint.
	if facts.RetryAt.After(facts.ObservedAt) {
		if remaining := facts.RetryAt.Sub(RequestBudgetNow(ctx)); remaining > 0 {
			return &trustedRetryAfterError{cause: facts, deadline: time.Now().Add(remaining)}
		}
	}
	return facts
}
