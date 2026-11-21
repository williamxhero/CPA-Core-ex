package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	moejson "github.com/MoeForge/moego/json"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

type providerSchedulingCallerKey struct{}

// WithProviderSchedulingCaller attaches only a pseudonym derived from a result
// returned by trusted access authentication, never a request header.
func WithProviderSchedulingCaller(ctx context.Context, accessProvider, authenticatedPrincipal string) context.Context {
	accessProvider = strings.TrimSpace(accessProvider)
	if accessProvider == "" || strings.TrimSpace(authenticatedPrincipal) == "" {
		return ctx
	}
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(accessProvider+"\x00"+authenticatedPrincipal)))
	return context.WithValue(ctx, providerSchedulingCallerKey{}, id)
}

// InheritProviderSchedulingCaller carries the authenticated caller across API
// execution contexts whose existing parent is independent of the HTTP request.
func InheritProviderSchedulingCaller(ctx, request context.Context) context.Context {
	if id := providerSchedulingCaller(request); id != "" {
		return context.WithValue(ctx, providerSchedulingCallerKey{}, id)
	}
	return ctx
}

func providerSchedulingCaller(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(providerSchedulingCallerKey{}).(string)
	return id
}

func (m *Manager) providerSchedulingMode(ctx context.Context, model string) string {
	return m.runtimeConfigSnapshot().ProviderSchedulingMode(strings.TrimSpace(thinking.ParseSuffix(model).ModelName), providerSchedulingCaller(ctx))
}

// ProviderSchedulingEnforced reports whether the unified scheduler owns this request.
func (m *Manager) ProviderSchedulingEnforced(ctx context.Context, model string) bool {
	return m.providerSchedulingMode(ctx, model) == internalconfig.ProviderSchedulingEnforce
}

type localNoAvailableRoute struct{ model string }

func (e localNoAvailableRoute) StatusCode() int { return http.StatusServiceUnavailable }
func (e localNoAvailableRoute) Error() string {
	body, err := moejson.Marshal(map[string]any{
		"error": map[string]string{
			"code": "no_available_route", "type": "server_error",
			"message": "No route is currently available for this model.", "model": e.model,
		},
	})
	if err != nil {
		return "no_available_route"
	}
	return string(body)
}

func newNoAvailableRouteError(model string) error { return localNoAvailableRoute{model: model} }

type scheduledCandidate struct {
	auth              *Auth
	owner             string
	model             string
	exec              ProviderExecutor
	limits            []schedulingLimit
	reasons           []string
	retryAt           time.Time
	diagnosticQuotaAt time.Time
	diagnosticQuota   bool
	diagnosticExpired bool
}

func schedulingResource(a *Auth) (resourceID, parentID string) {
	if a == nil || a.ResourceIdentity == nil || len(a.ResourceIdentity.Targets) == 0 {
		return "", ""
	}
	resourceID = a.ResourceIdentity.Targets[0].ResourceID
	if len(a.ResourceIdentity.Targets) > 1 {
		parentID = a.ResourceIdentity.Targets[1].ResourceID
	}
	return resourceID, parentID
}

func schedulingPolicy(cfg internalconfig.ProviderSchedulingConfig, a *Auth) internalconfig.ProviderSchedulingResource {
	id, parent := schedulingResource(a)
	if id == "" {
		return internalconfig.ProviderSchedulingResource{}
	}
	policy, found := cfg.Resources[id]
	if (!found || strings.TrimSpace(policy.Funding) == "") && parent != "" {
		policy = cfg.Resources[parent]
	}
	return policy
}

func (m *Manager) scheduledFundingAllows(ctx context.Context, a *Auth) bool {
	cfg := m.runtimeConfigSnapshot().Routing.ProviderScheduling
	return allowsRouteFunding(cfg, providerSchedulingCaller(ctx), schedulingPolicy(cfg, a).Funding)
}

// CheckProviderSchedulingUnboundExecution enforces hard constraints before a
// foreign executor without a credential binding can send a request.
func (m *Manager) CheckProviderSchedulingUnboundExecution(ctx context.Context, model, pinnedAuthID string) error {
	if m == nil || !m.ProviderSchedulingEnforced(ctx, model) {
		return nil
	}
	if strings.TrimSpace(pinnedAuthID) != "" {
		RecordExternalExecutorRouting(ctx, "hard_binding")
		return newNoAvailableRouteError(model)
	}
	if !m.scheduledFundingAllows(ctx, nil) {
		RecordExternalExecutorRouting(ctx, "funding_ineligible")
		return newNoAvailableRouteError(model)
	}
	return nil
}

func allowsRouteFunding(cfg internalconfig.ProviderSchedulingConfig, caller, funding string) bool {
	_, callerRestricted := cfg.CallerFunding[caller]
	if cfg.AllowedFunding == nil && !callerRestricted {
		return true
	}
	funding = strings.ToLower(strings.TrimSpace(funding))
	if funding != "subscription" && funding != "prepaid" {
		return false
	}
	allowedBy := func(list []string) bool {
		return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), funding) })
	}
	return (cfg.AllowedFunding == nil || allowedBy(cfg.AllowedFunding)) && (!callerRestricted || allowedBy(cfg.CallerFunding[caller]))
}

func (m *Manager) scheduledCandidates(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, now time.Time) ([]scheduledCandidate, Selector) {
	cfg := m.runtimeConfigSnapshot().Routing.ProviderScheduling
	caller := providerSchedulingCaller(ctx)
	pin := pinnedAuthIDFromMetadata(opts.Metadata)
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	allowed := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		allowed[canonicalSchedulingProvider(p)] = struct{}{}
	}
	reg := registry.GetGlobalRegistry()
	m.mu.RLock()
	selector := m.selector
	candidates := make([]scheduledCandidate, 0, len(m.auths))
	for _, a := range m.auths {
		if a == nil {
			continue
		}
		p := executorKeyFromAuth(a)
		exec, _ := m.executorLocked(p)
		candidates = append(candidates, scheduledCandidate{auth: a.Clone(), owner: p, exec: exec})
	}
	m.mu.RUnlock()

	excludedRoutes := make(map[string]struct{}, len(tried))
	for _, c := range candidates {
		if _, seen := tried[c.auth.ID]; seen {
			excludedRoutes[m.scheduledRouteIdentity(c.auth, model)] = struct{}{}
		}
	}
	claimed := make(map[string]string)
	for _, claim := range configuredSchedulingClaims(m.runtimeConfigSnapshot(), model) {
		if claim.id != "" && claim.reason != "" {
			claimed[claim.id] = claim.reason
		}
	}
	authority := m.inferenceAdmission.Load()
	for i := range candidates {
		c := &candidates[i]
		a := c.auth
		c.model = m.selectionModelForAuth(a, model)
		c.limits = schedulingLimits(cfg, a)
		if !m.authSupportsRouteModel(reg, a, model) {
			c.reasons = append(c.reasons, "model_not_registered")
		}
		_, providerAllowed := allowed[canonicalSchedulingProvider(c.owner)]
		if !providerAllowed {
			c.reasons = append(c.reasons, "provider_out_of_scope")
		}
		if c.exec == nil {
			c.reasons = append(c.reasons, "protocol_incompatible")
		} else {
			c.reasons = append(c.reasons, schedulingProtocolReasons(a, opts)...)
		}
		c.reasons = append(c.reasons, m.scheduledModelCapabilityReasons(a, model, opts, reg)...)
		if pin != "" && a.ID != pin {
			c.reasons = append(c.reasons, "hard_binding")
		}
		if !eligibility.allows(a) {
			c.reasons = append(c.reasons, "caller_ineligible")
		}
		if !allowsRouteFunding(cfg, caller, schedulingPolicy(cfg, a).Funding) {
			c.reasons = append(c.reasons, "funding_ineligible")
		}
		routeID := m.scheduledRouteIdentity(a, model)
		_, excludeByAuth := tried[a.ID]
		_, excludeByIdentity := tried[routeID]
		_, excludeByDuplicate := excludedRoutes[routeID]
		if excludeByAuth || excludeByIdentity || excludeByDuplicate || scheduledAntigravityExcludes(ctx, a.ID, c.owner) {
			c.reasons = append(c.reasons, "request_excluded")
		}
		id, parent := schedulingResource(a)
		if configReason := claimed[id]; configReason != "" {
			c.reasons = append(c.reasons, configReason)
		} else if configReason = claimed[parent]; configReason != "" {
			c.reasons = append(c.reasons, configReason)
		}
		blocked, reason, next := isAuthBlockedForModelForRequest(ctx, a, c.model, now, opts.Headers)
		if wantsSchedulingDecision(ctx) {
			if exp, known := a.AccessTokenExpirationTimeForRequest(ctx, opts.Headers); known && !exp.IsZero() {
				c.diagnosticExpired = !exp.After(now)
			}
			if a.Quota.Exceeded && a.Quota.Reason == "credential_quota" && a.Quota.NextRecoverAt.After(now) {
				c.diagnosticQuota, c.diagnosticQuotaAt = true, a.Quota.NextRecoverAt
			}
		}
		if blocked {
			switch {
			case reason == blockReasonDisabled:
				c.reasons = appendSchedulingReason(c.reasons, "manual_disabled")
			case reason == blockReasonCooldown || !next.IsZero():
				c.reasons = append(c.reasons, "cooldown")
				if eligible, nextEligible := retryRoundAvailabilityForAuthForRequest(ctx, a, c.model, now, opts.Headers); eligible && scheduledTrustedRecovery(a, c.model, nextEligible, now) {
					c.retryAt = nextEligible
				}
			default:
				c.reasons = append(c.reasons, "authentication_unavailable")
			}
		}
		if selectorExcludesZeroWeight(selector) && authWeight(a) <= 0 {
			c.reasons = append(c.reasons, "zero_weight")
		}
		if authority == nil {
			if a.Attributes[AttributeLegacyFundingHold] == "true" {
				c.reasons = appendSchedulingReason(c.reasons, "inference_admission_blocked")
			}
		} else {
			var err error
			if authority.inspect != nil && wantsSchedulingDecision(ctx) {
				var evidence *resource.QuotaGateEvidence
				evidence, err = authority.inspect(ctx, a, model)
				if evidence != nil {
					c.diagnosticQuota = true
					if evidence.RecheckAtMS > 0 {
						c.diagnosticQuotaAt = time.UnixMilli(evidence.RecheckAtMS)
					}
				}
			} else {
				err = authority.check(ctx, a, model)
			}
			if err != nil {
				c.reasons = appendSchedulingReason(c.reasons, "inference_admission_blocked")
			}
		}
	}
	return candidates, selector
}

func (m *Manager) pickScheduledRoute(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, "", err
		}
		cfg := m.runtimeConfigSnapshot()
		candidates, selector := m.scheduledCandidates(ctx, providers, model, opts, tried, m.getContinuityClock().Now())
		u := &m.providerSchedulingUse
		u.mu.Lock()
		available, byID := m.scheduledAvailable(candidates, model)
		report := func(selected *Auth) {
			if wantsSchedulingDecision(ctx) {
				decision := m.schedulingView(internalconfig.ProviderSchedulingEnforce, model, candidates, selected, scheduledHardAffinity(selector, model, opts))
				publishSchedulingDecision(ctx, decision)
			}
		}
		if len(available) == 0 {
			u.mu.Unlock()
			report(nil)
			return nil, nil, "", newNoAvailableRouteError(model)
		}
		if affinity, ok := selector.(*SessionAffinitySelector); !ok || !affinity.rebindOnNever {
			available = highestPriorityAuths(available)
		}
		selectorCtx := selectorContextForAvailableAuths(ctx, selector, model)
		opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
		opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = model
		a, err := selector.Pick(selectorCtx, "mixed", selectionArgForSelector(selector, model), opts, available)
		if err != nil || a == nil {
			u.mu.Unlock()
			report(nil)
			return nil, nil, "", newNoAvailableRouteError(model)
		}
		c, ok := byID[a.ID]
		if !ok || !slices.Contains(available, c.auth) {
			u.mu.Unlock()
			report(nil)
			return nil, nil, "", newNoAvailableRouteError(model)
		}
		m.mu.RLock()
		current := m.auths[a.ID]
		if current == nil || current.Generation != c.auth.Generation || current.RegistrationEpoch != c.auth.RegistrationEpoch || cfg != m.runtimeConfigSnapshot() {
			m.mu.RUnlock()
			u.mu.Unlock()
			continue
		}
		if errCtx := ctx.Err(); errCtx != nil {
			m.mu.RUnlock()
			u.mu.Unlock()
			return nil, nil, "", errCtx
		}
		if len(c.limits) > 0 {
			if u.counts == nil {
				u.counts = make(map[string]int)
			}
			for _, limit := range c.limits {
				u.counts[limit.id]++
			}
			opts.Metadata[routeReservationMetadata] = &routeReservation{manager: m, limits: c.limits}
		}
		m.mu.RUnlock()
		u.mu.Unlock()
		report(c.auth)
		return c.auth, c.exec, c.owner, nil
	}
}

// Caller holds the reservation lock. Mark capacity and deduplication reasons
// on the same exact pool the selector receives.
func (m *Manager) scheduledAvailable(candidates []scheduledCandidate, model string) ([]*Auth, map[string]scheduledCandidate) {
	available := make([]*Auth, 0, len(candidates))
	byID := make(map[string]scheduledCandidate, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	sort.Slice(candidates, func(i, j int) bool {
		if left, right := authPriority(candidates[i].auth), authPriority(candidates[j].auth); left != right {
			return left > right
		}
		return candidates[i].auth.ID < candidates[j].auth.ID
	})
	for i := range candidates {
		candidate := &candidates[i]
		if !m.providerSchedulingUse.available(candidate.limits) {
			candidate.reasons = append(candidate.reasons, "concurrency_full")
		}
		if len(candidate.reasons) > 0 {
			continue
		}
		key := m.scheduledRouteIdentity(candidate.auth, model)
		if _, duplicate := seen[key]; duplicate {
			candidate.reasons = append(candidate.reasons, "duplicate_route")
			continue
		}
		seen[key] = struct{}{}
		available = append(available, candidate.auth)
		byID[candidate.auth.ID] = *candidate
	}
	return available, byID
}

func appendSchedulingReason(reasons []string, reason string) []string {
	if !slices.Contains(reasons, reason) {
		return append(reasons, reason)
	}
	return reasons
}
