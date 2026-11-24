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

// A failed atomic pick can be re-evaluated against new availability. A
// selector rejection with a nonempty pool isn't evidence of a recovery.
type scheduledUnavailablePick struct{ localNoAvailableRoute }

func (e scheduledUnavailablePick) Unwrap() error { return e.localNoAvailableRoute }

type scheduledCandidate struct {
	auth              *Auth
	owner             string
	model             string
	routeID           string
	exec              ProviderExecutor
	limits            []schedulingLimit
	reasons           []string
	retryAt           time.Time
	diagnosticQuotaAt time.Time
	diagnosticQuota   bool
	diagnosticExpired bool
	refreshRunning    bool
	quotaBlocked      bool
	quotaEvidence     *resource.QuotaGateEvidence
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

func (m *Manager) scheduledCandidates(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}, now time.Time, pilotFirstSend bool) ([]scheduledCandidate, Selector) {
	cfg := m.runtimeConfigSnapshot().Routing.ProviderScheduling
	caller := providerSchedulingCaller(ctx)
	pin := pinnedAuthIDFromMetadata(opts.Metadata)
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	allowed := make(map[string]struct{}, len(providers))
	for _, p := range providers {
		allowed[canonicalSchedulingProvider(p)] = struct{}{}
	}
	reg := registry.GetGlobalRegistry()
	persistent := PersistentRetryPilot(ctx)
	m.mu.RLock()
	selector := m.selector
	candidates := make([]scheduledCandidate, 0, len(m.auths))
	for _, a := range m.auths {
		if a == nil {
			continue
		}
		p := executorKeyFromAuth(a)
		exec, _ := m.executorLocked(p)
		candidates = append(candidates, scheduledCandidate{auth: a.Clone(), owner: p, exec: exec,
			refreshRunning: persistent && p == "codex" && m.runningRefreshLocked(a)})
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
		c.routeID = m.scheduledRouteIdentity(a, model)
		_, excludeByAuth := tried[a.ID]
		_, excludeByIdentity := tried[c.routeID]
		_, excludeByDuplicate := excludedRoutes[c.routeID]
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
		pilotRoute := persistent && c.owner == "codex"
		var authBlock string
		if pilotRoute || wantsSchedulingDecision(ctx) {
			exp, known := a.AccessTokenExpirationTimeForRequest(ctx, opts.Headers)
			c.diagnosticExpired = known && !exp.IsZero() && !exp.After(now)
		}
		if pilotRoute {
			c.quotaBlocked = hasLiveQuotaCooldown(a, c.model, now)
			state := existingModelState(a, c.model)
			if state != nil && state.Status == StatusDisabled {
				blocked, reason = true, blockReasonDisabled
			}
			if reason != blockReasonDisabled {
				token := authAccessTokenForRequest(ctx, a, opts.Headers)
				rejected := token != "" && (token == a.RejectedAccessToken || token == a.RejectedSIWCAccessToken)
				switch {
				case a.LastError != nil && a.LastError.Code == string(PilotCodexRevoked):
					authBlock = "reauthentication_required"
				case rejected || c.diagnosticExpired || hasUnauthorizedAuthFailure(a):
					switch {
					case a.RequiresSignIn:
						authBlock = "reauthentication_required"
					case a.RequiresCredentialRecovery():
						authBlock = "credential_recovery_required"
					case c.refreshRunning && !c.quotaBlocked && !authHasUnchangedRejectedRefreshToken(a):
						authBlock = "refresh_in_progress"
					default:
						authBlock = "authentication_unavailable"
					}
				}
			}
		}
		if wantsSchedulingDecision(ctx) {
			if a.Quota.Exceeded && a.Quota.Reason == "credential_quota" && a.Quota.NextRecoverAt.After(now) {
				c.diagnosticQuota, c.diagnosticQuotaAt = true, a.Quota.NextRecoverAt
			}
		}
		if blocked || authBlock != "" {
			switch {
			case authBlock != "":
				c.reasons = append(c.reasons, authBlock)
			case reason == blockReasonDisabled:
				c.reasons = appendSchedulingReason(c.reasons, "manual_disabled")
			case reason == blockReasonCooldown || !next.IsZero():
				c.reasons = append(c.reasons, "cooldown")
				if eligible, nextEligible := retryRoundAvailabilityForAuthForRequest(ctx, a, c.model, now, opts.Headers); eligible && scheduledTrustedRecovery(a, c.model, nextEligible, now) {
					c.retryAt = nextEligible
				} else if pilotFirstSend && c.owner == "codex" && reason == blockReasonOther && next.After(now) && !a.credentialRetryAfter.After(now) {
					// An ordinary caller can leave a live model cooldown without a
					// Retry-After hint. Only the pilot's first send may wait for it.
					if state := existingModelState(a, c.model); state != nil && state.Unavailable && state.NextRetryAfter.Equal(next) {
						switch cooldownErrorReason(state.LastError) {
						case "transient_error", ErrorCodeTransientRateLimit:
							c.retryAt = next
						}
					}
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
			if authority.inspect != nil && (persistent || wantsSchedulingDecision(ctx)) {
				var evidence *resource.QuotaGateEvidence
				evidence, err = authority.inspect(ctx, a, model)
				if evidence != nil {
					c.quotaBlocked = c.quotaBlocked || err != nil
					if pilotRoute && err != nil {
						c.quotaEvidence = evidence
					}
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
		now := m.getContinuityClock().Now()
		candidates, selector := m.scheduledCandidates(ctx, providers, model, opts, tried, now, false)
		persistent := PersistentRetryPilot(ctx)
		b := requestBudgetFromContext(ctx)
		u := &m.providerSchedulingUse
		var alarms []pilotAlarm
		u.mu.Lock()
		hardBinding := scheduledHardAffinity(selector, model, opts)
		if persistent {
			u.pruneStalePersistentBackoffLocked(scheduledLiveRoutes(candidates), now)
			for i := range candidates {
				c := &candidates[i]
				if c.owner != "codex" || len(c.reasons) != 0 || (hardBinding != "" && c.auth.ID != hardBinding) {
					continue
				}
				if alarm := u.evaluatePersistentRecovery(c.routeID, now); alarm.code != "" {
					alarms = append(alarms, alarm)
				}
				switch state := u.backoff[c.routeID]; {
				case state.probe != nil:
					c.reasons = append(c.reasons, "probe_in_flight")
				case state.at.After(now):
					c.reasons = append(c.reasons, "cooldown")
				case state.slotLimit() > 0 && u.pilotInUse[c.routeID] >= state.slotLimit():
					c.reasons = append(c.reasons, "recovery_capacity_full")
				case u.olderWaiter(b, c.routeID):
					c.reasons = append(c.reasons, "older_waiter")
				}
			}
		}
		unlock := func() {
			u.mu.Unlock()
			for _, alarm := range alarms {
				alarm.emit()
			}
			if len(alarms) != 0 {
				m.providerSchedulingWake.signal()
			}
		}
		available, byID := m.scheduledAvailable(candidates)
		report := func(selected *Auth) {
			if wantsSchedulingDecision(ctx) {
				decision := m.schedulingView(internalconfig.ProviderSchedulingEnforce, model, candidates, selected, hardBinding)
				publishSchedulingDecision(ctx, decision)
			}
		}
		var boundUnavailable bool
		if persistent {
			if hardBinding != "" {
				boundUnavailable = byID[hardBinding].auth == nil
			}
		}
		if len(available) == 0 || boundUnavailable {
			unlock()
			report(nil)
			if persistent {
				return nil, nil, "", scheduledUnavailablePick{localNoAvailableRoute{model: model}}
			}
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
			unlock()
			report(nil)
			return nil, nil, "", newNoAvailableRouteError(model)
		}
		c, ok := byID[a.ID]
		if !ok || !slices.Contains(available, c.auth) {
			unlock()
			report(nil)
			return nil, nil, "", newNoAvailableRouteError(model)
		}
		m.mu.RLock()
		current := m.auths[a.ID]
		if current == nil || current.Generation != c.auth.Generation || current.RegistrationEpoch != c.auth.RegistrationEpoch || cfg != m.runtimeConfigSnapshot() {
			m.mu.RUnlock()
			unlock()
			continue
		}
		if errCtx := ctx.Err(); errCtx != nil {
			m.mu.RUnlock()
			unlock()
			return nil, nil, "", errCtx
		}
		persistentCodex := persistent && c.owner == "codex"
		if len(c.limits) > 0 || persistentCodex {
			if u.counts == nil {
				u.counts = make(map[string]int)
			}
			for _, limit := range c.limits {
				u.counts[limit.id]++
			}
			r := &routeReservation{manager: m, limits: c.limits}
			if persistentCodex {
				r.persistentRoute, r.ctx = c.routeID, ctx
				if u.pilotInUse == nil {
					u.pilotInUse = make(map[string]int)
				}
				u.pilotInUse[c.routeID]++
				if state, exists := u.backoff[c.routeID]; exists {
					r.faultGeneration = state.generation
					if state.firstSuccess.IsZero() {
						state.probe = r
						u.backoff[c.routeID] = state
					}
					recordPilotRecovery(b.trace.Load(), state.view(u.pilotInUse[c.routeID], u.waiterCount(c.routeID), now))
				}
			}
			opts.Metadata[routeReservationMetadata] = r
		}
		removed := persistent && u.removeWaiter(b)
		m.mu.RUnlock()
		unlock()
		if removed {
			m.providerSchedulingWake.signal()
		}
		report(c.auth)
		return c.auth, c.exec, c.owner, nil
	}
}

// Caller holds the reservation lock. Mark capacity and deduplication reasons
// on the same exact pool the selector receives.
func (m *Manager) scheduledAvailable(candidates []scheduledCandidate) ([]*Auth, map[string]scheduledCandidate) {
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
		key := candidate.routeID
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
