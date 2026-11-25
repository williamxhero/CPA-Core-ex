package auth

import (
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
)

func isUpstreamBalanceError(err *Error) bool {
	return err != nil && (err.Metadata[explicitBalanceExhaustionKey] == "1" || clienterror.IsExplicitBalanceExhaustion(err.Message))
}

func clearUpstreamBalanceCooldown(auth *Auth, now, through time.Time) bool {
	if auth.Disabled || auth.Status == StatusDisabled || auth.refreshGrantBlocked() || hasUnauthorizedAuthFailure(auth) || isUnauthorizedError(auth.LastError) {
		return false
	}
	authBalance := isUpstreamBalanceError(auth.LastError) && !auth.UpdatedAt.After(through)
	wrappedBalance := authBalance && auth.Quota.Reason == "credential_quota"
	changed := false
	for _, state := range auth.ModelStates {
		if state == nil || state.Status == StatusDisabled || state.UpdatedAt.After(through) {
			continue
		}
		if wrappedBalance && (state.credentialQuotaPropagated || state.Quota.Reason == "credential_quota") {
			// Remove only the credential-derived layer; restore independent
			// cooldowns (including model authentication failures) underneath it.
			if shadow := state.credentialQuotaShadow; shadow != nil && !isUpstreamBalanceError(shadow.LastError) && isModelStateActiveCooldown(shadow, now) {
				*state = *shadow.cloneShallow()
			} else if isUnauthorizedError(state.LastError) {
				continue
			} else {
				resetModelState(state, now)
			}
		} else if isUpstreamBalanceError(state.LastError) && !isUnauthorizedError(state.LastError) {
			resetModelState(state, now)
		} else {
			continue
		}
		changed = true
	}
	if authBalance {
		// An aggregate error can come from a model. Only release auth-level
		// deadlines when the auth holds the billing cooldown itself.
		if wrappedBalance || (auth.LastError.HTTPStatus != http.StatusUnauthorized && !auth.credentialRetryAfter.IsZero()) || len(auth.ModelStates) == 0 {
			auth.credentialRetryAfter = time.Time{}
			auth.forceCooldownUntil = time.Time{}
			auth.quotaForceCooldownUntil = time.Time{}
			auth.credQuotaForceUntil = time.Time{}
			auth.nonQuotaCooldownUntil = time.Time{}
			auth.providerRetryAt = time.Time{}
			auth.cooldownRecordedSeq = 0
			clearAggregatedAvailability(auth)
		}
		auth.LastError = nil
		auth.StatusMessage = ""
		changed = true
	}
	if changed {
		updateAggregatedAvailability(auth, now)
		if auth.LastError == nil && !hasModelError(auth, now) && !auth.Unavailable {
			auth.Status = StatusActive
		}
	}
	return changed
}
