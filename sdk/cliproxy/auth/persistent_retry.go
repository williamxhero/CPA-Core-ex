package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

const persistentRetryPilotModel = "gpt-6.2-sol"

func (m *Manager) persistentRetryLimit(ctx context.Context, req executor.Request, opts executor.Options) (limit int, enabled, explicit bool) {
	if m.HomeEnabled() || !opts.Stream || opts.Alt != "" || executor.DownstreamWebsocket(ctx) || executor.RequiredUpstreamWebsocket(ctx) {
		return 0, false, false
	}
	path, _ := opts.Metadata[executor.RequestPathMetadataKey].(string)
	if !(path == "/v1/chat/completions" && opts.SourceFormat == sdktranslator.FormatOpenAI ||
		path == "/v1/responses" && opts.SourceFormat == sdktranslator.FormatOpenAIResponse) {
		return 0, false, false
	}
	cfg := m.runtimeConfigSnapshot().Routing.ProviderScheduling
	if req.Model != persistentRetryPilotModel || requestedModelAliasFromOptions(opts, req.Model) != persistentRetryPilotModel ||
		!slices.Contains(cfg.PersistentRetryModels, persistentRetryPilotModel) {
		return 0, false, false
	}
	// Snapshot the effective limit and its precedence in the same request ledger.
	if upstream := m.configuredUpstreamErrorRetryLimit(); upstream != -2 {
		return upstream, true, true
	}
	limit, _, _ = m.retrySettings()
	return limit, true, false
}

// PersistentRetryPilot reports the enforced request's opt-in pilot scope.
func PersistentRetryPilot(ctx context.Context) bool {
	b := requestBudgetFromContext(ctx)
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.persistentRetry
}

func pilotCodex(ctx context.Context, provider string) bool {
	return provider == "codex" && PersistentRetryPilot(ctx)
}

// upstreamCategory classifies the last transient failure for routing traces.
type upstreamCategory string

const errorCodeTransientUpstream = "transient_upstream"

const (
	upstreamCategoryTransient          upstreamCategory = errorCodeTransientUpstream
	upstreamCategoryTransientRateLimit upstreamCategory = ErrorCodeTransientRateLimit
)

// retryStopReason explains why the pilot scheduler stopped repeating a request.
type retryStopReason string

const (
	retryStopCanceled               retryStopReason = "canceled"
	retryStopDeadlineExceeded       retryStopReason = "deadline_exceeded"
	retryStopDeadlineBeforeRecovery retryStopReason = "deadline_before_recovery"
	retryStopNoAvailableRoute       retryStopReason = "no_available_route"
	retryStopNoRecoveryRoute        retryStopReason = "no_recovery_route"
	retryStopNonTransientFailure    retryStopReason = "non_transient_failure"
	retryStopLocalValidation        retryStopReason = "local_validation"
	retryStopLocalDispatch          retryStopReason = "local_dispatch_rejected"
	retryStopRequestPolicy          retryStopReason = "request_policy"
	retryStopUpstreamValidation     retryStopReason = "upstream_validation"
	retryStopUpstreamPolicy         retryStopReason = "upstream_policy"
	retryStopOutputCommitted        retryStopReason = "output_committed"
	retryStopReplayUnsafe           retryStopReason = "replay_unsafe"
	retryStopRetryLimit             retryStopReason = "retry_limit"
	retryStopStreamRecoveryLimit    retryStopReason = "stream_recovery_buffer_limit"
)

func pilotLifecycleError(ctx context.Context, err error) error {
	if errors.Is(err, context.Canceled) && errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

func pilotRequestStop(err error) retryStopReason {
	switch {
	case isRequestStopError(err), isRequestTerminatedError(err), isSchedulerRejectError(err):
		return retryStopRequestPolicy
	case pilotCodexFailure(err) == PilotCodexPolicy:
		return retryStopUpstreamPolicy
	case pilotCodexFailure(err) == PilotCodexInvalid:
		return retryStopUpstreamValidation
	case isRequestInvalidError(err) && !hasUpstreamExecutionAttempt(err):
		return retryStopLocalValidation
	}
	return retryStopNonTransientFailure
}

func (b *requestBudget) setRetryStop(reason retryStopReason) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.persistentRetry && b.RetryStopReason == "" {
		b.RetryStopReason = string(reason)
		updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
	}
}

// PilotCodexFailure describes facts from the Codex HTTP SSE adapter. It does
// not authorize a replay or prove that any other route is affected.
type PilotCodexFailure string

const (
	PilotCodexRecoverable PilotCodexFailure = "upstream_failure"
	PilotCodexTransport   PilotCodexFailure = "upstream_transport"
	PilotCodexInvalid     PilotCodexFailure = "invalid_request"
	PilotCodexPolicy      PilotCodexFailure = "upstream_policy"
	PilotCodexAuth        PilotCodexFailure = "upstream_authentication_required"
	PilotCodexRevoked     PilotCodexFailure = "credential_revoked"
	PilotCodexPermission  PilotCodexFailure = "route_permission_denied"
	PilotCodexQuota       PilotCodexFailure = "quota_exhausted"
	PilotCodexModel       PilotCodexFailure = "route_model_unsupported"
)

func pilotCodexFailure(err error) PilotCodexFailure {
	var fact interface{ PilotCodexFailure() PilotCodexFailure }
	if errors.As(err, &fact) {
		return fact.PilotCodexFailure()
	}
	return ""
}

func persistentTransient(err error) bool {
	if !hasUpstreamExecutionAttempt(err) || upstreamAttemptProviderFromError(err) != "codex" ||
		isRequestTerminatedError(err) || isRequestStopError(err) || isSchedulerRejectError(err) {
		return false
	}
	switch pilotCodexFailure(err) {
	case PilotCodexRecoverable, PilotCodexTransport:
		return true
	case "":
		// These two are synthesized by the conductor, not responses classified
		// from status or message text. The dispatch marker is still required.
		switch errorCodeFromError(err) {
		case "empty_stream", "stream_bootstrap_timeout":
			return true
		}
	}
	return false
}

type persistentReservationKey struct{}

func isPilotRouteRejection(err error) bool {
	if !hasUpstreamExecutionAttempt(err) {
		return false
	}
	switch pilotCodexFailure(err) {
	case PilotCodexAuth, PilotCodexRevoked, PilotCodexPermission, PilotCodexQuota, PilotCodexModel:
		return true
	}
	return false
}

// Keep route-local rejections excluded across rounds without reusing raw
// identifiers outside the request ledger.
func notePilotRouteRejection(ctx context.Context, r *routeReservation, err error) {
	if !isPilotRouteRejection(err) {
		return
	}
	b := requestBudgetFromContext(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pilotRejected == nil {
		b.pilotRejected = make(map[string]struct{})
	}
	b.pilotRejected[r.persistentRoute] = struct{}{}
}

func (m *Manager) recordPilotStreamResult(ctx context.Context, result Result, auth *Auth, ephemeral bool, err error, matchedRule bool) {
	reservation, _ := ctx.Value(persistentReservationKey{}).(*routeReservation)
	if reservation != nil && errorCodeFromError(err) == "stream_recovery_buffer_limit" {
		markPilotReplayUnsafe(ctx)
		requestBudgetFromContext(ctx).setRetryStop(retryStopStreamRecoveryLimit)
		return
	}
	if reservation != nil && persistentTransient(err) && (!matchedRule || result.Error == nil || result.Error.Code != ErrorCodeForceCooldown) {
		// A matched request-scoped rule still paces the pilot in memory; the
		// neutral result below keeps persistent cooldown/quota state untouched.
		reservation.notePersistentFailure(ctx, err)
		if result.Error != nil {
			result.Error = &Error{HTTPStatus: statusCodeFromError(err), Code: errorCodeTransientUpstream, Message: "temporary upstream rejection"}
			if result.Error.HTTPStatus == http.StatusTooManyRequests {
				result.Error.Code = ErrorCodeTransientRateLimit
			}
		}
		m.recordAvailabilityNeutralResult(WithSkipPersist(ctx), result)
		return
	}
	if reservation != nil && result.Error != nil {
		if hasUpstreamExecutionAttempt(err) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			reservation.validationFailed = true
		}
		notePilotRouteRejection(ctx, reservation, err)
		// Rules inspected the response before this point. Never persist its text.
		result.Error.Message = "Codex inference rejected"
		if fact := pilotCodexFailure(err); fact != "" && result.Error.Code == "" {
			result.Error.Code = string(fact)
		}
	}
	m.recordExecutionResult(ctx, result, auth, ephemeral)
}

// ObservePilotReplayPayload checks the final request after payload rules have run.
func ObservePilotReplayPayload(ctx context.Context, payload []byte) {
	if PersistentRetryPilot(ctx) && requestMayRunHostedTools(payload) {
		markPilotReplayUnsafe(ctx)
	}
}

// ObservePilotCodexOutput conservatively fences an upstream event that may
// represent execution even if the downstream translator drops it.
func ObservePilotCodexOutput(ctx context.Context, eventType string, payload []byte) {
	switch eventType {
	case "response.completed", "response.done", "response.incomplete", "response.output_text.delta", "response.reasoning_text.delta", "response.reasoning_summary_text.delta", "response.refusal.delta":
		return
	case "response.output_item.added", "response.output_item.done":
		switch ojson.GetBytesNoCopy(payload, "item.type").String() {
		case "message", "reasoning", "function_call", "custom_tool_call":
			return
		}
	}
	markPilotReplayUnsafe(ctx)
}

func markPilotReplayUnsafe(ctx context.Context) {
	b := requestBudgetFromContext(ctx)
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ReplayUnsafe {
		return
	}
	b.ReplayUnsafe = true
	updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
}
