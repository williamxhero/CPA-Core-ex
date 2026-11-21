package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type requestBudgetKey struct{}

// scheduledAlternateRound lets selection explore the next round without
// spending it until a new credential starts a business attempt.
type scheduledAlternateRound struct {
	from     int
	excluded map[string]struct{}
}

type scheduledAlternateRoundKey struct{}

func scheduledAlternateRoundFromContext(ctx context.Context) *scheduledAlternateRound {
	round, _ := ctx.Value(scheduledAlternateRoundKey{}).(*scheduledAlternateRound)
	return round
}

// RequestBudgetSnapshot contains request accounting, never route identities or payloads.
// Round is zero-based. RoundAttempts counts business sends, not selected credentials.
type RequestBudgetSnapshot struct {
	Attempts            int
	Round               int
	RoundAttempts       int
	ActiveWait          time.Duration
	OutputCommitted     bool
	ReplayUnsafe        bool
	UpstreamCategory    string
	UpstreamRetryAt     time.Time
	UpstreamRetrySource string
	ServedModel         string
	UpstreamDecision    string
}

type requestBudget struct {
	trace atomic.Pointer[routingTrace]
	mu    sync.Mutex
	RequestBudgetSnapshot
	enforced            bool
	waiting             bool
	deadline            time.Time
	configuredWait      time.Duration
	credentials         map[string]struct{}
	routes              map[string]struct{}
	maxCredentials      int
	antigravityFailure  scheduledAntigravityFailure
	antigravityWaitUsed bool
	now                 func() time.Time
}

func requestBudgetFromContext(ctx context.Context) *requestBudget {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(requestBudgetKey{}).(*requestBudget)
	return b
}

// WithRequestBudget shares a ledger with any retry, bridge or nested call
// derived from this context. A new downstream request normally has a new context.
func WithRequestBudget(ctx context.Context) context.Context {
	if requestBudgetFromContext(ctx) != nil {
		return ctx
	}
	return WithFreshRequestBudget(ctx)
}

// InheritRequestBudget shares host-only accounting with a derived execution
// context. The inbound deadline constrains recovery waits, not inference.
func InheritRequestBudget(ctx, requestCtx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	b := requestBudgetFromContext(ctx)
	if b == nil {
		b = requestBudgetFromContext(requestCtx)
		if b == nil {
			ctx = WithFreshRequestBudget(ctx)
			b = requestBudgetFromContext(ctx)
		} else {
			ctx = context.WithValue(ctx, requestBudgetKey{}, b)
		}
	}
	if requestCtx != nil {
		if deadline, ok := requestCtx.Deadline(); ok {
			b.mu.Lock()
			if b.deadline.IsZero() || deadline.Before(b.deadline) {
				b.deadline = deadline
			}
			b.mu.Unlock()
		}
	}
	return ctx
}

// WithFreshRequestBudget starts an independent downstream turn on a reused connection.
func WithFreshRequestBudget(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestBudgetKey{}, &requestBudget{credentials: make(map[string]struct{}), routes: make(map[string]struct{})})
}

// RequestBudgetSnapshotFromContext exposes the accounting to trusted host diagnostics.
func RequestBudgetSnapshotFromContext(ctx context.Context) (RequestBudgetSnapshot, bool) {
	b := requestBudgetFromContext(ctx)
	if b == nil {
		return RequestBudgetSnapshot{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.RequestBudgetSnapshot, true
}

// RequestBudgetEnforced reports whether the shared ledger owns this request's repeat decisions.
func RequestBudgetEnforced(ctx context.Context) bool {
	b := requestBudgetFromContext(ctx)
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enforced
}

func (m *Manager) setupRequestBudget(ctx context.Context, req executor.Request, opts executor.Options) (context.Context, executor.Options) {
	ctx = WithRequestBudget(ctx)
	b := requestBudgetFromContext(ctx)
	model := authSelectionModelFromOptions(opts, req.Model)
	enforce := m.ProviderSchedulingEnforced(ctx, model)
	if enforce {
		opts = m.scheduleRequestOptions(req, opts)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enforced && enforce {
		b.enforced = true
		_, b.maxCredentials, _ = m.retrySettings()
		b.configuredWait = m.runtimeConfigSnapshot().ProviderSchedulingWait()
		b.now = m.getContinuityClock().Now
	}
	return ctx, opts
}

func (b *requestBudget) nextRound(from int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Round != from || b.OutputCommitted || b.ReplayUnsafe {
		return false
	}
	b.advanceRoundLocked()
	return true
}

func (b *requestBudget) advanceRoundLocked() {
	b.Round++
	b.RoundAttempts = 0
	clear(b.credentials)
	clear(b.routes)
}

func (b *requestBudget) credentialSnapshot() map[string]struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]struct{}, len(b.credentials)+len(b.routes))
	for id := range b.credentials {
		out[id] = struct{}{}
	}
	for route := range b.routes {
		out[route] = struct{}{}
	}
	return out
}

func (b *requestBudget) routeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.routes)
}

// The legacy loops counted credentials as soon as they selected one. An
// enforced round only spends a credential slot when business dispatch starts.
func roundCredentialLimitReached(ctx context.Context, attempted map[string]struct{}, limit int) bool {
	if limit == 0 {
		return false
	}
	if RequestBudgetEnforced(ctx) {
		b := requestBudgetFromContext(ctx)
		b.mu.Lock()
		defer b.mu.Unlock()
		if pending := scheduledAlternateRoundFromContext(ctx); pending != nil && b.Round == pending.from {
			return false
		}
		return len(b.routes) >= limit
	}
	return len(attempted) >= limit
}

func requestSentToCredential(ctx context.Context, id string) bool {
	b := requestBudgetFromContext(ctx)
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.credentials[id]
	return ok
}

// RecordRequestStreamOutput marks a payload offered for downstream delivery.
// Marking just before handoff also closes the window between the reader
// receiving output and the scheduler receiving the next failure.
func RecordRequestStreamOutput(ctx context.Context, payload []byte) {
	if streamPayloadCommitsOutput(payload) {
		if b := requestBudgetFromContext(ctx); b != nil {
			b.mu.Lock()
			b.OutputCommitted = true
			updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
			b.mu.Unlock()
		}
	}
}

var errBudgetReplayUnsafe = &Error{Code: "replay_unsafe", Message: "request cannot be safely repeated", HTTPStatus: http.StatusBadGateway}
var errBudgetCredentialLimit = &Error{Code: "request_retry_limit", Message: "request execution budget exhausted", HTTPStatus: http.StatusServiceUnavailable}

func (m *Manager) withBusinessInferenceBudget(ctx context.Context, auth *Auth, req executor.Request, opts executor.Options, routeModel string) context.Context {
	b := requestBudgetFromContext(ctx)
	if b == nil || auth == nil {
		return ctx
	}
	routeIdentity := auth.ID
	if RequestBudgetEnforced(ctx) && !m.HomeEnabled() {
		routeIdentity = m.scheduledRouteIdentity(auth, routeModel)
	}
	if routeIdentity == "" {
		routeIdentity = auth.ID
	}
	unsafe := streamReplayForbidden(opts) || requestMayRunHostedTools(req.Payload) || requestMayRunHostedTools(opts.OriginalRequest)
	return executor.WithBusinessAttemptRecorder(ctx, func(sendCtx context.Context) error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if err := sendCtx.Err(); err != nil {
			return err
		}
		if b.enforced {
			if !b.antigravityAdmit(sendCtx, auth, req.Model) {
				return errBudgetCredentialLimit
			}
			if b.OutputCommitted || (b.ReplayUnsafe && b.Attempts > 0) {
				return errBudgetReplayUnsafe
			}
			if pending := scheduledAlternateRoundFromContext(sendCtx); pending != nil {
				_, triedID := pending.excluded[auth.ID]
				_, triedRoute := pending.excluded[routeIdentity]
				if triedID || triedRoute || (b.Round != pending.from && b.Round != pending.from+1) {
					return errBudgetCredentialLimit
				}
				if b.Round == pending.from {
					b.advanceRoundLocked()
				}
			}
			if _, same := b.routes[routeIdentity]; !same && b.maxCredentials > 0 && len(b.routes) >= b.maxCredentials {
				return errBudgetCredentialLimit
			}
		}
		if b.enforced && b.antigravityFailure.authID != "" && canonicalSchedulingProvider(auth.Provider) != "antigravity" {
			b.UpstreamDecision = "alternate"
		}
		b.ServedModel = ""
		b.Attempts++
		b.RoundAttempts++
		b.credentials[auth.ID] = struct{}{}
		b.routes[routeIdentity] = struct{}{}
		b.ReplayUnsafe = b.ReplayUnsafe || unsafe
		updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
		return nil
	})
}

func requestMayRunHostedTools(payload []byte) bool {
	root := ojson.ParseBytes(payload)
	if root.Get("previous_response_id").Exists() {
		return true
	}
	for _, tool := range root.Get("tools").Array() {
		// Function declarations do not run server-side. Unknown tool kinds
		// may run remotely; don't assume they have verifiable idempotency.
		switch tool.Get("type").String() {
		case "function":
		case "":
			if !tool.Get("name").Exists() && !tool.Get("functionDeclarations").Exists() && !tool.Get("function_declarations").Exists() {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func budgetCanRepeat(ctx context.Context) bool {
	if !RequestBudgetEnforced(ctx) {
		return true
	}
	s, _ := RequestBudgetSnapshotFromContext(ctx)
	return !s.OutputCommitted && !s.ReplayUnsafe && ctx.Err() == nil
}

func isBudgetReplayStop(err error) bool {
	return errors.Is(err, errBudgetReplayUnsafe) || errors.Is(err, errBudgetCredentialLimit)
}

func scheduledUpstreamTransient(err error) bool {
	if err == nil || !hasUpstreamExecutionAttempt(err) {
		return false
	}
	var streamErr *Error
	if errors.As(err, &streamErr) && (streamErr.Code == "empty_stream" || streamErr.Code == "incomplete_stream") {
		return true
	}
	code := statusCodeFromError(err)
	return isRetryableUpstreamFailure(err, clienterror.Classify(code, err.Error())) ||
		(code == http.StatusTooManyRequests && !IsTerminalAuthError(err))
}

func (m *Manager) canOpenScheduledRound(ctx context.Context, opts executor.Options, err error, round, defaultRetry, homeLimit int, providers []string, model string) bool {
	if defaultRetry == 0 || !budgetCanRepeat(ctx) || !scheduledUpstreamTransient(err) {
		return false
	}
	if explicit := m.configuredUpstreamErrorRetryLimit(); explicit != -2 {
		return explicit == -1 || round < explicit
	}
	if m.HomeEnabled() {
		return m.homeRetryAllowed(round, homeLimit)
	}
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	return m.retryAllowedForRequest(ctx, round, providers, model, eligibility, pinnedAuthIDFromMetadata(opts.Metadata), defaultRetry, opts.Headers)
}

// scheduledTrustedRecovery matches the governing deadline against explicit,
// current provenance on the exact blocked model or credential. Default
// backoff, sibling-model hints and older observations cannot open a wait.
func scheduledTrustedRecovery(a *Auth, model string, deadline, now time.Time) bool {
	if a == nil || !deadline.After(now) {
		return false
	}
	if a.Quota.Exceeded && a.Quota.Reason == "credential_quota" && a.Quota.NextRecoverAt.After(now) {
		return a.Quota.NextRecoverAt.Equal(deadline) && a.providerRetryAt.Equal(deadline)
	}
	modelKey := canonicalModelLookupKey(model)
	for key, state := range a.ModelStates {
		if canonicalModelLookupKey(key) != modelKey || state == nil {
			continue
		}
		blocked, _, next := availabilityBlock(state.Unavailable, state.Quota.Exceeded, state.NextRetryAfter, state.Quota.NextRecoverAt, now)
		if blocked && next.Equal(deadline) && state.providerRetryAt.Equal(deadline) {
			return true
		}
	}
	return a.providerRetryAt.Equal(deadline) && (a.credentialRetryAfter.Equal(deadline) || (modelKey == "" && a.NextRetryAfter.Equal(deadline)))
}

type scheduledRetryOpportunity struct {
	ready                bool
	at                   time.Time
	changed              <-chan struct{}
	antigravityShortWait bool
}

func (m *Manager) awaitScheduledRecovery(ctx context.Context, opportunity scheduledRetryOpportunity, singleLimit time.Duration) (bool, error) {
	b := requestBudgetFromContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if opportunity.ready {
		return true, nil
	}
	if opportunity.at.IsZero() || !budgetCanRepeat(ctx) {
		return false, nil
	}
	clock := m.getContinuityClock()
	start := clock.Now()
	wait := opportunity.at.Sub(start)
	if wait <= 0 {
		return !opportunity.antigravityShortWait, nil
	}
	b.mu.Lock()
	if b.waiting || (opportunity.antigravityShortWait && b.antigravityWaitUsed) || wait > singleLimit || wait > b.configuredWait-b.ActiveWait {
		b.mu.Unlock()
		return false, nil
	}
	if deadline, ok := ctx.Deadline(); (ok && !opportunity.at.Before(deadline)) || (!b.deadline.IsZero() && !opportunity.at.Before(b.deadline)) {
		b.mu.Unlock()
		return false, nil
	}
	b.waiting = true
	if opportunity.antigravityShortWait {
		b.antigravityWaitUsed = true
		b.UpstreamDecision = "short_wait"
	}
	b.mu.Unlock()
	executor.NotifyContinuityWaitStart(ctx)
	defer executor.NotifyContinuityWaitEnd(ctx)
	err := waitForRecoverySignal(ctx, clock, wait, opportunity.changed)
	elapsed := clock.Now().Sub(start)
	b.mu.Lock()
	b.ActiveWait += max(0, elapsed)
	b.waiting = false
	updateRoutingAccounting(b.trace.Load(), b.RequestBudgetSnapshot)
	b.mu.Unlock()
	return err == nil, err
}

// The real clock selects directly on the update signal; the existing clock
// seam accepts cancellation, including a cancellation used only to wake a
// controlled wait on a state update.
func waitForRecoverySignal(ctx context.Context, clock continuityClock, wait time.Duration, changed <-chan struct{}) error {
	if _, real := clock.(realContinuityClock); real {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
			return ctx.Err()
		case <-t.C:
			return ctx.Err()
		}
	}
	if changed == nil {
		return clock.Wait(ctx, wait)
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-changed:
			cancel()
		case <-waitCtx.Done():
		}
	}()
	err := clock.Wait(waitCtx, wait)
	if errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return nil
	}
	return err
}

func (m *Manager) scheduledOpportunity(ctx context.Context, providers []string, model string, opts executor.Options, excluded map[string]struct{}, err error) scheduledRetryOpportunity {
	now := m.getContinuityClock().Now()
	if m.HomeEnabled() {
		var cooldown *homeDispatchRetryAfterError
		if errors.As(err, &cooldown) {
			if wait := cooldown.RetryAfter(); wait != nil && *wait > 0 {
				return scheduledRetryOpportunity{at: now.Add(*wait)}
			}
		}
		var exhausted *homeRetryRoundExhaustedError
		if errors.As(err, &exhausted) {
			if exhausted.retryNow {
				return scheduledRetryOpportunity{ready: true}
			}
			if wait := exhausted.RetryAfter(); hasUpstreamExecutionAttempt(err) && wait != nil && *wait > 0 {
				return scheduledRetryOpportunity{at: now.Add(*wait)}
			}
		}
		return scheduledRetryOpportunity{}
	}
	ready, next, changed := m.scheduledNextAvailability(ctx, providers, model, opts, excluded, now)
	return scheduledRetryOpportunity{ready: ready, at: next, changed: changed}
}

type scheduledExecution[T any] func(context.Context, executor.Options, int, int, *int) (T, error)

func runScheduledExecution[T any](m *Manager, ctx context.Context, providers []string, req executor.Request, opts executor.Options, prior error, execute scheduledExecution[T]) (T, error) {
	var zero T
	b := requestBudgetFromContext(ctx)
	defaultRetry, maxCredentials, maxWait := m.retrySettings()
	roundLimit := defaultRetry
	if upstream := m.configuredUpstreamErrorRetryLimit(); upstream == -1 {
		roundLimit = int(^uint(0) >> 1)
	} else if upstream > roundLimit {
		roundLimit = upstream
	}
	model := authSelectionModelFromOptions(opts, req.Model)
	homeLimit := -1
	var previous error
	// A failed stream that never reached an outer caller still carries the
	// transport evidence from the live attempt.
	if prior != nil {
		previous = prior
		if !budgetCanRepeat(ctx) || !scheduledUpstreamTransient(prior) {
			return zero, prior
		}
	}
	first := true
	homeWaitedAfter := -1
	roundCause := prior
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		s, _ := RequestBudgetSnapshotFromContext(ctx)
		if !budgetCanRepeat(ctx) {
			if previous != nil {
				return zero, previous
			}
			return zero, errBudgetReplayUnsafe
		}
		attempted := b.credentialSnapshot()
		ctxRound := seedScheduledRoundExclusions(ctx, attempted)
		room := maxCredentials == 0 || b.routeCount() < maxCredentials
		if room && (first || m.scheduledOpportunity(ctx, providers, model, opts, attempted, nil).ready) {
			result, err := execute(ctxRound, withAttemptedAuthTracker(opts, make(map[string]struct{})), s.Round, roundLimit, &homeLimit)
			if err == nil {
				return result, nil
			}
			if ctx.Err() != nil {
				return zero, ctx.Err()
			}
			if isRequestInvalidError(err) || isRequestTerminatedError(err) || isRequestStopError(err) || isSchedulerRejectError(err) {
				return zero, err
			}
			// Keep the best actual upstream result for the public
			// response, but never authorize a new round using evidence
			// from an earlier round that exhausted its opportunity.
			if previous == nil || hasUpstreamExecutionAttempt(err) {
				previous = err
			}
			if hasUpstreamExecutionAttempt(err) || roundCause == nil {
				roundCause = err
			}
			if !budgetCanRepeat(ctx) {
				return zero, previous
			}
			attempted = b.credentialSnapshot()
			room = maxCredentials == 0 || b.routeCount() < maxCredentials
		}
		first = false
		if facts := scheduledAntigravity429(previous); facts != nil {
			if !m.canOpenScheduledRound(ctx, opts, previous, s.Round, defaultRetry, homeLimit, providers, model) {
				return zero, scheduledAntigravityTerminal(ctx, facts)
			}
			// A full credential round may have stopped before an eligible
			// provider was reached. Try that provider without waiting. Home
			// owns its selection, so only a real send opens the next round.
			if !room && (m.HomeEnabled() || m.scheduledOpportunity(ctx, providers, model, opts, attempted, nil).ready) {
				probe := &scheduledAlternateRound{from: s.Round, excluded: attempted}
				alternateCtx := context.WithValue(seedScheduledRoundExclusions(ctx, attempted), scheduledAlternateRoundKey{}, probe)
				alternateHomeLimit := homeLimit
				result, alternateErr := execute(alternateCtx, withAttemptedAuthTracker(opts, make(map[string]struct{})), s.Round+1, roundLimit, &alternateHomeLimit)
				if ctx.Err() != nil {
					return zero, ctx.Err()
				}
				if alternateErr == nil {
					return result, nil
				}
				if current, _ := RequestBudgetSnapshotFromContext(ctx); current.Round != s.Round {
					if isRequestInvalidError(alternateErr) || isRequestTerminatedError(alternateErr) || isRequestStopError(alternateErr) || isSchedulerRejectError(alternateErr) {
						return zero, alternateErr
					}
					homeLimit = alternateHomeLimit
					previous, roundCause = alternateErr, alternateErr
					continue
				}
			}
			delay := facts.RetryAt.Sub(facts.ObservedAt)
			if delay <= 0 || delay >= 3*time.Second {
				return zero, scheduledAntigravityTerminal(ctx, facts)
			}
			// Immediately usable alternatives have already been exhausted.
			// This one recovery targets precisely the same credential and model.
			opportunity := scheduledRetryOpportunity{at: facts.RetryAt, antigravityShortWait: true}
			proceed, waitErr := m.awaitScheduledRecovery(ctx, opportunity, maxWait)
			if waitErr != nil {
				return zero, waitErr
			}
			if !proceed || !b.nextRound(s.Round) {
				return zero, scheduledAntigravityTerminal(ctx, facts)
			}
			retryCtx, retryOpts := b.scheduledAntigravityRepeat(ctx, opts)
			result, retryErr := execute(retryCtx, retryOpts, s.Round+1, roundLimit, &homeLimit)
			if ctx.Err() != nil {
				return zero, ctx.Err()
			}
			if retryErr == nil {
				return result, nil
			}
			if retryFacts := scheduledAntigravity429(retryErr); retryFacts != nil {
				return zero, scheduledAntigravityTerminal(ctx, retryFacts)
			}
			if hasUpstreamExecutionAttempt(retryErr) || isRequestTerminatedError(retryErr) {
				return zero, retryErr
			}
			return zero, scheduledAntigravityTerminal(ctx, facts)
		}
		if room {
			opportunity := m.scheduledOpportunity(ctx, providers, model, opts, attempted, roundCause)
			// Home already explored its entire round in one RPC loop. A
			// typed pre-admission cooldown is the sole same-round wait.
			if m.HomeEnabled() {
				if !isHomeDispatchCooldown(roundCause) || homeWaitedAfter == s.Attempts {
					opportunity = scheduledRetryOpportunity{}
				}
			}
			// Readiness without a concrete recovery can be a result of a
			// preparation failure (no business send), so never spin on it.
			if !opportunity.ready && !opportunity.at.IsZero() {
				if proceed, err := m.awaitScheduledRecovery(ctx, opportunity, maxWait); err != nil {
					return zero, err
				} else if proceed {
					homeWaitedAfter = s.Attempts
					roundCause = nil
					first = true
					continue
				}
			}
		}
		if !m.canOpenScheduledRound(ctx, opts, roundCause, s.Round, defaultRetry, homeLimit, providers, model) {
			break
		}
		opportunity := m.scheduledOpportunity(ctx, providers, model, opts, nil, roundCause)
		if m.configuredUpstreamErrorRetryLimit() == -1 && opportunity.ready &&
			(m.HomeEnabled() || !m.scheduledOpportunity(ctx, providers, model, opts, attempted, nil).ready) {
			// Unlimited means bounded recovery from actual transient failure.
			// Do not turn disabled cooldown/no hint into an unbounded tight loop.
			break
		}
		proceed, err := m.awaitScheduledRecovery(ctx, opportunity, maxWait)
		if err != nil {
			return zero, err
		}
		if !proceed || !b.nextRound(s.Round) {
			break
		}
		roundCause = nil
		first = true
	}
	if previous != nil && (hasUpstreamExecutionAttempt(previous) || isBudgetReplayStop(previous)) {
		return zero, previous
	}
	return zero, newNoAvailableRouteError(model)
}

func isHomeDispatchCooldown(err error) bool {
	var cooldown *homeDispatchRetryAfterError
	return errors.As(err, &cooldown)
}

func seedScheduledRoundExclusions(ctx context.Context, attempted map[string]struct{}) context.Context {
	ids := streamReplayExcludedAuthIDsFromContext(ctx)
	merged := append([]string(nil), ids...)
	for id := range attempted {
		if !slices.Contains(ids, id) {
			merged = append(merged, id)
		}
	}
	return withStreamReplayExcludedAuthIDs(ctx, merged)
}

func (m *Manager) executeScheduledStream(ctx context.Context, providers []string, req executor.Request, opts executor.Options, pinnedThread bool) (*executor.StreamResult, error) {
	run := func(ctx context.Context, prior error) (*executor.StreamResult, error) {
		return runScheduledExecution(m, ctx, providers, req, opts, prior, func(ctx context.Context, opts executor.Options, round, roundLimit int, homeLimit *int) (*executor.StreamResult, error) {
			_, maxCredentials, _ := m.retrySettings()
			return m.executeStreamMixedOnce(ctx, providers, req, opts, maxCredentials, homeLimit, round, roundLimit)
		})
	}
	if !m.HomeEnabled() && !streamReplayForbidden(opts) && !executor.RequiredUpstreamWebsocket(ctx) {
		ctx = withStreamReplayCoordinator(ctx, func(replayCtx context.Context, cause error) (*executor.StreamResult, error) {
			// Retain the original scheduler scope but not the transport's
			// per-attempt exclusions: the shared ledger seeds them by round.
			return run(withStreamReplayExcludedAuthIDs(replayCtx, nil), cause)
		})
	}
	res, err := run(ctx, nil)
	if RoutingTraceID(ctx) == "" || !hasUpstreamExecutionAttempt(err) {
		err = unwrapExecutionBoundaryError(err)
	}
	if pinnedThread && err != nil && !isRequestStopError(err) {
		err = claudeThreadReplayError(err)
	}
	var bootstrapErr *streamBootstrapError
	if errors.As(err, &bootstrapErr) {
		return streamErrorResult(bootstrapErr.Headers(), err), nil
	}
	return res, err
}
