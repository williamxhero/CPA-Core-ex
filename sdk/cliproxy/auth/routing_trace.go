package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	moejson "github.com/MoeForge/moego/json"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const (
	routingTraceEntries = 256
	routingTraceTTL     = 15 * time.Minute
	routingTraceStages  = 12
	routingTraceRows    = 64
)

type RoutingTerminal struct {
	Code   string `json:"code"`
	Status int    `json:"status"`
}

// RoutingRetryPolicy is the policy attached to the pilot request ledger, not
// the configured allowlist or the settings of a subsequent reload.
type RoutingRetryPolicy struct {
	SourceFormat            string                                       `json:"source_format"`
	UpstreamErrorRetryLimit int                                          `json:"upstream_error_retry_limit"`
	AdmissionCadence        internalconfig.PersistentRetryCadence        `json:"admission_cadence"`
	Cadence                 internalconfig.PersistentRetryCadence        `json:"cadence"`
	AdmissionWaiterCapacity internalconfig.PersistentRetryWaiterCapacity `json:"admission_waiter_capacity"`
	WaiterCapacity          internalconfig.PersistentRetryWaiterCapacity `json:"waiter_capacity"`
	WaiterBufferBytes       int                                          `json:"waiter_buffer_bytes"`
}

type RoutingRecoveryWait struct {
	NotBefore       *time.Time `json:"not_before,omitempty"`
	ProbePending    bool       `json:"probe_pending,omitempty"`
	CapacityPending bool       `json:"capacity_pending,omitempty"`
	RefreshPending  bool       `json:"refresh_pending,omitempty"`
	QueuePending    bool       `json:"queue_pending,omitempty"`
	TimingSource    string     `json:"timing_source,omitempty"`
	Waiters         int        `json:"waiters"`
	CadenceTier     string     `json:"cadence_tier,omitempty"`
}

// RoutingPilotRecovery is a redacted snapshot of one eligible fault group.
type RoutingPilotRecovery struct {
	CadenceTier          string                                 `json:"cadence_tier,omitempty"`
	TimingSource         string                                 `json:"timing_source,omitempty"`
	NextProbeAt          *time.Time                             `json:"next_probe_at,omitempty"`
	StableSince          *time.Time                             `json:"stable_since,omitempty"`
	FaultAgeMS           int64                                  `json:"fault_age_ms"`
	Failures             int                                    `json:"failures"`
	Probes               int                                    `json:"probes"`
	Slots                int                                    `json:"slots"`
	SlotLimit            int                                    `json:"slot_limit,omitempty"`
	Waiters              int                                    `json:"waiters"`
	ConsecutiveSuccesses int                                    `json:"consecutive_successes"`
	Alarmed              bool                                   `json:"alarmed"`
	Resolved             bool                                   `json:"resolved,omitempty"`
	Cadence              *internalconfig.PersistentRetryCadence `json:"cadence,omitempty"`
}

type RoutingTrace struct {
	RequestID           string                `json:"request_id"`
	Model               string                `json:"model"`
	Mode                string                `json:"mode"`
	StartedAt           time.Time             `json:"started_at"`
	Stages              []SchedulingDecision  `json:"stages"`
	OmittedStages       int                   `json:"omitted_stages,omitempty"`
	SendCount           int                   `json:"send_count"`
	Round               int                   `json:"round"`
	RoundSends          int                   `json:"round_sends"`
	WaitMS              int64                 `json:"wait_ms"`
	OutputCommitted     bool                  `json:"output_committed"`
	ReplayUnsafe        bool                  `json:"replay_unsafe"`
	UpstreamCategory    string                `json:"upstream_category,omitempty"`
	UpstreamRetrySource string                `json:"upstream_retry_source,omitempty"`
	RetryStopReason     string                `json:"retry_stop_reason,omitempty"`
	RetryPolicy         *RoutingRetryPolicy   `json:"retry_policy,omitempty"`
	LastRecoveryWait    *RoutingRecoveryWait  `json:"last_recovery_wait,omitempty"`
	PilotRecovery       *RoutingPilotRecovery `json:"pilot_recovery,omitempty"`
	Terminal            *RoutingTerminal      `json:"terminal,omitempty"`
}

const routingActivePilotEntries = internalconfig.PersistentRetryMaxWaiters * 2

type routingTraceStore struct {
	mu     sync.Mutex
	next   int
	slots  [routingTraceEntries]*routingTrace
	active map[string]*routingTrace
}

func (s *routingTraceStore) putLocked(t *routingTrace) {
	s.slots[s.next] = t
	s.next = (s.next + 1) % len(s.slots)
}

type routingTrace struct {
	mu         sync.Mutex
	data       RoutingTrace
	collect    bool
	store      *routingTraceStore
	now        func() time.Time
	retainedAt time.Time // under store.mu; completion time for a retained pilot
}

func routingTraceFromContext(ctx context.Context) *routingTrace {
	if b := requestBudgetFromContext(ctx); b != nil {
		return b.trace.Load()
	}
	return nil
}

func RoutingTraceID(ctx context.Context) string {
	if trace := routingTraceFromContext(ctx); trace != nil {
		return trace.data.RequestID
	}
	return ""
}

func (m *Manager) StartRoutingTrace(ctx context.Context, requestedModel, routingModel string) string {
	if m == nil {
		return ""
	}
	b := requestBudgetFromContext(ctx)
	if b == nil {
		return ""
	}
	if previous := b.trace.Load(); previous != nil {
		return previous.data.RequestID
	}
	mode := m.providerSchedulingMode(ctx, routingModel)
	if mode != internalconfig.ProviderSchedulingShadow && mode != internalconfig.ProviderSchedulingEnforce {
		return ""
	}

	id, err := uuid.NewV7()
	if err != nil {
		return ""
	}
	if !safeRoutingModel(requestedModel) {
		requestedModel = ""
	}
	t := &routingTrace{collect: providerSchedulingCaller(ctx) != "", store: &m.routingTraces, now: m.getContinuityClock().Now, data: RoutingTrace{
		RequestID: id.String(), Mode: mode, Model: requestedModel,
		StartedAt: m.getContinuityClock().Now().UTC(), Stages: make([]SchedulingDecision, 0),
	}}
	if !b.trace.CompareAndSwap(nil, t) {
		return b.trace.Load().data.RequestID
	}
	if !t.collect {
		return t.data.RequestID
	}
	s := &m.routingTraces
	s.mu.Lock()
	if s.active[t.data.RequestID] == nil && t.retainedAt.IsZero() {
		s.putLocked(t)
	}
	s.mu.Unlock()
	return t.data.RequestID
}

func (m *Manager) retainPilotTrace(t *routingTrace) bool {
	if t == nil || !t.collect {
		return true
	}
	s := t.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[t.data.RequestID] == t || !t.retainedAt.IsZero() {
		return true
	}
	if len(s.active) >= routingActivePilotEntries {
		return false
	}
	if s.active == nil {
		s.active = make(map[string]*routingTrace)
	}
	for i, entry := range s.slots {
		if entry == t {
			s.slots[i] = nil
		}
	}
	s.active[t.data.RequestID] = t
	return true
}

// Only public model identifiers can be projected, never an arbitrary payload.
func safeRoutingModel(model string) bool {
	if len(model) == 0 || len(model) > 128 {
		return false
	}
	for _, r := range model {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '/' || r == ':' || r == '.' || r == '(' || r == ')') {
			return false
		}
	}
	return true
}

func (m *Manager) RoutingTrace(id string) (RoutingTrace, bool) {
	if m == nil {
		return RoutingTrace{}, false
	}
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.Version() != 7 || id != parsed.String() {
		return RoutingTrace{}, false
	}
	now := m.getContinuityClock().Now()
	s := &m.routingTraces
	s.mu.Lock()
	found := s.active[id]
	for i, entry := range s.slots {
		if found != nil {
			break
		}
		if entry == nil {
			continue
		}
		retainedAt := entry.retainedAt
		if retainedAt.IsZero() {
			retainedAt = entry.data.StartedAt
		}
		if !retainedAt.Add(routingTraceTTL).After(now) {
			s.slots[i] = nil
			continue
		}
		if entry.data.RequestID == id {
			found = entry
		}
	}
	s.mu.Unlock()
	if found == nil {
		return RoutingTrace{}, false
	}
	found.mu.Lock()
	defer found.mu.Unlock()
	view := found.data
	view.Stages = append([]SchedulingDecision{}, found.data.Stages...)
	for i := range view.Stages {
		view.Stages[i].Candidates = cloneSchedulingRows(view.Stages[i].Candidates)
	}
	if view.RetryPolicy != nil {
		policy := *view.RetryPolicy
		view.RetryPolicy = &policy
	}
	if view.LastRecoveryWait != nil {
		wait := *view.LastRecoveryWait
		if wait.NotBefore != nil {
			at := *wait.NotBefore
			wait.NotBefore = &at
		}
		view.LastRecoveryWait = &wait
	}
	if view.PilotRecovery != nil {
		recovery := *view.PilotRecovery
		if recovery.Cadence != nil {
			cadence := *recovery.Cadence
			recovery.Cadence = &cadence
		}
		if recovery.NextProbeAt != nil {
			at := *recovery.NextProbeAt
			recovery.NextProbeAt = &at
		}
		if recovery.StableSince != nil {
			at := *recovery.StableSince
			recovery.StableSince = &at
		}
		view.PilotRecovery = &recovery
	}
	if view.Terminal != nil {
		terminal := *view.Terminal
		view.Terminal = &terminal
	}
	return view, true
}

func routingTraceCollects(ctx context.Context) bool {
	trace := routingTraceFromContext(ctx)
	return trace != nil && trace.collect
}

func recordRoutingStage(ctx context.Context, decision SchedulingDecision) {
	t := routingTraceFromContext(ctx)
	if t == nil || !t.collect {
		return
	}
	if len(decision.Candidates) > routingTraceRows {
		decision.OmittedCandidates = len(decision.Candidates) - routingTraceRows
	}
	decision.Candidates = cloneSchedulingRows(decision.Candidates[:min(routingTraceRows, len(decision.Candidates))])
	// The request's accepted public identifier is authoritative. A plugin or
	// mapped route can use an internal selection identifier.
	decision.Model = t.data.Model
	decision.SelectedResourceID = catalogRoutingID(decision.SelectedResourceID)
	decision.ActualResourceID = catalogRoutingID(decision.ActualResourceID)
	decision.ProposedResourceID = catalogRoutingID(decision.ProposedResourceID)
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.data.Stages) < routingTraceStages {
		t.data.Stages = append(t.data.Stages, decision)
	} else {
		t.data.Stages[routingTraceStages-1] = decision
		t.data.OmittedStages++
	}
}

func catalogRoutingID(raw string) string {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw {
		return ""
	}
	return raw
}

func recordRoutingRetryPolicy(t *routingTrace, sourceFormat string, limit int, cfg internalconfig.PersistentRetryConfig) {
	if t == nil || !t.collect {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data.RetryPolicy = &RoutingRetryPolicy{SourceFormat: sourceFormat, UpstreamErrorRetryLimit: limit, AdmissionCadence: cfg.Cadence(), Cadence: cfg.Cadence(), AdmissionWaiterCapacity: cfg.WaiterCapacity(), WaiterCapacity: cfg.WaiterCapacity(), WaiterBufferBytes: pilotWaitBufferBytes}
}

func recordWaiterCapacity(t *routingTrace, capacity internalconfig.PersistentRetryWaiterCapacity) {
	if t == nil || !t.collect {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if policy := t.data.RetryPolicy; policy != nil {
		policy.WaiterCapacity = capacity
	}
}

func recordRoutingRecoveryWait(t *routingTrace, opportunity scheduledRetryOpportunity) {
	if t == nil || !t.collect || !opportunity.persistentWait {
		return
	}
	wait := &RoutingRecoveryWait{ProbePending: opportunity.probePending, CapacityPending: opportunity.capacityPending, RefreshPending: opportunity.refreshPending,
		QueuePending: opportunity.queuePending, TimingSource: opportunity.timingSource, Waiters: opportunity.waiters, CadenceTier: opportunity.cadenceTier}
	if !opportunity.at.IsZero() {
		at := opportunity.at.UTC()
		wait.NotBefore = &at
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data.LastRecoveryWait = wait
}

func recordPilotRecovery(t *routingTrace, view RoutingPilotRecovery) {
	if t == nil || !t.collect {
		return
	}
	t.mu.Lock()
	t.data.PilotRecovery = &view
	if policy := t.data.RetryPolicy; policy != nil && view.Cadence != nil {
		policy.Cadence = *view.Cadence
	}
	t.mu.Unlock()
}

func updateRoutingAccounting(t *routingTrace, accounting RequestBudgetSnapshot) {
	if t == nil || !t.collect {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data.SendCount, t.data.Round, t.data.RoundSends = accounting.Attempts, accounting.Round, accounting.RoundAttempts
	t.data.WaitMS = accounting.ActiveWait.Milliseconds()
	t.data.OutputCommitted, t.data.ReplayUnsafe = accounting.OutputCommitted, accounting.ReplayUnsafe
	t.data.UpstreamCategory = accounting.UpstreamCategory
	t.data.UpstreamRetrySource = accounting.UpstreamRetrySource
	t.data.RetryStopReason = accounting.RetryStopReason
}

func FinishRoutingTrace(ctx context.Context, status int, err error) {
	t := routingTraceFromContext(ctx)
	if t == nil || !t.collect {
		return
	}
	if PersistentRetryPilot(ctx) {
		err = pilotLifecycleError(ctx, err)
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			requestBudgetFromContext(ctx).setRetryStop(retryStopDeadlineExceeded)
		case errors.Is(err, context.Canceled):
			requestBudgetFromContext(ctx).setRetryStop(retryStopCanceled)
		}
	}
	accounting, _ := RequestBudgetSnapshotFromContext(ctx)
	updateRoutingAccounting(t, accounting)
	code := "succeeded"
	var failure *RoutingFailure
	switch {
	case errors.As(err, &failure):
		code = failure.Code
	case errors.Is(err, context.Canceled):
		code, status = "canceled", 499
	case errors.Is(err, context.DeadlineExceeded):
		code = "deadline_exceeded"
		if status == 0 {
			status = http.StatusGatewayTimeout
		}
	case status >= 400 || err != nil:
		code = "failed"
	}
	t.mu.Lock()
	if t.data.Terminal == nil {
		t.data.Terminal = &RoutingTerminal{Code: code, Status: status}
	}
	t.mu.Unlock()
	s := t.store
	if s != nil {
		finishedAt := t.now()
		s.mu.Lock()
		if s.active[t.data.RequestID] == t {
			delete(s.active, t.data.RequestID)
			t.retainedAt = finishedAt
			s.putLocked(t)
		}
		s.mu.Unlock()
	}
}

// RoutingFailure owns the only fields exposed for an enforced scheduling
// failure. It intentionally cannot unwrap to raw upstream bodies or headers.
type RoutingFailure struct {
	Code           string `json:"code"`
	Type           string `json:"type"`
	Message        string `json:"message"`
	Model          string `json:"model,omitempty"`
	RequestID      string `json:"request_id,omitempty"`
	UpstreamStatus string `json:"status,omitempty"`
	status         int
	retryAt        time.Time
	now            func() time.Time
}

func (e *RoutingFailure) StatusCode() int { return e.status }
func (e *RoutingFailure) SafeResponseHeaders() http.Header {
	if e.retryAt.IsZero() || e.now == nil {
		return nil
	}
	return safeRetryAfterHeader(e.retryAt.Sub(e.now()))
}

func (e *RoutingFailure) Error() string {
	body, _ := moejson.Marshal(struct {
		Error *RoutingFailure `json:"error"`
	}{e})
	return string(body)
}

func RoutingErrorForResponse(ctx context.Context, err error) error {
	trace := routingTraceFromContext(ctx)
	if trace == nil || err == nil || trace.data.Mode != internalconfig.ProviderSchedulingEnforce {
		return err
	}
	status := clienterror.HTTPStatusFromError(err)
	var local localNoAvailableRoute
	var capacity pilotBackpressure
	var terminated *executor.RequestTerminatedError
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &terminated) {
		return err
	}
	budget, _ := RequestBudgetSnapshotFromContext(ctx)
	var ag *executor.AntigravityResourceExhausted
	actual := budget.Attempts > 0 && (hasUpstreamExecutionAttempt(err) || errors.As(err, &ag))
	failure := &RoutingFailure{Model: trace.data.Model, RequestID: trace.data.RequestID, status: status}
	switch {
	case errors.As(err, &capacity):
		failure.status = http.StatusServiceUnavailable
		failure.Code, failure.Type, failure.Message = "local_backpressure", "server_error", capacity.Error()
	case errors.As(err, &local):
		failure.status = http.StatusServiceUnavailable
		failure.Code, failure.Type, failure.Message = "no_available_route", "server_error", "No route is currently available for this model."
	case actual && budget.RetryStopReason == string(retryStopRetryLimit) && isPilotRouteRejection(err):
		// The final credential's denial does not describe the paced route
		// the request could have used with another business send.
		failure.status = budget.pacedStatus
		if failure.status < 400 || failure.status > 599 {
			failure.status = http.StatusBadGateway
		}
		failure.Code, failure.Type, failure.Message = "upstream_unavailable", "server_error", "The upstream service could not complete the request."
		if failure.status == http.StatusTooManyRequests {
			failure.Code, failure.Type, failure.Message = "rate_limit_exceeded", "rate_limit_error", "The upstream rate limit was reached."
		}
	case actual && pilotCodexFailure(err) == PilotCodexQuota:
		failure.Code, failure.Type, failure.Message = "quota_exhausted", "rate_limit_error", "The upstream rejected this route for quota exhaustion."
	case actual && status == http.StatusTooManyRequests:
		failure.Code, failure.Type, failure.Message = "rate_limit_exceeded", "rate_limit_error", "The upstream rate limit was reached."
		// #54 defines these structured, normalized facts as applicable to
		// the terminal request. A generic per-credential header cannot
		// advertise when mixed local restrictions will clear.
		if ag != nil {
			failure.UpstreamStatus = "RESOURCE_EXHAUSTED"
			if ag.RetrySource != "" && ag.RetryAt.After(ag.ObservedAt) {
				failure.retryAt, failure.now = ag.RetryAt, func() time.Time { return RequestBudgetNow(ctx) }
			}
		}
	case actual && pilotCodexFailure(err) != "":
		fact := pilotCodexFailure(err)
		failure.Code, failure.Type, failure.Message = string(fact), "server_error", "The upstream service could not complete the request."
		switch fact {
		case PilotCodexInvalid, PilotCodexPolicy:
			failure.Type, failure.Message = "invalid_request_error", "The upstream rejected this request."
		case PilotCodexAuth, PilotCodexRevoked:
			failure.status = http.StatusBadGateway
			failure.Message = "The upstream credential could not authenticate."
		case PilotCodexPermission, PilotCodexModel:
			failure.status = http.StatusBadGateway
		case PilotCodexRecoverable:
			failure.Code = "upstream_unavailable"
		}
	case pilotCodexTerminalFallback(budget, actual, status):
		failure.Code, failure.Type, failure.Message = "upstream_unavailable", "server_error", "The upstream service could not complete the request."
		if !actual {
			failure.Code, failure.Message = "local_dispatch_rejected", "The request could not be dispatched."
			if status >= 400 && status < 500 {
				failure.Code, failure.Type, failure.Message = "invalid_request", "invalid_request_error", "The request failed local validation."
			}
		}
	case actual && (status == http.StatusUnauthorized || status == http.StatusForbidden):
		failure.status = http.StatusBadGateway
		failure.Code, failure.Type, failure.Message = "upstream_authentication_required", "server_error", "The upstream credential could not authenticate."
	case actual && status >= 500 && status <= 599:
		failure.Code, failure.Type, failure.Message = "upstream_unavailable", "server_error", "The upstream service could not complete the request."
	default:
		return err
	}
	return failure
}

func pilotCodexTerminalFallback(budget RequestBudgetSnapshot, actual bool, status int) bool {
	switch retryStopReason(budget.RetryStopReason) {
	case retryStopLocalValidation, retryStopLocalDispatch:
		return !actual
	case retryStopRequestPolicy, retryStopStreamRecoveryLimit, retryStopOutputCommitted, retryStopReplayUnsafe:
		return actual && status < http.StatusInternalServerError
	}
	return false
}
