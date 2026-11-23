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

type RoutingTrace struct {
	RequestID           string               `json:"request_id"`
	Model               string               `json:"model"`
	Mode                string               `json:"mode"`
	StartedAt           time.Time            `json:"started_at"`
	Stages              []SchedulingDecision `json:"stages"`
	OmittedStages       int                  `json:"omitted_stages,omitempty"`
	SendCount           int                  `json:"send_count"`
	Round               int                  `json:"round"`
	RoundSends          int                  `json:"round_sends"`
	WaitMS              int64                `json:"wait_ms"`
	OutputCommitted     bool                 `json:"output_committed"`
	ReplayUnsafe        bool                 `json:"replay_unsafe"`
	UpstreamCategory    string               `json:"upstream_category,omitempty"`
	UpstreamRetrySource string               `json:"upstream_retry_source,omitempty"`
	RetryStopReason     string               `json:"retry_stop_reason,omitempty"`
	Terminal            *RoutingTerminal     `json:"terminal,omitempty"`
}

type routingTraceStore struct {
	mu    sync.Mutex
	next  int
	slots [routingTraceEntries]*routingTrace
}

type routingTrace struct {
	mu      sync.Mutex
	data    RoutingTrace
	collect bool
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
	t := &routingTrace{collect: providerSchedulingCaller(ctx) != "", data: RoutingTrace{
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
	s.slots[s.next] = t
	s.next = (s.next + 1) % len(s.slots)
	s.mu.Unlock()
	return t.data.RequestID
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
	var found *routingTrace
	for i, entry := range s.slots {
		if entry == nil {
			continue
		}
		if !entry.data.StartedAt.Add(routingTraceTTL).After(now) {
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
	case status >= 400 || err != nil:
		code = "failed"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.data.Terminal == nil {
		t.data.Terminal = &RoutingTerminal{Code: code, Status: status}
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
	var terminated *executor.RequestTerminatedError
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &terminated) {
		return err
	}
	budget, _ := RequestBudgetSnapshotFromContext(ctx)
	var ag *executor.AntigravityResourceExhausted
	actual := budget.Attempts > 0 && (hasUpstreamExecutionAttempt(err) || errors.As(err, &ag))
	failure := &RoutingFailure{Model: trace.data.Model, RequestID: trace.data.RequestID, status: status}
	switch {
	case errors.As(err, &local):
		failure.status = http.StatusServiceUnavailable
		failure.Code, failure.Type, failure.Message = "no_available_route", "server_error", "No route is currently available for this model."
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
