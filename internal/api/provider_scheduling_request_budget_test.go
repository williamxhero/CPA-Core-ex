package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
)

func TestProviderSchedulingUnlimitedRetryDoesNotPollWithoutTrustedHint(t *testing.T) {
	f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) {
		emit("{\"type\":\"error\",\"error\":{\"type\":\"server_error\",\"code\":\"rate_limit_exceeded\",\"message\":\"rate limited\"}}")
	})
	cfg := f.inventory.server.cfg
	cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
	f.inventory.manager.SetConfig(cfg)
	f.inventory.manager.SetRetryConfig(0, time.Second, 3)
	f.inventory.manager.SetUpstreamErrorRetryLimit(-1)

	status, body := f.request(t, "http", nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("want actual upstream 429, got %d: %s", status, body)
	}
	f.assertAttempts(t, "A,P,B")
}

type providerBudgetClock struct {
	now     atomic.Pointer[time.Time]
	waits   chan time.Duration
	advance bool
}

func newProviderBudgetClock(now time.Time, advance bool) *providerBudgetClock {
	clock := &providerBudgetClock{waits: make(chan time.Duration, 8), advance: advance}
	clock.now.Store(&now)
	return clock
}
func (c *providerBudgetClock) Now() time.Time { return *c.now.Load() }
func (c *providerBudgetClock) Wait(ctx context.Context, d time.Duration) error {
	c.waits <- d
	if c.advance {
		now := c.Now().Add(d)
		c.now.Store(&now)
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestProviderSchedulingControlledRecovery(t *testing.T) {
	coreauth.SetTransientErrorCooldownSeconds(1)
	t.Cleanup(func() { coreauth.SetTransientErrorCooldownSeconds(0) })
	for _, test := range []struct {
		name       string
		recovery   time.Duration
		synthetic  bool
		maxWait    time.Duration
		activeWait string
		deadline   time.Duration
		earlyWake  bool
		backup     bool
		canceled   bool
		wantStatus int
		wantWait   time.Duration
		wantCalls  string
	}{
		{name: "healthy backup", recovery: 135 * time.Hour, maxWait: time.Second, backup: true, wantStatus: 200, wantCalls: "P"},
		{name: "exact short recovery", recovery: 700 * time.Millisecond, maxWait: time.Second, wantStatus: 200, wantWait: 700 * time.Millisecond, wantCalls: "A"},
		{name: "long recovery", recovery: 135 * time.Hour, maxWait: time.Second, wantStatus: 503},
		{name: "synthetic transient cooldown", synthetic: true, maxWait: 20 * time.Second, wantStatus: 503},
		{name: "unknown recovery", maxWait: time.Second, wantStatus: 503},
		{name: "single wait budget", recovery: 700 * time.Millisecond, maxWait: 500 * time.Millisecond, wantStatus: 503},
		{name: "shared active budget", recovery: 700 * time.Millisecond, maxWait: time.Second, activeWait: "500ms", wantStatus: 503},
		{name: "client deadline", recovery: 700 * time.Millisecond, maxWait: time.Second, deadline: 400 * time.Millisecond, wantStatus: 503},
		{name: "wake early on healthy backup", recovery: 700 * time.Millisecond, maxWait: time.Second, earlyWake: true, wantStatus: 200, wantWait: 100 * time.Millisecond, wantCalls: "P"},
		{name: "cancel during wait", recovery: 700 * time.Millisecond, maxWait: time.Second, canceled: true, wantWait: 700 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) { emit(combinedCapacitySuccess) })
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce", MaxActiveWait: "20s"}
			if test.activeWait != "" {
				cfg.Routing.ProviderScheduling.MaxActiveWait = test.activeWait
			}
			m.SetConfig(&cfg)
			m.SetRetryConfig(0, test.maxWait, 3)
			m.SetUpstreamErrorRetryLimit(-1)
			var until time.Time
			var backup *coreauth.Auth
			start := time.Now()
			for _, a := range m.List() {
				key := a.Attributes["api_key"]
				if key == "A" && (test.recovery > 0 || test.synthetic) {
					var hint *time.Duration
					if !test.synthetic {
						hint = &test.recovery
					}
					m.MarkResult(context.Background(), coreauth.Result{
						AuthID: a.ID, Provider: a.Provider, Model: "capacity-gate-model", RetryAfter: hint,
						Error: &coreauth.Error{HTTPStatus: 429, Code: coreauth.ErrorCodeTransientRateLimit, Message: "rate limited"},
					})
					a, _ = m.GetByID(a.ID)
					until = a.ModelStates["capacity-gate-model"].NextRetryAfter
					continue
				}
				if key == "P" && test.backup {
					continue
				}
				if key == "P" && test.earlyWake {
					backup = a.Clone()
				}
				a.Disabled = true
				if _, err := m.Update(context.Background(), a); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			if test.synthetic {
				now = start
			} else if !until.IsZero() {
				now = until.Add(-test.recovery)
			}
			clock := newProviderBudgetClock(now, !test.canceled && !test.earlyWake)
			m.SetContinuityClockForTest(clock)

			request, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.deadline > 0 {
				var stop context.CancelFunc
				request, stop = context.WithTimeout(request, test.deadline)
				defer stop()
			}
			// A real API handler and router, with host-local budget observation. The
			// predictor's actual HTTP sends are recorded by the controlled provider.
			request = coreauth.WithRequestBudget(request)
			handler := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m))
			engine := gin.New()
			engine.POST("/v1/responses", handler.Responses)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("{\"model\":\"capacity-gate-model\",\"input\":[]}")).WithContext(request)
			req.Header.Set("Content-Type", "application/json")
			done := make(chan struct{})
			go func() { engine.ServeHTTP(recorder, req); close(done) }()
			if test.canceled || test.earlyWake {
				select {
				case d := <-clock.waits:
					if d != test.recovery {
						t.Fatalf("requested wait = %s, want %s", d, test.recovery)
					}
				case <-done:
					t.Fatalf("request terminated before short wait: %d %s", recorder.Code, recorder.Body)
				case <-time.After(4 * time.Second):
					t.Fatal("request never entered the controlled wait")
				}
				if test.canceled {
					cancel()
				} else {
					advanced := now.Add(test.wantWait)
					clock.now.Store(&advanced)
					if _, err := m.Update(context.Background(), backup); err != nil {
						t.Fatal(err)
					}
				}
			}
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("request did not finish")
			}
			if !test.canceled && recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.wantStatus, recorder.Body)
			}
			f.mu.Lock()
			actual := strings.Join(f.attempts, ",")
			f.mu.Unlock()
			if actual != test.wantCalls {
				t.Fatalf("upstream sends = %q, want %q", actual, test.wantCalls)
			}
			if !test.canceled {
				budget, _ := coreauth.RequestBudgetSnapshotFromContext(request)
				wantAttempts := 0
				if test.wantCalls != "" {
					wantAttempts = 1
				}
				if budget.ActiveWait != test.wantWait || budget.Round != 0 || budget.Attempts != wantAttempts {
					t.Fatalf("budget = %+v; want round 0, %d attempts, wait %s", budget, wantAttempts, test.wantWait)
				}
			}
			if test.wantWait == 0 && len(clock.waits) != 0 {
				t.Fatal("a request with no short opportunity waited")
			}
		})
	}
}

func TestProviderSchedulingHTTPRetryZeroWithTrustedRecovery(t *testing.T) {
	for _, test := range []struct {
		name                                string
		requestRetry, upstreamRetry         int
		wantStatus, wantAttempts, wantRound int
		wantWait                            time.Duration
	}{
		{"zero overrides unlimited", 0, -1, 429, 1, 0, 0},
		{"finite round", 1, 1, 200, 2, 1, time.Second},
		{"unlimited has a concrete short recovery", 1, -1, 200, 2, 1, time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) {
				if requests.Add(1) == 1 {
					emit(`{"type":"error","status":429,"headers":{"Retry-After":"1"},"error":{"type":"rate_limit_error","code":"turn_rate_limit_exceeded","message":"Codex is at capacity"}}`)
					return
				}
				emit(combinedCapacitySuccess)
			})
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
			m.SetConfig(&cfg)
			m.SetRetryConfig(test.requestRetry, 2*time.Second, 1)
			m.SetUpstreamErrorRetryLimit(test.upstreamRetry)
			for _, a := range m.List() {
				if a.Attributes["api_key"] == "A" {
					continue
				}
				a.Disabled = true
				if _, err := m.Update(context.Background(), a); err != nil {
					t.Fatal(err)
				}
			}
			clock := newProviderBudgetClock(time.Now(), true)
			m.SetContinuityClockForTest(clock)

			budgetCtx := coreauth.WithRequestBudget(context.Background())
			handler := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m))
			engine := gin.New()
			engine.POST("/v1/responses", handler.Responses)
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"capacity-gate-model","input":[]}`)).WithContext(budgetCtx)
			req.Header.Set("Content-Type", "application/json")
			engine.ServeHTTP(recorder, req)
			budget, _ := coreauth.RequestBudgetSnapshotFromContext(budgetCtx)
			if recorder.Code != test.wantStatus || int(requests.Load()) != test.wantAttempts || budget.Attempts != test.wantAttempts || budget.Round != test.wantRound || budget.ActiveWait != test.wantWait {
				t.Fatalf("status=%d body=%s actual HTTP=%d budget=%+v", recorder.Code, recorder.Body, requests.Load(), budget)
			}
		})
	}
}

func TestProviderSchedulingHTTPDoesNotRepeatObservableOrUnsafeExecution(t *testing.T) {
	tests := []struct {
		name, payload, outputEvent, marker string
		stream                             bool
	}{
		{name: "visible text", payload: `{"model":"capacity-gate-model","input":[],"stream":true}`, stream: true, outputEvent: `{"type":"response.output_text.delta","delta":"text-once"}`, marker: "text-once"},
		{name: "visible tool arguments", payload: `{"model":"capacity-gate-model","input":[],"stream":true}`, stream: true, outputEvent: `{"type":"response.function_call_arguments.delta","delta":"tool-once"}`, marker: "tool-once"},
		{name: "unverified upstream continuation", payload: `{"model":"capacity-gate-model","input":[],"previous_response_id":"upstream-state"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) {
				if requests.Add(1) != 1 {
					emit(combinedCapacitySuccess)
					return
				}
				if test.stream {
					emit(`{"type":"response.created","response":{"id":"accepted-A","output":[]}}`)
					emit(test.outputEvent)
				}
				emit(`{"type":"error","status":429,"headers":{"Retry-After":"1"},"error":{"type":"rate_limit_error","code":"turn_rate_limit_exceeded","message":"controlled-stop"}}`)
			})
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
			m.SetConfig(&cfg)
			m.SetRetryConfig(2, time.Second, 3)
			m.SetUpstreamErrorRetryLimit(-1)
			handler := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m))
			engine := gin.New()
			engine.POST("/v1/responses", handler.Responses)
			request := func(payload string) (*httptest.ResponseRecorder, coreauth.RequestBudgetSnapshot) {
				t.Helper()
				ctx := coreauth.WithRequestBudget(context.Background())
				recorder := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(payload)).WithContext(ctx)
				req.Header.Set("Content-Type", "application/json")
				engine.ServeHTTP(recorder, req)
				budget, ok := coreauth.RequestBudgetSnapshotFromContext(ctx)
				if !ok {
					t.Fatal("missing budget")
				}
				return recorder, budget
			}
			response, budget := request(test.payload)
			if requests.Load() != 1 || budget.Attempts != 1 || budget.Round != 0 || budget.ActiveWait != 0 || budget.OutputCommitted != test.stream || budget.ReplayUnsafe == test.stream {
				t.Fatalf("first response=%d %s actual HTTP=%d budget=%+v", response.Code, response.Body, requests.Load(), budget)
			}
			body := response.Body.String()
			if test.stream {
				if response.Code != 200 || strings.Count(body, test.marker) != 1 || strings.Count(body, "event: error") != 1 || !strings.Contains(body, "controlled-stop") {
					t.Fatalf("committed HTTP response = %d %s", response.Code, body)
				}
			} else if response.Code != 429 {
				t.Fatalf("unsafe continuation status = %d: %s", response.Code, body)
			}
			next, nextBudget := request(`{"model":"capacity-gate-model","input":[]}`)
			if next.Code != 200 || nextBudget.Attempts != 1 || nextBudget.Round != 0 || nextBudget.ReplayUnsafe || nextBudget.OutputCommitted || requests.Load() != 2 {
				t.Fatalf("independent request response=%d %s actual HTTP=%d budget=%+v", next.Code, next.Body, requests.Load(), nextBudget)
			}
		})
	}
}

type budgetHomeDispatch struct {
	baseURL string
	calls   atomic.Int32
}

func (*budgetHomeDispatch) HeartbeatOK() bool { return true }
func (d *budgetHomeDispatch) RPopAuth(ctx context.Context, model, session string, headers http.Header, count int) ([]byte, error) {
	return d.RPopAuthWithRetryRoundConstraints(ctx, model, session, headers, count, 0, nil, "")
}
func (*budgetHomeDispatch) AbortAmbiguousDispatch() {}
func (d *budgetHomeDispatch) RPopAuthWithRetryRoundConstraints(_ context.Context, model, _ string, _ http.Header, _ int, round int, _ []string, _ string) ([]byte, error) {
	if d.calls.Add(1) > 5 {
		return []byte(`{"error":{"type":"auth_not_found","message":"guard nonterminating retry"}}`), nil
	}
	return json.Marshal(map[string]any{
		"model":      model,
		"auth_index": "home-budget",
		"auth": map[string]any{
			"id": "home-budget", "provider": "codex", "status": "active",
			"attributes": map[string]string{"api_key": "A", "base_url": d.baseURL},
			"metadata":   map[string]any{"access_token": "A"},
		},
	})
}

func TestProviderSchedulingHomeUnlimitedDoesNotInventImmediateRecovery(t *testing.T) {
	f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) {
		emit(`{"type":"error","error":{"type":"server_error","code":"rate_limit_exceeded","message":"rate limited"}}`)
	})
	m := f.inventory.manager
	cfg := *f.inventory.server.cfg
	cfg.Home.Enabled = true
	cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
	m.SetConfig(&cfg)
	m.SetRetryConfig(1, time.Second, 1)
	m.SetUpstreamErrorRetryLimit(-1)
	var upstream string
	for _, a := range m.List() {
		if a.Attributes["api_key"] == "A" {
			upstream = a.Attributes["base_url"]
		}
	}
	if upstream == "" {
		t.Fatal("fixture has no upstream base URL")
	}
	dispatch := &budgetHomeDispatch{baseURL: upstream}
	m.PublishHomeDispatch(dispatch, executionregistry.New(), 1)
	timeout, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	ctx := coreauth.WithRequestBudget(timeout)
	handler := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, m))
	engine := gin.New()
	engine.POST("/v1/responses", handler.Responses)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"capacity-gate-model","input":[]}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(recorder, req)
	budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
	if recorder.Code != 429 || dispatch.calls.Load() != 1 || budget.Attempts != 1 || budget.Round != 0 || budget.ActiveWait != 0 {
		t.Fatalf("status=%d body=%s dispatch=%d budget=%+v", recorder.Code, recorder.Body, dispatch.calls.Load(), budget)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := strings.Join(f.attempts, ","); got != "A" {
		t.Fatalf("actual upstream sends = %q, want A", got)
	}
}
