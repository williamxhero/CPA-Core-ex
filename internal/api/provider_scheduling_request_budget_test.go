package api

import (
	"context"
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
	for _, test := range []struct {
		name       string
		recovery   time.Duration
		maxWait    time.Duration
		backup     bool
		canceled   bool
		wantStatus int
		wantWait   time.Duration
		wantCalls  string
	}{
		{name: "healthy backup", recovery: 135 * time.Hour, maxWait: time.Second, backup: true, wantStatus: 200, wantCalls: "P"},
		{name: "exact short recovery", recovery: 700 * time.Millisecond, maxWait: time.Second, wantStatus: 200, wantWait: 700 * time.Millisecond, wantCalls: "A"},
		{name: "long recovery", recovery: 135 * time.Hour, maxWait: time.Second, wantStatus: 503},
		{name: "unknown recovery", maxWait: time.Second, wantStatus: 503},
		{name: "single wait budget", recovery: 700 * time.Millisecond, maxWait: 500 * time.Millisecond, wantStatus: 503},
		{name: "cancel during wait", recovery: 700 * time.Millisecond, maxWait: time.Second, canceled: true, wantWait: 700 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newCapacityGateRoute(t, "http", func(_ string, emit func(string)) { emit(combinedCapacitySuccess) })
			m := f.inventory.manager
			cfg := *f.inventory.server.cfg
			cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
			m.SetConfig(&cfg)
			m.SetRetryConfig(0, test.maxWait, 3)
			m.SetUpstreamErrorRetryLimit(-1)
			var until time.Time
			for _, a := range m.List() {
				key := a.Attributes["api_key"]
				if key == "A" && test.recovery > 0 {
					m.MarkResult(context.Background(), coreauth.Result{
						AuthID: a.ID, Provider: a.Provider, Model: "capacity-gate-model", RetryAfter: &test.recovery,
						Error: &coreauth.Error{HTTPStatus: 429, Code: coreauth.ErrorCodeTransientRateLimit, Message: "rate limited"},
					})
					a, _ = m.GetByID(a.ID)
					until = a.ModelStates["capacity-gate-model"].NextRetryAfter
					continue
				}
				if key == "P" && test.backup {
					continue
				}
				a.Disabled = true
				if _, err := m.Update(context.Background(), a); err != nil {
					t.Fatal(err)
				}
			}
			now := time.Now()
			if !until.IsZero() {
				now = until.Add(-test.recovery)
			}
			clock := newProviderBudgetClock(now, !test.canceled)
			m.SetContinuityClockForTest(clock)

			request, cancel := context.WithCancel(context.Background())
			defer cancel()
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
			if test.canceled {
				select {
				case d := <-clock.waits:
					if d != test.wantWait {
						t.Fatalf("wait = %s, want %s", d, test.wantWait)
					}
				case <-done:
					t.Fatalf("request terminated before short wait: %d %s", recorder.Code, recorder.Body)
				case <-time.After(4 * time.Second):
					t.Fatal("request never entered the controlled wait")
				}
				cancel()
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
