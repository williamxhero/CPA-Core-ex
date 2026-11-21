package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/home"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
)

const scheduledAntigravityModel = "gemini-2.5-flash"
const scheduledAntigravity429Body = `{"error":{"code":429,"message":"upstream generation is unavailable","status":"RESOURCE_EXHAUSTED"}}`

type scheduledAntigravityHTTP struct {
	manager *coreauth.Manager
	cfg     *config.Config
	api     *gin.Engine
	clock   *providerBudgetClock
	mu      sync.Mutex
	calls   []string
	targets map[string]string
}

func newScheduledAntigravityHTTP(t *testing.T, upstream func(string, string, http.ResponseWriter, *http.Request), providers ...string) *scheduledAntigravityHTTP {
	t.Helper()
	f := &scheduledAntigravityHTTP{cfg: &config.Config{}, api: gin.New(), clock: newProviderBudgetClock(time.Now(), true), targets: make(map[string]string)}
	f.cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{Mode: "enforce"}
	f.manager = coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	f.manager.SetConfig(f.cfg)
	f.manager.SetRetryConfig(1, 3*time.Second, 0)
	f.manager.SetUpstreamErrorRetryLimit(-1)
	f.manager.SetContinuityClockForTest(f.clock)
	f.manager.RegisterExecutor(runtimeexecutor.NewAntigravityExecutor(f.cfg))
	add := func(id string, provider string, priority string) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.calls = append(f.calls, id)
			f.mu.Unlock()
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("reading upstream request: %v", err)
			}
			upstream(id, string(body), w, r)
		}))
		t.Cleanup(target.Close)
		f.targets[id] = target.URL
		auth := &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive,
			Attributes: map[string]string{"base_url": target.URL, "priority": priority},
			Metadata:   map[string]any{"access_token": id, "expired": time.Now().Add(time.Hour).Format(time.RFC3339), "project_id": "fake-project"},
		}
		if provider == "codex" {
			auth.Attributes["api_key"] = id
		}
		if _, err := f.manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: scheduledAntigravityModel}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	add("A", "antigravity", "30")
	add("A2", "antigravity", "20")
	for _, provider := range providers {
		if provider == "codex" {
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(f.cfg))
			add("B", provider, "10")
		}
	}
	handler := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.cfg.SDKConfig, f.manager))
	f.api.POST("/v1/responses", handler.Responses)
	return f
}

func TestProviderSchedulingAntigravityGeneric429ShortWait(t *testing.T) {
	for _, test := range []struct {
		name, header, detail string
		wait                 time.Duration
		retry                int
		deadline             bool
	}{
		{name: "header only", header: "1", wait: time.Second, retry: 1},
		{name: "retry info only", detail: `{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"0.75s"}`, wait: 750 * time.Millisecond, retry: 1},
		{name: "later of both", header: "1", detail: `{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1.5s"}`, wait: 1500 * time.Millisecond, retry: 1},
		{name: "header exactly 3", header: "3", detail: `{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1s"}`, retry: 1},
		{name: "retry info takes precedence if longer", header: "1", detail: `{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"3.01s"}`, retry: 1},
		{name: "ambiguous header", header: "1, 2", retry: 1},
		{name: "zero", header: "0", detail: `{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"0s"}`, retry: 1},
		{name: "invalid", header: "+1", detail: `{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"-1s"}`, retry: 1},
		{name: "text and unrelated detail", detail: `{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"UNRECOGNIZED","metadata":{"quotaResetDelay":"1s"}}`, retry: 1},
		{name: "no extra round", header: "1"},
		{name: "deadline too soon", header: "1", retry: 1, deadline: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newScheduledAntigravityHTTP(t, func(_ string, _ string, w http.ResponseWriter, _ *http.Request) {
				if test.header != "" {
					w.Header().Set("Retry-After", test.header)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = fmt.Fprintf(w, `{"error":{"status":"RESOURCE_EXHAUSTED","message":"retry in 1s","details":[%s]}}`, test.detail)
			})
			f.manager.SetRetryConfig(test.retry, 3*time.Second, 1)
			ctx := coreauth.WithRequestBudget(context.Background())
			if test.deadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			}
			resp := f.request(ctx, true)
			if resp.Code != 429 || !strings.Contains(resp.Body.String(), "RESOURCE_EXHAUSTED") {
				t.Fatalf("expected a real resource exhaustion, got %d: %s", resp.Code, resp.Body)
			}
			if test.header == "3" && resp.Header().Get("Retry-After") != "3" {
				t.Fatalf("valid upstream advisory missing: %v", resp.Header())
			}
			if (test.name == "zero" || test.name == "invalid" || test.name == "ambiguous header" || test.name == "text and unrelated detail") && resp.Header().Get("Retry-After") != "" {
				t.Fatalf("untrusted upstream advisory passed through: %v", resp.Header())
			}
			wantCalls := "A"
			if test.wait > 0 {
				wantCalls += ",A"
				select {
				case d := <-f.clock.waits:
					if d != test.wait {
						t.Fatalf("waited %s, want %s", d, test.wait)
					}
				default:
					t.Fatal("no requested wait")
				}
			}
			if len(f.clock.waits) != 0 {
				t.Fatal("unexpected extra wait")
			}
			f.assertCalls(t, wantCalls)
			budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
			if budget.UpstreamCategory != "antigravity_resource_exhausted" || budget.ActiveWait != test.wait {
				t.Fatalf("missing classified recovery accounting: %+v", budget)
			}
			if test.wait > 0 && (budget.UpstreamDecision != "short_wait" || budget.UpstreamRetrySource == "" || budget.UpstreamRetryAt.IsZero() || budget.Attempts != 2) {
				t.Fatalf("missing short wait diagnostics: %+v", budget)
			}
		})
	}
}

func TestProviderSchedulingAntigravityGeneric429TakesAlternateBeforeHint(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			f := newScheduledAntigravityHTTP(t, func(id string, body string, w http.ResponseWriter, _ *http.Request) {
				if !strings.Contains(body, scheduledAntigravityModel) {
					t.Errorf("upstream lost model: %s", body)
				}
				if id == "B" {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "data: %s\n\n", combinedCapacitySuccess)
					return
				}
				w.Header().Set("Retry-After", "1")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, scheduledAntigravity429Body)
			}, "codex")
			f.manager.SetRetryConfig(0, 3*time.Second, 0)
			ctx := coreauth.WithRequestBudget(context.Background())
			resp := f.request(ctx, stream)
			if resp.Code != 200 {
				t.Fatalf("alternate HTTP provider got %d: %s", resp.Code, resp.Body)
			}
			if len(f.clock.waits) != 0 {
				t.Fatal("healthy alternate should prevent waiting")
			}
			f.assertCalls(t, "A,B")
			budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
			if budget.Attempts != 2 || budget.UpstreamDecision != "alternate" || budget.UpstreamCategory != "antigravity_resource_exhausted" {
				t.Fatalf("missing alternate diagnostics: %+v", budget)
			}
		})
	}
}

func TestProviderSchedulingAntigravityKeepsAlternateTerminalResult(t *testing.T) {
	f := newScheduledAntigravityHTTP(t, func(id string, _ string, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if id == "B" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"type":"invalid_request_error","message":"controlled alternate rejection","code":"invalid_request"}}`)
			return
		}
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, scheduledAntigravity429Body)
	}, "codex")
	resp := f.request(context.Background(), false)
	f.assertCalls(t, "A,B")
	if resp.Code != 400 || !strings.Contains(resp.Body.String(), "controlled alternate rejection") || len(f.clock.waits) != 0 {
		t.Fatalf("alternate terminal response was replaced: %d %s", resp.Code, resp.Body)
	}
}

func TestProviderSchedulingAntigravityRecognizedLimitsAndLegacyRemainSeparate(t *testing.T) {
	for _, test := range []struct{ name, mode, body string }{
		{"plain HTTP 429", "enforce", `{"error":{"code":429,"message":"text only RESOURCE_EXHAUSTED"}}`},
		{"explicit limit", "enforce", `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"RATE_LIMIT_EXCEEDED"}]}}`},
		{"explicit quota", "enforce", `{"error":{"code":429,"status":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"QUOTA_EXHAUSTED"}]}}`},
		{"legacy generic", "off", scheduledAntigravity429Body},
		{"shadow generic", "shadow", scheduledAntigravity429Body},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newScheduledAntigravityHTTP(t, func(_ string, _ string, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, test.body)
			})
			cfg := *f.cfg
			cfg.Routing.ProviderScheduling.Mode = test.mode
			f.manager.SetConfig(&cfg)
			f.manager.SetRetryConfig(0, 0, 0)
			f.manager.SetUpstreamErrorRetryLimit(0)
			ctx := coreauth.WithRequestBudget(context.Background())
			resp := f.request(ctx, false)
			budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
			if resp.Code != 429 || budget.UpstreamCategory != "" {
				t.Fatalf("status=%d body=%s budget=%+v", resp.Code, resp.Body, budget)
			}
			f.assertCalls(t, "A,A2")
		})
	}
}

func TestProviderSchedulingAntigravityCancellationStopsShortWait(t *testing.T) {
	f := newScheduledAntigravityHTTP(t, func(_ string, _ string, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, scheduledAntigravity429Body)
	})
	clock := newProviderBudgetClock(f.clock.Now(), false)
	f.manager.SetContinuityClockForTest(clock)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := coreauth.WithRequestBudget(parent)
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- f.request(ctx, true) }()
	select {
	case wait := <-clock.waits:
		if wait != time.Second {
			t.Fatalf("wait %v, want 1s", wait)
		}
	case response := <-finished:
		t.Fatalf("ended before cancellable wait: %d %s", response.Code, response.Body)
	case <-time.After(4 * time.Second):
		t.Fatal("never entered controllable wait")
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(4 * time.Second):
		t.Fatal("request did not finish on cancellation")
	}
	f.assertCalls(t, "A")
	budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
	if budget.Attempts != 1 || budget.Round != 0 {
		t.Fatalf("cancellation advanced the retry round: %+v", budget)
	}
}

func TestProviderSchedulingAntigravityCommittedStreamIsNotReplayed(t *testing.T) {
	f := newScheduledAntigravityHTTP(t, func(id string, _ string, w http.ResponseWriter, _ *http.Request) {
		if id != "A" {
			t.Errorf("unexpected alternate %s after output", id)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"response\":{\"modelVersion\":\"gemini-trial\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"antigravity-output-once\"}]}}]}}\n\n")
		w.(http.Flusher).Flush()
		_, _ = fmt.Fprintf(w, "data: %s\n\n", scheduledAntigravity429Body)
	}, "codex")
	ctx := coreauth.WithRequestBudget(context.Background())
	resp := f.request(ctx, true)
	f.assertCalls(t, "A")
	if resp.Code != 200 || strings.Count(resp.Body.String(), "event: error") != 1 || !strings.Contains(resp.Body.String(), "antigravity-output-once") {
		t.Fatalf("committed response=%d %s", resp.Code, resp.Body)
	}
	budget, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
	if !budget.OutputCommitted || budget.Attempts != 1 || budget.ServedModel != "gemini-trial" || budget.UpstreamCategory == "antigravity_resource_exhausted" || len(f.clock.waits) != 0 {
		t.Fatalf("possible replay or confusion between the requested model, upstream model, HTTP status and SSE event: %+v", budget)
	}
}

type scheduledAntigravityHomeDispatch struct {
	targets    map[string]string
	candidates []string
}

func (*scheduledAntigravityHomeDispatch) HeartbeatOK() bool       { return true }
func (*scheduledAntigravityHomeDispatch) AbortAmbiguousDispatch() {}
func (d *scheduledAntigravityHomeDispatch) RPopAuth(ctx context.Context, model, session string, headers http.Header, count int) ([]byte, error) {
	return d.RPopAuthWithRetryRoundConstraints(ctx, model, session, headers, count, 0, nil, "")
}
func (d *scheduledAntigravityHomeDispatch) RPopAuthWithRetryRoundConstraints(_ context.Context, model, _ string, _ http.Header, _ int, _ int, excluded []string, pin string) ([]byte, error) {
	for _, id := range d.candidates {
		exclude := pin != "" && id != pin
		for _, ex := range excluded {
			exclude = exclude || ex == id
		}
		if exclude {
			continue
		}
		provider := "antigravity"
		attr := map[string]string{"base_url": d.targets[id]}
		if id == "B" {
			provider = "codex"
			attr["api_key"] = id
		}
		return json.Marshal(map[string]any{
			"model": model, "auth_index": id,
			"auth": map[string]any{
				"id": id, "provider": provider, "status": "active",
				"attributes": attr,
				"metadata":   map[string]string{"access_token": id, "expired": time.Now().Add(time.Hour).Format(time.RFC3339), "project_id": "fake-project"},
			},
		})
	}
	return nil, home.ErrAuthNotFound
}

func TestProviderSchedulingAntigravityHomeSharesExclusionAndShortWait(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, backup := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%t/backup=%t", stream, backup), func(t *testing.T) {
				f := newScheduledAntigravityHTTP(t, func(id string, _ string, w http.ResponseWriter, _ *http.Request) {
					if id == "B" {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, "data: %s\n\n", combinedCapacitySuccess)
						return
					}
					w.Header().Set("Retry-After", "1")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = io.WriteString(w, scheduledAntigravity429Body)
				}, "codex")
				cfg := *f.cfg
				cfg.Home.Enabled = true
				f.manager.SetConfig(&cfg)
				d := &scheduledAntigravityHomeDispatch{targets: f.targets, candidates: []string{"A", "A2"}}
				if backup {
					d.candidates = append(d.candidates, "B")
				}
				f.manager.PublishHomeDispatch(d, executionregistry.New(), 1)
				ctx := coreauth.WithRequestBudget(context.Background())
				resp := f.request(ctx, stream)
				snap, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
				if backup {
					f.assertCalls(t, "A,B")
					if resp.Code != 200 || !strings.Contains(resp.Body.String(), "healthy-B") || snap.Attempts != 2 || snap.Round != 0 || snap.ActiveWait != 0 {
						t.Fatalf("status=%d, body=%s, accounting=%+v", resp.Code, resp.Body, snap)
					}
				} else {
					f.assertCalls(t, "A,A")
					if resp.Code != 429 || snap.Attempts != 2 || snap.Round != 1 || snap.ActiveWait != time.Second {
						t.Fatalf("status=%d, body=%s, accounting=%+v", resp.Code, resp.Body, snap)
					}
				}
			})
		}
	}
}

func (f *scheduledAntigravityHTTP) request(ctx context.Context, stream bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"input":"status check","stream":%t}`, scheduledAntigravityModel, stream))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	f.api.ServeHTTP(recorder, req)
	return recorder
}

func (f *scheduledAntigravityHTTP) assertCalls(t *testing.T, expected string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if actual := strings.Join(f.calls, ","); actual != expected {
		t.Fatalf("business upstream calls %q, want %q", actual, expected)

	}
}

func TestProviderSchedulingAntigravityGeneric429DoesNotWriteCooldownOrSwitchKeys(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			f := newScheduledAntigravityHTTP(t, func(_ string, body string, w http.ResponseWriter, _ *http.Request) {
				if !strings.Contains(body, scheduledAntigravityModel) {
					t.Errorf("upstream lost model: %s", body)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, scheduledAntigravity429Body)
			})
			for i := 0; i < 2; i++ {
				response := f.request(context.Background(), stream)
				if response.Code != http.StatusTooManyRequests {
					t.Fatalf("downstream got %d, want real 429: %s", response.Code, response.Body)
				}
			}
			f.assertCalls(t, "A,A")
			if len(f.clock.waits) != 0 {
				t.Fatal("429 with no trusted hint waited")
			}
			for _, a := range f.manager.List() {
				if a.Disabled || a.Quota.Exceeded || !a.NextRetryAfter.IsZero() {
					t.Fatalf("runtime credential acquired a persistent block after a request: %s", a.ID)
				}
				for _, state := range a.ModelStates {
					if state.Quota.Exceeded || !state.NextRetryAfter.IsZero() {
						t.Fatalf("runtime model acquired a persistent block after a request: %s", a.ID)
					}
				}
			}
		})
	}
}

func TestProviderSchedulingAntigravityAlternateBeforeWaitAtRoundBoundary(t *testing.T) {
	for _, homeRouting := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			for _, test := range []struct {
				name, hint, wantCalls          string
				retries, wantStatus, wantRound int
				wantWait                       time.Duration
				backup                         bool
			}{
				{name: "hint-with-backup", hint: "1", wantCalls: "A,B", retries: 1, wantStatus: 200, wantRound: 1, backup: true},
				{name: "no-hint-with-backup", wantCalls: "A,B", retries: 1, wantStatus: 200, wantRound: 1, backup: true},
				{name: "no-next-round", hint: "1", wantCalls: "A", wantStatus: 429, backup: true},
				{name: "no-backup", hint: "1", wantCalls: "A,A", retries: 1, wantStatus: 429, wantRound: 1, wantWait: time.Second},
				{name: "no-hint-or-backup", wantCalls: "A", retries: 1, wantStatus: 429},
			} {
				t.Run(fmt.Sprintf("home=%t/stream=%t/%s", homeRouting, stream, test.name), func(t *testing.T) {
					providers := []string(nil)
					if test.backup {
						providers = []string{"codex"}
					}
					f := newScheduledAntigravityHTTP(t, func(id string, _ string, w http.ResponseWriter, _ *http.Request) {
						if id == "B" {
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = fmt.Fprintf(w, "data: %s\n\n", combinedCapacitySuccess)
							return
						}
						if test.hint != "" {
							w.Header().Set("Retry-After", test.hint)
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusTooManyRequests)
						_, _ = io.WriteString(w, scheduledAntigravity429Body)
					}, providers...)
					f.manager.SetRetryConfig(test.retries, 3*time.Second, 1)
					f.manager.SetUpstreamErrorRetryLimit(1)
					if homeRouting {
						cfg := *f.cfg
						cfg.Home.Enabled = true
						f.manager.SetConfig(&cfg)
						d := &scheduledAntigravityHomeDispatch{targets: f.targets, candidates: []string{"A", "A2"}}
						if test.backup {
							d.candidates = append(d.candidates, "B")
						}
						f.manager.PublishHomeDispatch(d, executionregistry.New(), 1)
					}
					ctx := coreauth.WithRequestBudget(context.Background())
					resp := f.request(ctx, stream)
					snap, _ := coreauth.RequestBudgetSnapshotFromContext(ctx)
					f.assertCalls(t, test.wantCalls)
					if resp.Code != test.wantStatus || snap.Attempts != len(strings.Split(test.wantCalls, ",")) || snap.Round != test.wantRound || snap.ActiveWait != test.wantWait {
						t.Fatalf("status=%d, body=%s, accounting=%+v", resp.Code, resp.Body, snap)
					}
				})
			}
		}
	}
}
