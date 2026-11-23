package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const persistentPilotModel = "gpt-6.2-sol"
const persistentPilotChat = `{"model":"gpt-6.2-sol","stream":true,"messages":[{"role":"user","content":"hello"}]}`

type persistentPilotClock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

func newPersistentPilotHTTP(t *testing.T, allowlist string, retries int, clock persistentPilotClock, upstream http.HandlerFunc) *inventoryHarness {
	t.Helper()
	f := newInventoryHarness(t, t.TempDir())
	cfg, err := config.ParseConfigBytes([]byte(`disable-image-generation: true
routing:
  provider-scheduling:
    mode: enforce
    persistent-retry-models: ` + allowlist + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	f.manager.SetConfig(cfg)
	f.manager.SetRetryConfig(1, 500*time.Millisecond, 0)
	f.manager.SetUpstreamErrorRetryLimit(retries)
	f.manager.SetContinuityClockForTest(clock)
	f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
	for _, a := range f.manager.List() {
		a.Disabled = true
		if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); err != nil {
			t.Fatal(err)
		}
	}
	addPersistentPilotCodex(t, f, "primary", "20", upstream)
	access := sdkaccess.NewManager()
	access.SetProviders([]sdkaccess.Provider{schedulingHTTPAccess{}})
	base := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, f.manager)
	f.server.engine.POST("/v1/chat/completions", AuthMiddleware(access), openai.NewOpenAIAPIHandler(base).ChatCompletions)
	f.server.engine.POST("/v1/responses", AuthMiddleware(access), openai.NewOpenAIResponsesAPIHandler(base).Responses)
	return f
}

func addPersistentPilotCodex(t *testing.T, f *inventoryHarness, name, priority string, upstream http.HandlerFunc) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/responses" {
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		upstream(w, r)
	}))
	t.Cleanup(target.Close)
	id := t.Name() + "/" + name
	a := &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive,
		Attributes: map[string]string{"base_url": target.URL, "api_key": "test-CANARY", "priority": priority}}
	if _, err := f.manager.Register(coreauth.WithSkipPersist(t.Context()), a); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: persistentPilotModel}, {ID: "pilot-control-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
}

func callPersistentPilot(ctx context.Context, f *inventoryHarness, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer open")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, r)
	return w
}

func persistentPilotStart(w http.ResponseWriter, id string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":%q,\"created_at\":1712345678,\"status\":\"in_progress\"}}\n\n", id)
	fmt.Fprintf(w, "data: {\"type\":\"response.in_progress\",\"response\":{\"id\":%q,\"status\":\"in_progress\"}}\n\n", id)
	w.(http.Flusher).Flush()
}

func persistentPilotFail(w http.ResponseWriter, id string) {
	fmt.Fprintf(w, "data: {\"type\":\"response.failed\",\"response\":{\"id\":%q,\"status\":\"failed\",\"error\":{\"code\":\"upstream_unavailable\",\"message\":\"RAW-FAILURE-CANARY\"}}}\n\n", id)
}

func persistentPilotSucceed(w http.ResponseWriter, text string) {
	fmt.Fprintf(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":%q,\"output_index\":0,\"content_index\":0}\n\n", text)
	fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-success\",\"status\":\"completed\",\"output\":[]}}\n\n")
}

func TestProviderSchedulingPersistentPilotDeadlineBeforeRecovery(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), false)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "42")
		persistentPilotStart(w, "resp-failed-deadline")
		persistentPilotFail(w, "resp-failed-deadline")
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != 502 || attempts.Load() != 1 || len(clock.waits) != 0 || ojson.Get(trace, "retry_stop_reason").String() != "deadline_before_recovery" {
		t.Fatalf("recovery crossed deadline: status=%d sends=%d body=%s trace=%s", w.Code, attempts.Load(), w.Body, trace)
	}
}

func TestProviderSchedulingPersistentPilotCommittedOutput(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		persistentPilotStart(w, "resp-delivered")
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"already delivered\"}\n\n")
		w.(http.Flusher).Flush()
		persistentPilotFail(w, "resp-delivered")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"hello"}`)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	raw := w.Body.String()
	if w.Code != 200 || attempts.Load() != 1 || len(clock.waits) != 0 || strings.Count(raw, "already delivered") != 1 ||
		strings.Contains(raw, "CANARY") || strings.Count(raw, `"code":"upstream_unavailable"`) != 1 ||
		ojson.Get(trace, "retry_stop_reason").String() != "output_committed" {
		t.Fatalf("committed stream was not terminated once: status=%d sends=%d body=%s trace=%s", w.Code, attempts.Load(), raw, trace)
	}
}

func TestProviderSchedulingPersistentPilotHostedOutput(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) > 1 {
			persistentPilotStart(w, "resp-success")
			persistentPilotSucceed(w, "should-never-replay")
			return
		}
		persistentPilotStart(w, "resp-failed-hosted")
		fmt.Fprint(w, "data: {\"type\":\"response.web_search_call.in_progress\",\"item_id\":\"ws-hosted\"}\n\n")
		persistentPilotFail(w, "resp-failed-hosted")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != 502 || attempts.Load() != 1 || len(clock.waits) != 0 || strings.Contains(w.Body.String(), "resp-failed-hosted") ||
		ojson.Get(trace, "retry_stop_reason").String() != "replay_unsafe" {
		t.Fatalf("hosted tool could be replayed: status=%d sends=%d body=%s trace=%s", w.Code, attempts.Load(), w.Body, trace)
	}
}

func TestProviderSchedulingPersistentPilotPreambleCap(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) > 1 {
			persistentPilotStart(w, "resp-success")
			persistentPilotSucceed(w, "should-never-replay")
			return
		}
		persistentPilotStart(w, "resp-failed-cap")
		for range 300 {
			fmt.Fprint(w, "data: {\"type\":\"response.in_progress\",\"response\":{\"id\":\"resp-failed-cap\",\"status\":\"in_progress\"}}\n\n")
		}
		persistentPilotFail(w, "resp-failed-cap")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != 507 || attempts.Load() != 1 || len(clock.waits) != 0 || strings.Contains(w.Body.String(), "resp-failed-cap") ||
		ojson.Get(trace, "retry_stop_reason").String() != "stream_recovery_buffer_limit" {
		t.Fatalf("buffer cap did not stop replay: status=%d sends=%d body=%s trace=%s", w.Code, attempts.Load(), w.Body, trace)
	}
}

func TestProviderSchedulingPersistentPilotCancelDuringWait(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), false)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		persistentPilotStart(w, "resp-failed-cancel")
		persistentPilotFail(w, "resp-failed-cancel")
	})
	guard, stop := context.WithTimeout(t.Context(), 10*time.Second)
	defer stop()
	ctx, cancel := context.WithCancel(guard)
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat) }()
	select {
	case <-clock.waits:
	case <-guard.Done():
		t.Fatal("request did not enter recovery wait")
	}
	cancel()
	select {
	case w := <-done:
		trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
		if attempts.Load() != 1 || ojson.Get(trace, "send_count").Int() != 1 || ojson.Get(trace, "retry_stop_reason").String() != "canceled" || strings.Contains(w.Body.String(), "resp-failed-cancel") {
			t.Fatalf("canceled wait dispatched or lost its terminal reason: sends=%d body=%s trace=%s", attempts.Load(), w.Body, trace)
		}
	case <-guard.Done():
		t.Fatal("canceled wait did not terminate")
	}
}

func TestProviderSchedulingPersistentPilotHalfOpenRelease(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	probe, unblock := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, r *http.Request) {
		switch attempts.Add(1) {
		case 1:
			persistentPilotStart(w, "resp-before-probe")
			persistentPilotFail(w, "resp-before-probe")
			return
		case 2:
			close(probe)
			select {
			case <-unblock:
			case <-r.Context().Done():
				return
			}
		case 3:
			close(probe)
			select {
			case <-unblock:
			case <-r.Context().Done():
				return
			}
		}
		persistentPilotStart(w, "resp-success")
		persistentPilotSucceed(w, "success")
	})
	start := func() <-chan *httptest.ResponseRecorder {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat) }()
		select {
		case <-probe:
		case <-ctx.Done():
			t.Fatal("expected an upstream send")
		}
		return done
	}
	done := start()
	w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
	if w.Code != 503 || attempts.Load() != 2 || !strings.Contains(w.Body.String(), "no_available_route") {
		t.Fatalf("second caller dispatched during probe: %d sends=%d %s", w.Code, attempts.Load(), w.Body)
	}
	close(unblock)
	if w := <-done; w.Code != 200 {
		t.Fatalf("probe failed: %d %s", w.Code, w.Body)
	}
	probe, unblock = make(chan struct{}), make(chan struct{})
	done = start()
	w = callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
	close(unblock)
	<-done
	if w.Code != 200 || attempts.Load() != 4 {
		t.Fatalf("successful probe did not restore ordinary concurrency: %d sends=%d %s", w.Code, attempts.Load(), w.Body)
	}
}

func TestProviderSchedulingPersistentPilotPreferBackupWithFiniteBudget(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var primary, backup atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 1, clock, func(w http.ResponseWriter, _ *http.Request) {
		primary.Add(1)
		persistentPilotStart(w, "resp-primary-failed")
		persistentPilotFail(w, "resp-primary-failed")
	})
	addPersistentPilotCodex(t, f, "backup", "10", func(w http.ResponseWriter, _ *http.Request) {
		backup.Add(1)
		persistentPilotStart(w, "resp-success")
		persistentPilotSucceed(w, "available-backup")
	})
	f.manager.SetRetryConfig(1, 500*time.Millisecond, 1)
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	if w.Code != 200 || primary.Load() != 1 || backup.Load() != 1 || len(clock.waits) != 0 || !strings.Contains(w.Body.String(), "available-backup") || strings.Contains(w.Body.String(), "resp-primary-failed") {
		t.Fatalf("expected one additional send to the available backup without waiting: %d primary=%d backup=%d waits=%d %s", w.Code, primary.Load(), backup.Load(), len(clock.waits), w.Body)
	}
}

func TestProviderSchedulingPersistentPilotFiniteSameRouteBudget(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) > 2 {
			persistentPilotStart(w, "resp-success")
			persistentPilotSucceed(w, "outside-budget")
			return
		}
		persistentPilotStart(w, "resp-failed-budget")
		persistentPilotFail(w, "resp-failed-budget")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != 502 || attempts.Load() != 2 || len(clock.waits) != 1 || ojson.Get(trace, "send_count").Int() != 2 ||
		ojson.Get(trace, "retry_stop_reason").String() != "retry_limit" || strings.Contains(w.Body.String(), "resp-failed-budget") {
		t.Fatalf("expected exactly one additional send: status=%d sends=%d body=%s trace=%s", w.Code, attempts.Load(), w.Body, trace)
	}
}

func TestProviderSchedulingPersistentPilotTerminalRateLimitBudget(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		persistentPilotStart(w, "resp-failed-429")
		fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-failed-429\",\"status\":\"failed\",\"status_code\":429,\"error\":{\"message\":\"RAW-FAILURE-CANARY\"}}}\n\n")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	raw := w.Body.String()
	if w.Code != 429 || attempts.Load() != 1 || len(clock.waits) != 0 || ojson.Get(raw, "error.code").String() != "rate_limit_exceeded" || strings.Contains(raw, "CANARY") {
		t.Fatalf("wrong structured 429 terminal: status=%d sends=%d body=%s", w.Code, attempts.Load(), raw)
	}
	diag := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if ojson.Get(diag, "send_count").Int() != 1 || ojson.Get(diag, "upstream_category").String() != "transient_rate_limit" ||
		ojson.Get(diag, "retry_stop_reason").String() != "retry_limit" || strings.Contains(diag, "CANARY") {
		t.Fatalf("incorrect routing trace: %s", diag)
	}
}

func TestProviderSchedulingPersistentPilotMatchedRuleRateLimitPacesRetry(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			persistentPilotStart(w, "resp-failed-matched-rule")
			fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-failed-matched-rule\",\"status\":\"failed\",\"status_code\":429,\"error\":{\"message\":\"MATCHED-LIMIT-CANARY\"}}}\n\n")
			return
		}
		persistentPilotStart(w, "resp-success")
		persistentPilotSucceed(w, "recovered-matched-rule")
	})
	authID := t.Name() + "/primary"
	for _, a := range f.manager.List() {
		if a.ID != authID {
			continue
		}
		a.Metadata = map[string]any{"request_scoped_errors": []config.RequestScopedErrorRule{{
			Status: http.StatusTooManyRequests,
			Match:  []string{"MATCHED-LIMIT-CANARY"},
			Action: coreauth.RequestScopedActionContinue,
		}}}
		if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); err != nil {
			t.Fatal(err)
		}
		break
	}
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	raw := w.Body.String()
	if w.Code != http.StatusOK || attempts.Load() != 2 || len(clock.waits) != 1 || strings.Contains(raw, "MATCHED-LIMIT-CANARY") || !strings.Contains(raw, "recovered-matched-rule") {
		t.Fatalf("matched-rule 429 was not paced and retried into success: status=%d sends=%d waits=%d body=%s", w.Code, attempts.Load(), len(clock.waits), raw)
	}
	select {
	case wait := <-clock.waits:
		assertPersistentPilotStepWait(t, wait, time.Second)
	default:
		t.Fatal("missing matched-rule rate-limit wait")
	}
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if ojson.Get(trace, "send_count").Int() != 2 || ojson.Get(trace, "upstream_category").String() != "transient_rate_limit" {
		t.Fatalf("incorrect matched-rule recovery trace: %s", trace)
	}
}

func assertPersistentPilotStepWait(t *testing.T, wait, base time.Duration) {
	t.Helper()
	if wait < base || wait > base+base/4 {
		t.Fatalf("wait = %v, want the %v step with up to 25%% jitter", wait, base)
	}
}

func TestProviderSchedulingPersistentPilotQuotaEvidenceControlsRetry(t *testing.T) {
	const quotaBody = `{"error":{"type":"usage_limit_reached","message":"You've hit your usage limit.","resets_in_seconds":3600}}`
	for _, tc := range []struct {
		name         string
		body         string
		recover      bool
		wantStatus   int
		wantSends    int32
		wantWaits    int
		wantCategory string
		wantStop     string
		wantSource   string
	}{
		{name: "bare 429", body: `{"error":{"message":"temporary upstream rejection"}}`, recover: true, wantStatus: http.StatusOK, wantSends: 2, wantWaits: 1, wantCategory: "transient_rate_limit", wantSource: "local_backoff"},
		{name: "authoritative quota 429", body: quotaBody, wantStatus: http.StatusTooManyRequests, wantSends: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newProviderBudgetClock(time.Now(), true)
			var attempts atomic.Int32
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
				n := attempts.Add(1)
				if tc.recover && n > 1 {
					persistentPilotStart(w, "resp-success")
					persistentPilotSucceed(w, "recovered-bare-429")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, tc.body)
			})
			ctx, cancel := context.WithTimeout(coreauth.WithRequestBudget(t.Context()), 10*time.Second)
			defer cancel()
			w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
			trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
			if w.Code != tc.wantStatus || attempts.Load() != tc.wantSends || len(clock.waits) != tc.wantWaits || ojson.Get(trace, "send_count").Int() != int64(tc.wantSends) {
				t.Fatalf("unexpected retry pacing: status=%d sends=%d waits=%d body=%s trace=%s", w.Code, attempts.Load(), len(clock.waits), w.Body, trace)
			}
			if category := ojson.Get(trace, "upstream_category").String(); category != tc.wantCategory {
				t.Fatalf("upstream category = %q, want %q: %s", category, tc.wantCategory, trace)
			}
			if stop := ojson.Get(trace, "retry_stop_reason").String(); stop != tc.wantStop {
				t.Fatalf("retry stop reason = %q, want %q: %s", stop, tc.wantStop, trace)
			}
			if source := ojson.Get(trace, "upstream_retry_source").String(); source != tc.wantSource {
				t.Fatalf("upstream retry source = %q, want %q: %s", source, tc.wantSource, trace)
			}
		})
	}
}

func TestProviderSchedulingPersistentPilotResponseStatusRateLimitRecovery(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			persistentPilotStart(w, "resp-failed-envelope-429")
			fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-failed-envelope-429\",\"status\":\"failed\",\"status_code\":429,\"error\":{\"message\":\"RAW-FAILURE-CANARY\"}}}\n\n")
			return
		}
		persistentPilotStart(w, "resp-success")
		persistentPilotSucceed(w, "recovered-envelope-429")
	})
	ctx := coreauth.WithRequestBudget(t.Context())
	w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
	raw := w.Body.String()
	if w.Code != http.StatusOK || attempts.Load() != 2 || len(clock.waits) != 1 || strings.Contains(raw, "resp-failed-envelope-429") ||
		strings.Contains(raw, "CANARY") || !strings.Contains(raw, "recovered-envelope-429") {
		t.Fatalf("response-level 429 was not retried into success: status=%d sends=%d waits=%d body=%s", w.Code, attempts.Load(), len(clock.waits), raw)
	}
	budget, ok := coreauth.RequestBudgetSnapshotFromContext(ctx)
	if !ok || budget.Attempts != 2 || budget.UpstreamCategory != "transient_rate_limit" || budget.UpstreamRetryAt.IsZero() {
		t.Fatalf("reflected 429 was not classified as a transient rate limit: %+v", budget)
	}
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if ojson.Get(trace, "send_count").Int() != 2 || ojson.Get(trace, "upstream_category").String() != "transient_rate_limit" ||
		ojson.Get(trace, "terminal.code").String() != "succeeded" || ojson.Get(trace, "terminal.status").Int() != http.StatusOK {
		t.Fatalf("incorrect recovery trace: %s", trace)
	}
}

func TestProviderSchedulingPersistentPilotResponsesRetryAfter(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "42")
			persistentPilotStart(w, "resp-failed-long")
			persistentPilotFail(w, "resp-failed-long")
			return
		}
		persistentPilotStart(w, "resp-success")
		persistentPilotSucceed(w, "recovered-responses")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"hello"}`)
	raw := w.Body.String()
	if w.Code != 200 || attempts.Load() != 2 || strings.Contains(raw, "resp-failed-long") ||
		strings.Count(raw, `"type":"response.created"`) != 1 || strings.Count(raw, `"type":"response.completed"`) != 1 || !strings.Contains(raw, "recovered-responses") {
		t.Fatalf("expected one coherent Responses stream: status=%d sends=%d body=%s", w.Code, attempts.Load(), raw)
	}
	select {
	case wait := <-clock.waits:
		if wait != 42*time.Second {
			t.Fatalf("Retry-After not honored: waited %v", wait)
		}
	default:
		t.Fatal("missing Retry-After wait")
	}
}

func TestProviderSchedulingPersistentPilotChatIncident(t *testing.T) {
	for _, model := range []string{persistentPilotModel, "pilot-control-model"} {
		t.Run(model, func(t *testing.T) {
			var attempts atomic.Int32
			clock := newProviderBudgetClock(time.Now(), true)
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
				n := attempts.Add(1)
				if n <= 3 {
					id := fmt.Sprintf("resp-failed-%d", n)
					persistentPilotStart(w, id)
					persistentPilotFail(w, id)
					return
				}
				persistentPilotStart(w, "resp-success")
				persistentPilotSucceed(w, "recovered-on-fourth")
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			w := callPersistentPilot(ctx, f, "/v1/chat/completions", strings.Replace(persistentPilotChat, persistentPilotModel, model, 1))
			raw := w.Body.String()
			if model != persistentPilotModel {
				if attempts.Load() != 1 || len(clock.waits) != 0 || strings.Contains(raw, "recovered-on-fourth") {
					t.Fatalf("unlisted model changed behavior: status=%d sends=%d waits=%d body=%s", w.Code, attempts.Load(), len(clock.waits), raw)
				}
				return
			}
			if w.Code != 200 || attempts.Load() != 4 || strings.Count(raw, "recovered-on-fourth") != 1 || strings.Count(raw, "[DONE]") != 1 || strings.Contains(raw, "resp-failed-") || strings.Contains(raw, "CANARY") {
				t.Fatalf("expected four real sends and one successful stream: status=%d sends=%d body=%s", w.Code, attempts.Load(), raw)
			}
			for _, lower := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
				select {
				case wait := <-clock.waits:
					if wait < lower || wait > lower+lower/4 {
						t.Fatalf("backoff = %v, expected %v with up to 25%% jitter", wait, lower)
					}
				default:
					t.Fatalf("missing wait with lower bound %v", lower)
				}
			}
		})
	}
}

func TestProviderSchedulingPersistentPilotEmptyAllowlist(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), true)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[]", 1, clock, func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			persistentPilotStart(w, "resp-unlisted-failed")
			persistentPilotFail(w, "resp-unlisted-failed")
			return
		}
		persistentPilotStart(w, "resp-unlisted-success")
		persistentPilotSucceed(w, "must-not-replay")
	})
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != http.StatusBadGateway || attempts.Load() != 1 || len(clock.waits) != 0 || ojson.Get(trace, "retry_stop_reason").String() != "" {
		t.Fatalf("empty allowlist started the pilot: status=%d sends=%d waits=%d body=%s trace=%s", w.Code, attempts.Load(), len(clock.waits), w.Body, trace)
	}
}
