package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
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
	t.Setenv("MANAGEMENT_PASSWORD", "")
	caller := sha256.Sum256([]byte(sdkaccess.DefaultAccessProviderName + "\x00open"))
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := fmt.Sprintf(`access:
  api-keys: [open, outside-pilot]
management:
  secret-key: test-password
oauth:
  auth-dir: %q
multimedia:
  disable-image-generation: true
routing:
  retry:
    request-retry: 1
    max-retry-credentials: 1
    upstream-error-retry-limit: %d
  provider-scheduling:
    mode: enforce
    models: [gpt-6.2-sol, pilot-control-model]
    callers: [%x]
    persistent-retry-models: %s
`, filepath.ToSlash(filepath.Join(dir, "auth")), retries, caller, allowlist)
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg) // Same initial snapshot as the service builder.
	manager.SetContinuityClockForTest(clock)
	manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
	s := NewServer(cfg, manager, sdkaccess.NewManager(), path)
	f := &inventoryHarness{t: t, server: s, manager: manager}
	t.Cleanup(func() {
		if err := s.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	addPersistentPilotCodex(t, f, "primary", "20", upstream)
	return f
}

func addPersistentPilotCodex(t *testing.T, f *inventoryHarness, name, priority string, upstream http.HandlerFunc) string {
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
	return id
}

func callPersistentPilot(ctx context.Context, f *inventoryHarness, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	servePersistentPilot(ctx, f, w, path, body, "open")
	return w
}

func servePersistentPilot(ctx context.Context, f *inventoryHarness, w http.ResponseWriter, path, body, key string) {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	f.server.engine.ServeHTTP(w, r)
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
	persistentPilotSucceedWithID(w, "resp-success", text)
}

func persistentPilotSucceedWithID(w http.ResponseWriter, id, text string) {
	fmt.Fprintf(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":%q,\"output_index\":0,\"content_index\":0}\n\n", text)
	fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":%q,\"status\":\"completed\",\"output\":[]}}\n\n", id)
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

type persistentPilotTimer struct {
	at   time.Time
	fire chan struct{}
}

type manualPersistentPilotClock struct {
	now    atomic.Pointer[time.Time]
	timers chan persistentPilotTimer
}

func newManualPersistentPilotClock() *manualPersistentPilotClock {
	c := &manualPersistentPilotClock{timers: make(chan persistentPilotTimer)}
	c.moveTo(time.Now())
	return c
}

func (c *manualPersistentPilotClock) Now() time.Time     { return *c.now.Load() }
func (c *manualPersistentPilotClock) moveTo(t time.Time) { c.now.Store(&t) }
func (c *manualPersistentPilotClock) Wait(ctx context.Context, d time.Duration) error {
	timer := persistentPilotTimer{at: c.Now().Add(d), fire: make(chan struct{})}
	select {
	case c.timers <- timer:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-timer.fire:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func awaitPilotTimer(t *testing.T, ctx context.Context, clock *manualPersistentPilotClock, done <-chan *httptest.ResponseRecorder) persistentPilotTimer {
	t.Helper()
	select {
	case timer := <-clock.timers:
		return timer
	case w := <-done:
		t.Fatalf("original request returned before its route recovered: %d %s", w.Code, w.Body)
	case <-ctx.Done():
		t.Fatal("request did not reach a recovery wait")
	}
	return persistentPilotTimer{}
}

func awaitPilotResult(t *testing.T, ctx context.Context, done <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-done:
		return w
	case <-ctx.Done():
		t.Fatal("request did not finish")
		return nil
	}
}

// Responses can finish writing its completed frame before the execution
// goroutine publishes the final accounting. Observe the protected receipt
// until both sides have finished, without sleeping or changing request time.
func awaitPilotTerminalTrace(t *testing.T, ctx context.Context, f *inventoryHarness, id string) string {
	t.Helper()
	for {
		trace := readSchedulingTraceForTest(t, f, id)
		if ojson.Get(trace, "terminal").Exists() {
			return trace
		}
		if ctx.Err() != nil {
			t.Fatalf("missing terminal accounting for %q: %s", id, trace)
		}
		runtime.Gosched()
	}
}

func startPilotRequest(ctx context.Context, f *inventoryHarness, path, body string) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- callPersistentPilot(ctx, f, path, body) }()
	return done
}

func TestProviderSchedulingPersistentPilotHalfOpenRelease(t *testing.T) {
	for _, tc := range []struct{ name, path, body, terminal, sourceFormat string }{
		{"chat", "/v1/chat/completions", persistentPilotChat, "data: [DONE]", "openai"},
		{"responses", "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"hello"}`, `"type":"response.completed"`, "openai-response"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newManualPersistentPilotClock()
			var attempts atomic.Int32
			probe, unblock := make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, r *http.Request) {
				payload, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("reading upstream request: %v", err)
					return
				}
				text := ojson.GetBytes(payload, "input.0.content.0.text").String()
				n := attempts.Add(1)
				if n <= 2 && text != "request-A" || n == 3 && text != "request-B" || n > 3 {
					t.Errorf("unexpected upstream call %d for %q", n, text)
				}
				if n == 1 {
					w.WriteHeader(http.StatusBadGateway) // No Retry-After in the counterexample.
					return
				}
				if n == 2 {
					close(probe)
					select {
					case <-unblock:
					case <-r.Context().Done():
						return
					}
				}
				id := "resp-" + text
				persistentPilotStart(w, id)
				persistentPilotSucceedWithID(w, id, "result-"+text)
			})
			a := startPilotRequest(ctx, f, tc.path, strings.Replace(tc.body, "hello", "request-A", 1))
			aTimer := awaitPilotTimer(t, ctx, clock, a)
			assertPersistentPilotStepWait(t, aTimer.at.Sub(clock.Now()), time.Second)
			bRecorder := httptest.NewRecorder()
			b := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				servePersistentPilot(ctx, f, bRecorder, tc.path, strings.Replace(tc.body, "hello", "request-B", 1), "open")
				b <- bRecorder
			}()
			bTimer := awaitPilotTimer(t, ctx, clock, b)
			// The clock signal synchronizes with the handler setting the header,
			// before the recorder can receive a response.
			bID := bRecorder.Header().Get("X-Request-ID")
			for _, key := range []string{"", "open"} {
				r := httptest.NewRequest(http.MethodGet, "/v8/management/observability/routing/"+bID, nil)
				r.RemoteAddr = "127.0.0.1:1234"
				if key != "" {
					r.Header.Set("Authorization", "Bearer "+key)
				}
				w := httptest.NewRecorder()
				f.server.engine.ServeHTTP(w, r)
				if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "send_count") {
					t.Fatalf("trace readable without admin access: %d %s", w.Code, w.Body)
				}
			}
			trace := ojson.Parse(readSchedulingTraceForTest(t, f, bID))
			limit := trace.Get("retry_policy.upstream_error_retry_limit")
			if trace.Get("mode").String() != "enforce" || trace.Get("model").String() != persistentPilotModel ||
				trace.Get("retry_policy.source_format").String() != tc.sourceFormat || !limit.Exists() || limit.Int() != -1 ||
				!trace.Get("last_recovery_wait.not_before").Exists() || trace.Get("send_count").Int() != 0 || trace.Get("terminal").Exists() {
				t.Fatalf("B's effective policy or first-send wait missing from trace: %s", trace.Raw)
			}
			if attempts.Load() != 1 || !bTimer.at.Equal(aTimer.at) {
				t.Fatalf("B did not wait for the existing cooldown: sends=%d A=%v B=%v", attempts.Load(), aTimer.at, bTimer.at)
			}
			clock.moveTo(aTimer.at)
			close(aTimer.fire)
			select {
			case <-probe:
			case <-ctx.Done():
				t.Fatal("A did not acquire the half-open probe")
			}
			close(bTimer.fire)
			// Keep A blocked until B has actually re-evaluated at the cooldown
			// boundary and is waiting on the probe, not just its original timer.
			for {
				trace := ojson.Parse(readSchedulingTraceForTest(t, f, bID))
				if trace.Get("last_recovery_wait.probe_pending").Bool() {
					if trace.Get("send_count").Int() != 0 || trace.Get("terminal").Exists() || attempts.Load() != 2 {
						t.Fatalf("B dispatched or finished during A's probe: sends=%d trace=%s", attempts.Load(), trace.Raw)
					}
					break
				}
				select {
				case w := <-b:
					t.Fatalf("B returned during A's probe: %d %s", w.Code, w.Body)
				case <-ctx.Done():
					t.Fatalf("B did not re-evaluate into a half-open wait: %s", trace.Raw)
				default:
					runtime.Gosched()
				}
			}
			close(unblock)
			var aID string
			for _, result := range []struct {
				done       <-chan *httptest.ResponseRecorder
				own, other string
				sends      int64
			}{{a, "request-A", "request-B", 2}, {b, "request-B", "request-A", 1}} {
				w := awaitPilotResult(t, ctx, result.done)
				raw := w.Body.String()
				id := w.Header().Get("X-Request-ID")
				if result.own == "request-A" {
					aID = id
				} else if id != bID || id == aID {
					t.Fatalf("B lost its original request identity: A=%q B-before=%q B-after=%q", aID, bID, id)
				}
				trace := awaitPilotTerminalTrace(t, ctx, f, id)
				if w.Code != http.StatusOK || strings.Count(raw, "result-"+result.own) != 1 || !strings.Contains(raw, "resp-"+result.own) ||
					strings.Contains(raw, result.other) || strings.Count(raw, tc.terminal) != 1 || strings.Contains(trace, "CANARY") ||
					strings.Contains(trace, "request-A") || strings.Contains(trace, "request-B") ||
					ojson.Get(trace, "send_count").Int() != result.sends || ojson.Get(trace, "terminal.code").String() != "succeeded" {
					t.Fatalf("wrong independent stream or accounting: status=%d body=%s trace=%s", w.Code, raw, trace)
				}
			}
			if attempts.Load() != 3 {
				t.Fatalf("expected two A sends and one B send, got %d", attempts.Load())
			}
		})
	}
}

func updatePilotAuth(t *testing.T, f *inventoryHarness, id string, update func(*coreauth.Auth)) {
	t.Helper()
	for _, a := range f.manager.List() {
		if a.ID == id {
			update(a)
			if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatalf("missing upstream fixture %s", id)
}

func TestProviderSchedulingPersistentPilotFirstSendAfterOrdinaryCooldown(t *testing.T) {
	const path = "/v1/chat/completions"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	guard, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	clock := newManualPersistentPilotClock()
	// Compare the timer and the HTTP receipt on the same wall-clock basis.
	clock.moveTo(clock.Now().UTC())
	var sends atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, func(w http.ResponseWriter, r *http.Request) {
		if sends.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway) // No Retry-After and no quota signal.
			return
		}
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading upstream request: %v", err)
			return
		}
		text := ojson.GetBytes(payload, "input.0.content.0.text").String()
		id := "resp-" + text
		persistentPilotStart(w, id)
		persistentPilotSucceedWithID(w, id, "result-"+text)
	})
	ordinary := func() <-chan *httptest.ResponseRecorder {
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			w := httptest.NewRecorder()
			servePersistentPilot(ctx, f, w, path, persistentPilotChat, "outside-pilot")
			done <- w
		}()
		return done
	}
	before := time.Now()
	a := awaitPilotResult(t, guard, ordinary())
	after := time.Now()
	if a.Code != http.StatusBadGateway || sends.Load() != 1 || a.Header().Get("Retry-After") != "" || a.Header().Get("X-Request-ID") != "" {
		t.Fatalf("ordinary A did not return its unhinted 502: status=%d sends=%d headers=%v body=%s", a.Code, sends.Load(), a.Header(), a.Body)
	}
	// An ordinary caller arriving during the same cooldown must still fail fast.
	select {
	case <-clock.timers:
		t.Fatal("ordinary caller entered a pilot recovery wait")
	case w := <-ordinary():
		if w.Code != http.StatusServiceUnavailable || sends.Load() != 1 || w.Header().Get("X-Request-ID") != "" {
			t.Fatalf("ordinary caller did not keep its legacy response: status=%d sends=%d headers=%v body=%s", w.Code, sends.Load(), w.Header(), w.Body)
		}
	case <-guard.Done():
		t.Fatal("ordinary caller did not fail fast during cooldown")
	}

	bRecorder := httptest.NewRecorder()
	b := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		servePersistentPilot(ctx, f, bRecorder, path, strings.Replace(persistentPilotChat, "hello", "request-B", 1), "open")
		b <- bRecorder
	}()
	var timer persistentPilotTimer
	select {
	case w := <-b:
		trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
		t.Fatalf("pilot B returned instead of waiting for its first send: status=%d total sends=%d body=%s trace=%s", w.Code, sends.Load(), w.Body, trace)
	case timer = <-clock.timers:
	case <-guard.Done():
		t.Fatal("pilot B did not enter a recovery wait")
	}
	// The legacy cooldown is measured from A's actual failure time, not B's
	// clock or arrival time. The timer signal also synchronizes the header read.
	id := bRecorder.Header().Get("X-Request-ID")
	trace := ojson.Parse(readSchedulingTraceForTest(t, f, id))
	limit := trace.Get("retry_policy.upstream_error_retry_limit")
	if timer.at.Before(before.Add(time.Minute)) || timer.at.After(after.Add(time.Minute)) || sends.Load() != 1 ||
		trace.Get("last_recovery_wait.not_before").String() != timer.at.UTC().Format(time.RFC3339Nano) ||
		!limit.Exists() || limit.Int() != 0 || trace.Get("send_count").Int() != 0 || trace.Get("terminal").Exists() {
		t.Fatalf("pilot B did not wait without sending until A's cooldown ended: timer=%v sends=%d trace=%s", timer.at, sends.Load(), trace.Raw)
	}
	wait := timer.at.Sub(clock.Now())
	clock.moveTo(timer.at)
	close(timer.fire)
	w := awaitPilotResult(t, guard, b)
	trace = ojson.Parse(awaitPilotTerminalTrace(t, guard, f, id))
	if w.Code != http.StatusOK || sends.Load() != 2 || w.Header().Get("X-Request-ID") != id ||
		strings.Count(w.Body.String(), "result-request-B") != 1 || !strings.Contains(w.Body.String(), "resp-request-B") ||
		strings.Count(w.Body.String(), "data: [DONE]") != 1 || trace.Get("send_count").Int() != 1 ||
		trace.Get("wait_ms").Int() != wait.Milliseconds() || trace.Get("terminal.code").String() != "succeeded" {
		t.Fatalf("pilot B did not complete its own first send: status=%d total sends=%d body=%s trace=%s", w.Code, sends.Load(), w.Body, trace.Raw)
	}
}

func TestProviderSchedulingPersistentPilotFirstSendRecovery(t *testing.T) {
	const path = "/v1/chat/completions"
	for _, scenario := range []string{"trusted-hint", "healthy-backup", "backup-wakes-waiter", "cancel", "no-route", "ineligible-backup", "confirmed-quota"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 10*time.Second)
			defer stop()
			clock := newManualPersistentPilotClock()
			// Leave room to advance five virtual minutes without crossing the
			// real-time safety deadline used to bound the test.
			start := clock.Now().Add(-10 * time.Minute)
			clock.moveTo(start)
			var primary, backup atomic.Int32
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, func(w http.ResponseWriter, _ *http.Request) {
				if scenario == "confirmed-quota" {
					primary.Add(1)
					w.WriteHeader(http.StatusTooManyRequests)
					fmt.Fprint(w, `{"error":{"type":"usage_limit_reached","message":"You've hit your usage limit.","resets_in_seconds":300}}`)
					return
				}
				w.Header().Set("Retry-After", "300")
				n := primary.Add(1)
				if n != 1 && clock.Now().Before(start.Add(300*time.Second)) {
					t.Errorf("primary sent at %v before 300s", clock.Now().Sub(start))
				}
				w.WriteHeader(http.StatusBadGateway)
			})
			call := func() *httptest.ResponseRecorder {
				return awaitPilotResult(t, ctx, startPilotRequest(ctx, f, path, persistentPilotChat))
			}
			assertResult := func(w *httptest.ResponseRecorder, status int, sends int64, reason string) string {
				t.Helper()
				id := w.Header().Get("X-Request-ID")
				trace := ojson.Parse(readSchedulingTraceForTest(t, f, id))
				limit := trace.Get("retry_policy.upstream_error_retry_limit")
				if (status != 0 && w.Code != status) || !limit.Exists() || limit.Int() != 0 ||
					trace.Get("send_count").Int() != sends || trace.Get("retry_stop_reason").String() != reason {
					t.Fatalf("unexpected result: status=%d body=%s trace=%s", w.Code, w.Body, trace.Raw)
				}
				return trace.Raw
			}
			if scenario == "confirmed-quota" {
				assertResult(call(), http.StatusTooManyRequests, 1, "")
				b := startPilotRequest(ctx, f, path, persistentPilotChat)
				select {
				case <-clock.timers:
					t.Fatal("a quota reset estimate opened a first-send wait")
				case w := <-b:
					trace := assertResult(w, http.StatusServiceUnavailable, 0, "no_available_route")
					if primary.Load() != 1 || ojson.Get(trace, "last_recovery_wait").Exists() {
						t.Fatalf("quota-blocked request sent or waited: %s", trace)
					}
				case <-ctx.Done():
					t.Fatal("quota-blocked request did not return")
				}
				return
			}
			// Prime the shared cooldown. The explicit zero must forbid A's
			// addition but not B's first send later on the same route.
			assertResult(call(), http.StatusBadGateway, 1, "retry_limit")
			primaryID := t.Name() + "/primary"
			switch scenario {
			case "no-route":
				updatePilotAuth(t, f, primaryID, func(a *coreauth.Auth) { a.Disabled = true })
				if trace := assertResult(call(), http.StatusServiceUnavailable, 0, "no_available_route"); ojson.Get(trace, "last_recovery_wait").Exists() || ojson.Get(trace, "terminal.code").String() != "no_available_route" {
					t.Fatalf("disabled route caused a wait: %s", trace)
				}
				return
			case "healthy-backup", "backup-wakes-waiter", "ineligible-backup":
				id := addPersistentPilotCodex(t, f, "backup", "10", func(w http.ResponseWriter, _ *http.Request) {
					backup.Add(1)
					persistentPilotStart(w, "resp-success")
					persistentPilotSucceed(w, "backup-result")
				})
				if scenario == "healthy-backup" {
					w := call()
					trace := assertResult(w, http.StatusOK, 1, "")
					if primary.Load() != 1 || backup.Load() != 1 || !strings.Contains(w.Body.String(), "backup-result") || ojson.Get(trace, "last_recovery_wait").Exists() {
						t.Fatalf("healthy backup was not used immediately: primary=%d backup=%d body=%s trace=%s", primary.Load(), backup.Load(), w.Body, trace)
					}
					return
				}
				if scenario == "ineligible-backup" {
					// Still a Codex credential, but it doesn't serve this model.
					registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "pilot-control-model"}})
				} else {
					updatePilotAuth(t, f, id, func(a *coreauth.Auth) { a.Disabled = true })
				}
			}

			bCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			b := startPilotRequest(bCtx, f, path, strings.Replace(persistentPilotChat, "hello", "request-B", 1))
			timer := awaitPilotTimer(t, ctx, clock, b)
			if timer.at.Sub(start) != 300*time.Second || primary.Load() != 1 || backup.Load() != 0 {
				t.Fatalf("wrong initial wait: %v primary=%d backup=%d", timer.at.Sub(start), primary.Load(), backup.Load())
			}
			if scenario == "backup-wakes-waiter" {
				clock.moveTo(start.Add(time.Second))
				updatePilotAuth(t, f, t.Name()+"/backup", func(a *coreauth.Auth) { a.Disabled = false; a.Status = coreauth.StatusActive })
				w := awaitPilotResult(t, ctx, b)
				trace := assertResult(w, http.StatusOK, 1, "")
				if primary.Load() != 1 || backup.Load() != 1 || !strings.Contains(w.Body.String(), "backup-result") || ojson.Get(trace, "wait_ms").Int() != 1000 {
					t.Fatalf("backup did not wake B early: primary=%d backup=%d body=%s trace=%s", primary.Load(), backup.Load(), w.Body, trace)
				}
				return
			}
			if scenario == "cancel" {
				cancel()
				assertResult(awaitPilotResult(t, ctx, b), 0, 0, "canceled")
				clock.moveTo(timer.at)
				close(timer.fire)
				if primary.Load() != 1 || backup.Load() != 0 {
					t.Fatalf("canceled B reached upstream: primary=%d backup=%d", primary.Load(), backup.Load())
				}
				return
			}
			clock.moveTo(start.Add(299 * time.Second))
			// A same-route generation update is a re-evaluation signal, not
			// authority to discard the trusted minimum.
			updatePilotAuth(t, f, primaryID, func(a *coreauth.Auth) { a.Label = "same route, refreshed" })
			timer = awaitPilotTimer(t, ctx, clock, b)
			if timer.at.Sub(clock.Now()) != time.Second || primary.Load() != 1 || backup.Load() != 0 {
				t.Fatalf("route sent early or lost its hint: remaining=%v primary=%d backup=%d", timer.at.Sub(clock.Now()), primary.Load(), backup.Load())
			}
			clock.moveTo(timer.at)
			close(timer.fire)
			trace := assertResult(awaitPilotResult(t, ctx, b), http.StatusBadGateway, 1, "retry_limit")
			if primary.Load() != 2 || backup.Load() != 0 || ojson.Get(trace, "wait_ms").Int() != 300000 {
				t.Fatalf("zero allowed more than B's first send or charged waiting as a send: primary=%d backup=%d trace=%s", primary.Load(), backup.Load(), trace)
			}
		})
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

func TestProviderSchedulingPersistentPilotUnmatchedCaller(t *testing.T) {
	clock := newProviderBudgetClock(time.Now(), false)
	var attempts atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	w := httptest.NewRecorder()
	servePersistentPilot(ctx, f, w, "/v1/chat/completions", persistentPilotChat, "outside-pilot")
	if w.Code != http.StatusBadGateway || attempts.Load() != 1 || len(clock.waits) != 0 || w.Header().Get("X-Request-ID") != "" {
		t.Fatalf("unmatched caller entered the pilot: status=%d sends=%d waits=%d body=%s", w.Code, attempts.Load(), len(clock.waits), w.Body)
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
