package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
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
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

const persistentPilotModel = "gpt-6.2-sol"
const persistentPilotPrimaryResource = "fee222e4-6116-4cd5-9578-23265074d937"
const persistentPilotChat = `{"model":"gpt-6.2-sol","stream":true,"messages":[{"role":"user","content":"hello"}]}`

type persistentPilotClock interface {
	Now() time.Time
	Wait(context.Context, time.Duration) error
}

func newPersistentPilotHTTP(t *testing.T, allowlist string, retries int, clock persistentPilotClock, upstream http.HandlerFunc, options ...ServerOption) *inventoryHarness {
	t.Helper()
	return newConfiguredPersistentPilotHTTP(t, allowlist, retries, clock, 1, "", upstream, options...)
}

func newConfiguredPersistentPilotHTTP(t *testing.T, allowlist string, retries int, clock persistentPilotClock, slots int, pilotYAML string, upstream http.HandlerFunc, options ...ServerOption) *inventoryHarness {
	t.Helper()
	return newPersistentPilotHTTPWithYAML(t, allowlist, retries, clock, slots, 1, pilotYAML, upstream, options...)
}

func newPersistentPilotHTTPWithYAML(t *testing.T, allowlist string, retries int, clock persistentPilotClock, slots, credentials int, pilotYAML string, upstream http.HandlerFunc, options ...ServerOption) *inventoryHarness {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "")
	caller := sha256.Sum256([]byte(sdkaccess.DefaultAccessProviderName + "\x00open"))
	other := sha256.Sum256([]byte(sdkaccess.DefaultAccessProviderName + "\x00second-pilot"))
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := fmt.Sprintf(`access:
  api-keys: [open, second-pilot, outside-pilot]
management:
  secret-key: test-password
oauth:
  auth-dir: %q
multimedia:
  disable-image-generation: true
routing:
  retry:
    request-retry: 1
    max-retry-credentials: %d
    upstream-error-retry-limit: %d
  provider-scheduling:
    mode: enforce
    models: [gpt-6.2-sol, pilot-control-model]
    callers: [%x, %x]
    persistent-retry-models: %s
    resources:
      %q: {funding: subscription, max-concurrent: %d}
%s`, filepath.ToSlash(filepath.Join(dir, "auth")), credentials, retries, caller, other, allowlist, persistentPilotPrimaryResource, slots, pilotYAML)
	if errWrite := os.WriteFile(path, []byte(yaml), 0600); errWrite != nil {
		t.Fatal(errWrite)
	}
	cfg, errLoad := config.LoadConfig(path)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg) // Same initial snapshot as the service builder.
	manager.SetContinuityClockForTest(clock)
	manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
	s := NewServer(cfg, manager, sdkaccess.NewManager(), path, options...)
	f := &inventoryHarness{t: t, server: s, manager: manager}
	t.Cleanup(func() {
		if errStop := s.Stop(context.Background()); errStop != nil {
			t.Error(errStop)
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
	if name == "primary" {
		a.ResourceIdentity = &resource.Binding{Targets: []resource.Target{{ResourceID: persistentPilotPrimaryResource}}}
	}
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
	writePilotEvent(w, `{"type":"response.created","response":{"created_at":1712345678,"status":"in_progress"}}`, "response.id", id)
	writePilotEvent(w, `{"type":"response.in_progress","response":{"status":"in_progress"}}`, "response.id", id)
	w.(http.Flusher).Flush()
}

func persistentPilotFail(w http.ResponseWriter, id string) {
	writePilotEvent(w, `{"type":"response.failed","response":{"status":"failed","error":{"code":"upstream_unavailable","message":"RAW-FAILURE-CANARY"}}}`, "response.id", id)
}

func persistentPilotSucceed(w http.ResponseWriter, text string) {
	persistentPilotSucceedWithID(w, "resp-success", text)
}

func persistentPilotSucceedWithID(w http.ResponseWriter, id, text string) {
	writePilotEvent(w, `{"type":"response.output_text.delta","output_index":0,"content_index":0}`, "delta", text)
	writePilotEvent(w, `{"type":"response.completed","response":{"status":"completed","output":[]}}`, "response.id", id)
}

func writePilotEvent(w http.ResponseWriter, fixture, path, value string) {
	fmt.Fprintf(w, "data: %s\n\n", setPilotFixtureField(fixture, path, value))
}

func setPilotFixtureField(fixture, path, value string) string {
	doc := ojson.NewDocString(fixture)
	_ = doc.Set(path, value)
	return doc.String()
}

func pilotFixtureWithContent(fixture, text string) string {
	path := "input"
	if ojson.Get(fixture, "messages").Exists() {
		path = "messages.0.content"
	}
	return setPilotFixtureField(fixture, path, text)
}

type pilotCloseErrorBody struct{ io.ReadCloser }

func (body pilotCloseErrorBody) Close() error {
	if errClose := body.ReadCloser.Close(); errClose != nil {
		return errClose
	}
	return fmt.Errorf("raw upstream cleanup: CLOSE-CANARY")
}

func TestProviderSchedulingPersistentPilotCleanupCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	logger := log.StandardLogger()
	hooks := logger.ReplaceHooks(log.LevelHooks{})
	hook := logtest.NewLocal(logger)
	t.Cleanup(func() { logger.ReplaceHooks(hooks) })
	logs := t.TempDir()
	var sends atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, newProviderBudgetClock(time.Now(), false), func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		persistentPilotStart(w, "resp-preamble-CANARY")
		writePilotEvent(w, `{"type":"response.failed","response":{"error":{"message":"BODY-CANARY"}}}`, "response.error.code", "thinking_signature_invalid")
	}, WithRequestLoggerFactory(func(*config.Config, string) logging.RequestLogger {
		return logging.NewFileRequestLogger(true, logs, logs, 10)
	}))
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	f.manager.SetRoundTripperProvider(gateFixedTransport{rt: nativeFundingTestTransport(func(r *http.Request) (*http.Response, error) {
		resp, errRoundTrip := transport.RoundTrip(r)
		if errRoundTrip == nil {
			resp.Body = pilotCloseErrorBody{resp.Body}
		}
		return resp, errRoundTrip
	})})
	w := callPersistentPilot(ctx, f, "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"PAYLOAD-CANARY"}`)
	trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
	if w.Code != 400 || sends.Load() != 1 || ojson.Get(trace, "send_count").Int() != 1 ||
		ojson.Get(trace, "retry_stop_reason").String() != "upstream_validation" || strings.Contains(w.Body.String()+trace, "CANARY") {
		t.Fatalf("wrong rejection after cleanup: status=%d sends=%d body=%s trace=%s", w.Code, sends.Load(), w.Body, trace)
	}
	entries, errRead := os.ReadDir(logs)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if len(entries) != 0 {
		t.Fatal("pilot cleanup produced a request capture")
	}
	var closeReported bool
	for _, entry := range hook.AllEntries() {
		closeReported = closeReported || entry.Message == "Codex response body close failed"
		if strings.Contains(entry.Message+fmt.Sprint(entry.Data), "CANARY") {
			t.Fatal("pilot cleanup leaked canary material into application logs")
		}
	}
	if !closeReported {
		t.Fatal("body close failure was not reported")
	}
}

func TestProviderSchedulingPersistentPilotIgnoresPostConnectBootstrapTimer(t *testing.T) {
	for _, buffering := range []bool{false, true} {
		t.Run(fmt.Sprint(buffering), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			started, release := make(chan struct{}), make(chan struct{})
			var sends atomic.Int32
			yaml := fmt.Sprintf("upstream:\n  codex: {stream-bootstrap-buffering: %t, stream-bootstrap-timeout: 20ms}\n", buffering)
			f := newConfiguredPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, newProviderBudgetClock(time.Now(), false), 1, yaml, func(w http.ResponseWriter, req *http.Request) {
				sends.Add(1)
				persistentPilotStart(w, "resp-slow")
				close(started)
				select {
				case <-release:
					persistentPilotSucceedWithID(w, "resp-slow", "slow-response-delivered")
				case <-req.Context().Done():
				}
			})
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- callPersistentPilot(ctx, f, "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"slow"}`)
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("upstream did not start")
			}
			// Hold the real producer open well beyond the configured network timer.
			timer := time.NewTimer(150 * time.Millisecond)
			defer timer.Stop()
			select {
			case w := <-result:
				trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
				t.Fatalf("bootstrap timer ended live stream: status=%d body=%s trace=%s", w.Code, w.Body, trace)
			case <-timer.C:
			}
			close(release)
			w := awaitPilotResult(t, ctx, result)
			trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
			if w.Code != 200 || sends.Load() != 1 || !strings.Contains(w.Body.String(), "slow-response-delivered") ||
				ojson.Get(trace, "send_count").Int() != 1 || ojson.Get(trace, "terminal.code").String() != "succeeded" {
				t.Fatalf("stream did not complete after producer resumed: status=%d sends=%d body=%s trace=%s", w.Code, sends.Load(), w.Body, trace)
			}
		})
	}
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
			a := startPilotRequest(ctx, f, tc.path, pilotFixtureWithContent(tc.body, "request-A"))
			aTimer := awaitPilotTimer(t, ctx, clock, a)
			assertPersistentPilotStepWait(t, aTimer.at.Sub(clock.Now()), time.Second)
			bRecorder := httptest.NewRecorder()
			b := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				servePersistentPilot(ctx, f, bRecorder, tc.path, pilotFixtureWithContent(tc.body, "request-B"), "open")
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
		servePersistentPilot(ctx, f, bRecorder, path, pilotFixtureWithContent(persistentPilotChat, "request-B"), "open")
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

func TestProviderSchedulingPilotManagementDisableAfterTOS(t *testing.T) {
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 1, newProviderBudgetClock(time.Now(), false), func(http.ResponseWriter, *http.Request) { t.Error("disabled credential sent") })
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, []byte(`{"type":"codex","disabled":true,"cpa_disable_cause":"tos_violation"}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	f.manager.SetStore(store)
	reload := func() {
		entries, err := store.List(t.Context())
		if err != nil || len(entries) != 1 {
			t.Fatalf("load: %v (%d entries)", err, len(entries))
		}
		a := entries[0]
		a.ID = t.Name() + "/primary"
		if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); err != nil {
			t.Fatal(err)
		}
	}
	reload()
	updatePilotAuth(t, f, t.Name()+"/primary", func(a *coreauth.Auth) { a.LastError = &coreauth.Error{Code: "tos_violation"} })
	check := func(want string) {
		t.Helper()
		w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
		trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
		if w.Code != 503 || ojson.Get(trace, "retry_stop_reason").String() != want {
			t.Fatalf("want %s: %d %s", want, w.Code, trace)
		}
	}
	check("tos_violation")
	r := httptest.NewRequest(http.MethodPatch, "/v8/management/credentials/status", strings.NewReader(`{"name":"fixture.json","disabled":true}`))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("disable: %d %s", w.Code, w.Body)
	}
	check("manual_disabled")
	reload()
	check("manual_disabled")
}

func TestProviderSchedulingPilotReloadedDisableWithoutCause(t *testing.T) {
	for _, tc := range []struct{ name, body, stop string }{{"legacy", `{"type":"codex","disabled":true}`, "disabled"}, {"operational", `{"type":"codex","disabled":true,"cpa_disable_cause":"tos_violation"}`, "tos_violation"}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "fixture.json"), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			store := fileauth.NewFileTokenStore()
			store.SetBaseDir(dir)
			entries, err := store.List(t.Context())
			if err != nil || len(entries) != 1 {
				t.Fatalf("reload: count=%d err=%v", len(entries), err)
			}
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 1, newProviderBudgetClock(time.Now(), false), func(http.ResponseWriter, *http.Request) { t.Error("disabled credential sent") })
			a := entries[0]
			a.ID = t.Name() + "/primary"
			if _, errUpdate := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
			trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
			if w.Code != 503 || strings.Contains(trace, "manual_disabled") || ojson.Get(trace, "retry_stop_reason").String() != tc.stop || ojson.Get(trace, "send_count").Int() != 0 {
				t.Fatalf("status=%d trace=%s", w.Code, trace)
			}
		})
	}
}

func TestProviderSchedulingPersistentPilotFirstSendRecovery(t *testing.T) {
	const path = "/v1/chat/completions"
	for _, scenario := range []string{"trusted-hint", "healthy-backup", "backup-wakes-waiter", "cancel", "no-route", "operational-suspension", "ineligible-backup", "unscoped-quota"} {
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
				if scenario == "unscoped-quota" && primary.Add(1) == 1 {
					w.WriteHeader(http.StatusTooManyRequests)
					fmt.Fprint(w, `{"error":{"type":"usage_limit_reached","message":"You've hit your usage limit.","resets_in_seconds":300}}`)
					return
				}
				if scenario == "unscoped-quota" {
					persistentPilotStart(w, "resp-quota-recovered")
					persistentPilotSucceed(w, "quota-envelope-first-send")
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
			if scenario == "unscoped-quota" {
				// Unlike WHAMAuthority's confirmed quota gate, this envelope can
				// neither stop B nor establish a 300s retry deadline.
				assertResult(call(), http.StatusTooManyRequests, 1, "retry_limit")
				b := startPilotRequest(ctx, f, path, persistentPilotChat)
				timer := awaitPilotTimer(t, ctx, clock, b)
				assertPersistentPilotStepWait(t, timer.at.Sub(start), time.Second)
				if primary.Load() != 1 {
					t.Fatal("B sent before transient backoff expired")
				}
				clock.moveTo(timer.at)
				close(timer.fire)
				w := awaitPilotResult(t, ctx, b)
				trace := assertResult(w, http.StatusOK, 1, "")
				if primary.Load() != 2 || !strings.Contains(w.Body.String(), "quota-envelope-first-send") || !ojson.Get(trace, "last_recovery_wait").Exists() {
					t.Fatalf("B did not recover its first send: status=%d body=%s trace=%s", w.Code, w.Body, trace)
				}
				return
			}
			// Prime the shared cooldown. The explicit zero must forbid A's
			// addition but not B's first send later on the same route.
			assertResult(call(), http.StatusBadGateway, 1, "retry_limit")
			primaryID := t.Name() + "/primary"
			switch scenario {
			case "no-route":
				updatePilotAuth(t, f, primaryID, func(a *coreauth.Auth) {
					a.Disabled = true
					a.Metadata = map[string]any{coreauth.DisableCauseMetadataKey: "manual"}
				})
				if trace := assertResult(call(), http.StatusServiceUnavailable, 0, "manual_disabled"); ojson.Get(trace, "last_recovery_wait").Exists() || ojson.Get(trace, "terminal.code").String() != "no_available_route" {
					t.Fatalf("disabled route caused a wait: %s", trace)
				}
				return
			case "operational-suspension":
				updatePilotAuth(t, f, primaryID, func(a *coreauth.Auth) {
					a.Disabled, a.Status = true, coreauth.StatusDisabled
					a.LastError = &coreauth.Error{Code: "tos_violation"}
				})
				if trace := assertResult(call(), http.StatusServiceUnavailable, 0, "tos_violation"); ojson.Get(trace, "last_recovery_wait").Exists() || strings.Contains(trace, "manual_disabled") {
					t.Fatalf("wrong suspension evidence: %s", trace)
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
			b := startPilotRequest(bCtx, f, path, pilotFixtureWithContent(persistentPilotChat, "request-B"))
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

func waitForPilotEvent(t *testing.T, ctx context.Context, f *inventoryHarness, path, event string) <-chan *httptest.ResponseRecorder {
	t.Helper()
	ctx = coreauth.WithFreshRequestBudget(ctx)
	done := startPilotRequest(ctx, f, path, persistentPilotChat)
	for {
		id := coreauth.RoutingTraceID(ctx)
		if id != "" {
			trace := readSchedulingTraceForTest(t, f, id)
			if ojson.Get(trace, "last_recovery_wait."+event).Bool() && ojson.Get(trace, "send_count").Int() == 0 && !ojson.Get(trace, "terminal").Exists() {
				return done
			}
		}
		select {
		case result := <-done:
			t.Fatalf("request did not wait for %s: %d %s", event, result.Code, result.Body)
		case <-ctx.Done():
			t.Fatalf("missing %s wait (request %q)", event, id)
		default:
			runtime.Gosched()
		}
	}
}

func TestProviderSchedulingPersistentPilotDeadlineWhileWaiting(t *testing.T) {
	clock := newManualPersistentPilotClock()
	var sends atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.WriteHeader(502)
	})
	// A genuine request deadline, not a restriction inferred from Retry-After.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := startPilotRequest(ctx, f, "/v1/chat/completions", persistentPilotChat)
	awaitPilotTimer(t, ctx, clock, done)
	w := awaitPilotResult(t, t.Context(), done)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if sends.Load() != 1 || ojson.Get(trace, "retry_stop_reason").String() != "deadline_exceeded" || ojson.Get(trace, "terminal.code").String() != "deadline_exceeded" {
		t.Fatalf("real deadline reported incorrectly: sends=%d trace=%s", sends.Load(), trace)
	}
}

func TestProviderSchedulingPersistentPilotWaitsForCapacity(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 8*time.Second)
	defer stop()
	clock := newManualPersistentPilotClock()
	entered, release := make(chan struct{}), make(chan struct{})
	var sends atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, func(w http.ResponseWriter, r *http.Request) {
		if sends.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		persistentPilotStart(w, "resp-success")
		persistentPilotSucceed(w, "capacity-available")
	})
	defer close(release)
	path := "/v1/chat/completions"
	a := startPilotRequest(ctx, f, path, persistentPilotChat)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("A never entered upstream")
	}
	b := waitForPilotEvent(t, ctx, f, path, "capacity_pending")
	if sends.Load() != 1 {
		t.Fatal("B sent before acquiring capacity")
	}
	release <- struct{}{}
	awaitPilotResult(t, ctx, a)
	w := awaitPilotResult(t, ctx, b)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != 200 || sends.Load() != 2 || !strings.Contains(w.Body.String(), "capacity-available") ||
		ojson.Get(trace, "send_count").Int() != 1 || !ojson.Get(trace, "last_recovery_wait.capacity_pending").Bool() {
		t.Fatalf("wrong capacity recovery: status=%d sends=%d trace=%s", w.Code, sends.Load(), trace)
	}
}

func TestProviderSchedulingPersistentPilotRefreshLogsOpaqueCredential(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	logger := log.StandardLogger()
	level, hooks := logger.GetLevel(), logger.ReplaceHooks(log.LevelHooks{})
	hook := logtest.NewLocal(logger)
	logger.SetLevel(log.DebugLevel)
	t.Cleanup(func() { logger.SetLevel(level); logger.ReplaceHooks(hooks) })
	var sends, renewals atomic.Int32
	usePilotRefreshIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected issuer path %s", r.URL.Path)
		}
		renewals.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"GRANT-CANARY"}`)
	})
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 1, newProviderBudgetClock(time.Now(), false), func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":"token_expired","message":"UPSTREAM-CANARY"}}`)
	})
	const file = "FILE-CANARY@example.test.json"
	primary, ok := f.manager.GetByID(t.Name() + "/primary")
	if !ok {
		t.Fatal("missing primary credential")
	}
	updatePilotAuth(t, f, primary.ID, func(a *coreauth.Auth) { a.Disabled = true })
	primary.ID, primary.Index, primary.FileName = file, "", file
	delete(primary.Attributes, "api_key")
	primary.Metadata = map[string]any{"type": "codex", "access_token": "ACCESS-CANARY", "refresh_token": "REFRESH-CANARY"}
	if _, errRegister := f.manager.Register(coreauth.WithSkipPersist(ctx), primary); errRegister != nil {
		t.Fatal(errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(file, "codex", []*registry.ModelInfo{{ID: persistentPilotModel}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(file) })
	transport := http.DefaultTransport
	http.DefaultTransport = nativeFundingTestTransport(func(r *http.Request) (*http.Response, error) {
		resp, err := transport.RoundTrip(r)
		if err == nil && r.URL.Path == "/oauth/token" {
			resp.Body = pilotCloseErrorBody{resp.Body}
		}
		return resp, err
	})
	t.Cleanup(func() { http.DefaultTransport = transport })
	hook.Reset() // Observe the request and refresh, not fixture registration.
	w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
	trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
	if w.Code != 502 || sends.Load() != 1 || renewals.Load() != 1 || ojson.Get(trace, "send_count").Int() != 1 ||
		ojson.Get(trace, "retry_stop_reason").String() != "upstream_authentication_required" || strings.Contains(w.Body.String()+trace, "CANARY") {
		t.Fatalf("wrong refresh result: status=%d sends=%d renewals=%d trace=%s", w.Code, sends.Load(), renewals.Load(), trace)
	}
	var correlated bool
	for _, entry := range hook.AllEntries() {
		if strings.Contains(entry.Message, "refresh") && entry.Data["credential_ref"] != nil {
			correlated = true
		}
		if strings.Contains(entry.Message+fmt.Sprint(entry.Data), "CANARY") {
			t.Fatal("credential refresh leaked canary material to application logs")
		}
	}
	if !correlated {
		t.Fatal("missing opaque credential reference in refresh logs")
	}
}

func usePilotRefreshIssuer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	issuer, network := quotaTLS(t, handler)
	transport := issuer.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = "chatgpt.com"
	transport.DialContext = func(ctx context.Context, protocol, addr string) (net.Conn, error) {
		if addr != "auth.openai.com:443" {
			return (&net.Dialer{}).DialContext(ctx, protocol, addr)
		}
		return network.DialContext(ctx, protocol, addr)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
}

func TestProviderSchedulingPersistentPilotWaitsForActualRefresh(t *testing.T) {
	for _, outcome := range []string{"renewed", "invalid-grant"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, stop := context.WithTimeout(t.Context(), 10*time.Second)
			defer stop()
			clock := newManualPersistentPilotClock()
			entered, release := make(chan struct{}), make(chan struct{})
			var inference, renewals atomic.Int32
			usePilotRefreshIssuer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/token" || renewals.Add(1) != 1 {
					t.Error("unexpected OAuth request")
					w.WriteHeader(500)
					return
				}
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return
				}
				if outcome == "invalid-grant" {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"error":"invalid_grant","error_description":"GRANT-CANARY"}`)
					return
				}
				fmt.Fprint(w, `{"access_token":"renewed-CANARY","refresh_token":"new-grant-CANARY","expires_in":3600}`)
			})
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, clock, func(w http.ResponseWriter, r *http.Request) {
				inference.Add(1)
				if r.Header.Get("Authorization") != "Bearer renewed-CANARY" {
					t.Error("sent inference without the renewed token")
				}
				persistentPilotStart(w, "resp-success")
				persistentPilotSucceed(w, "renewal-available")
			})
			id := t.Name() + "/primary"
			updatePilotAuth(t, f, id, func(a *coreauth.Auth) {
				delete(a.Attributes, "api_key")
				a.Metadata = map[string]any{"type": "codex", "access_token": "expired-CANARY", "refresh_token": "old-grant-CANARY", "expired": time.Now().Add(-time.Hour).Format(time.RFC3339)}
			})
			// Before a job is running, expiry (even with a scheduled due time)
			// neither admits an execution nor supplies an event to wait on.
			path := "/v1/chat/completions"
			if w := callPersistentPilot(ctx, f, path, persistentPilotChat); w.Code != 503 || inference.Load() != 0 {
				t.Fatalf("expired credential unexpectedly dispatched: %d %s", w.Code, w.Body)
			}
			f.manager.StartAutoRefresh(ctx, time.Millisecond)
			defer f.manager.StopAutoRefresh()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("real OAuth exchange never entered")
			}
			b := waitForPilotEvent(t, ctx, f, path, "refresh_pending")
			if inference.Load() != 0 {
				t.Fatal("refresh was counted as inference or bypassed")
			}
			close(release)
			w := awaitPilotResult(t, ctx, b)
			trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
			wantStatus, wantSends := 200, int32(1)
			if outcome == "invalid-grant" {
				wantStatus, wantSends = 503, 0
				if ojson.Get(trace, "retry_stop_reason").String() != "reauthentication_required" {
					t.Fatalf("grant rejection did not record reauthentication: %s", trace)
				}
			}
			if w.Code != wantStatus || inference.Load() != wantSends || renewals.Load() != 1 || ojson.Get(trace, "send_count").Int() != int64(wantSends) || strings.Contains(w.Body.String()+trace, "CANARY") {
				t.Fatalf("wrong refresh resolution: status=%d sends=%d trace=%s", w.Code, inference.Load(), trace)
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

func TestProviderSchedulingPilotCompatibilityFallbackHonorsCredentialLimit(t *testing.T) {
	var primary, compat atomic.Int32
	f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 1, newProviderBudgetClock(time.Now(), true), func(w http.ResponseWriter, _ *http.Request) {
		if primary.Add(1) == 1 {
			http.Error(w, "temporary", 502)
			return
		}
		persistentPilotStart(w, "resp-primary")
		persistentPilotSucceed(w, "primary-recovered")
	})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { compat.Add(1); http.Error(w, "unexpected fallback", 502) }))
	t.Cleanup(target.Close)
	const provider = "openai-compatibility"
	id := t.Name() + "/compat"
	f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(provider, f.server.cfg))
	_, err := f.manager.Register(coreauth.WithSkipPersist(t.Context()), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": "fixture", "base_url": target.URL, "compat_name": provider, "priority": "10"}, Metadata: map[string]any{"request_retry": 0}})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: persistentPilotModel}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
	if compat.Load() != 0 {
		t.Fatalf("legacy credential sent in excluded round: compat=%d primary=%d status=%d", compat.Load(), primary.Load(), w.Code)
	}
	if primary.Load() != 2 || w.Code != 200 {
		t.Fatalf("eligible pilot did not recover: primary=%d status=%d body=%s", primary.Load(), w.Code, w.Body)
	}
}

func TestProviderSchedulingPersistentPilotExplicitBudgetOverridesCredentialRetry(t *testing.T) {
	for _, limit := range []int{-1, 1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			clock := newProviderBudgetClock(time.Now(), true)
			var sends atomic.Int32
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", limit, clock, func(w http.ResponseWriter, _ *http.Request) {
				if sends.Add(1) <= 2 {
					http.Error(w, "temporary failure", http.StatusBadGateway)
					return
				}
				persistentPilotStart(w, "resp-recovered")
				persistentPilotSucceedWithID(w, "resp-recovered", "recovered-after-two")
			})
			a, ok := f.manager.GetByID(t.Name() + "/primary")
			if !ok {
				t.Fatal("missing primary credential")
			}
			a.Metadata = map[string]any{"request_retry": 0}
			if _, errUpdate := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
			trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
			wantStatus, wantSends, wantStop := 200, int32(3), ""
			if limit == 1 {
				wantStatus, wantSends, wantStop = 502, 2, "retry_limit"
			}
			gotResult := strings.Contains(w.Body.String(), "recovered-after-two")
			if w.Code != wantStatus || gotResult != (limit == -1) || sends.Load() != wantSends ||
				ojson.Get(trace, "retry_policy.upstream_error_retry_limit").Int() != int64(limit) ||
				ojson.Get(trace, "send_count").Int() != int64(wantSends) || ojson.Get(trace, "retry_stop_reason").String() != wantStop {
				t.Fatalf("wrong budget outcome: status=%d sends=%d body=%s trace=%s", w.Code, sends.Load(), w.Body, trace)
			}
		})
	}
}

func TestProviderSchedulingPilotUnscopedQuotaFrameStatus(t *testing.T) {
	for _, path := range []string{"status_code", "error.status_code"} {
		t.Run(path, func(t *testing.T) {
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", 0, newProviderBudgetClock(time.Now(), true), func(w http.ResponseWriter, _ *http.Request) {
				persistentPilotStart(w, "resp-hidden")
				doc := ojson.NewDocString(`{"type":"response.failed","error":{"type":"usage_limit_reached","message":"RAW-CANARY"}}`)
				_ = doc.Set(path, 502)
				fmt.Fprintf(w, "data: %s\n\n", doc.String())
			})
			w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
			trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
			if w.Code != 502 || ojson.Get(trace, "upstream_category").String() != "transient_upstream" || strings.Contains(w.Body.String()+trace, "CANARY") {
				t.Fatalf("status=%d body=%s trace=%s", w.Code, w.Body, trace)
			}
		})
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
		status       int
		legacy       bool
		recover      bool
		wantStatus   int
		wantSends    int32
		wantWaits    int
		wantCategory string
		wantStop     string
		wantSource   string
	}{
		{name: "bare 429", body: `{"error":{"message":"temporary upstream rejection"}}`, status: 429, recover: true, wantStatus: 200, wantSends: 2, wantWaits: 1, wantCategory: "transient_rate_limit", wantSource: "local_backoff"},
		{name: "unscoped quota 429", body: quotaBody, status: 429, recover: true, wantStatus: 200, wantSends: 2, wantWaits: 1, wantCategory: "transient_rate_limit", wantSource: "local_backoff"},
		{name: "unscoped quota on 502", body: quotaBody, status: 502, recover: true, wantStatus: 200, wantSends: 2, wantWaits: 1, wantCategory: "transient_upstream", wantSource: "local_backoff"},
		{name: "legacy quota 429", body: quotaBody, status: 429, legacy: true, wantStatus: 429, wantSends: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newProviderBudgetClock(time.Now(), true)
			var attempts atomic.Int32
			allowlist := "[gpt-6.2-sol]"
			if tc.legacy {
				allowlist = "[]"
			}
			f := newPersistentPilotHTTP(t, allowlist, -1, clock, func(w http.ResponseWriter, _ *http.Request) {
				n := attempts.Add(1)
				if tc.recover && n > 1 {
					persistentPilotStart(w, "resp-success")
					persistentPilotSucceed(w, "recovered-without-quota-authority")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			ctx, cancel := context.WithTimeout(coreauth.WithRequestBudget(t.Context()), 10*time.Second)
			defer cancel()
			w := callPersistentPilot(ctx, f, "/v1/chat/completions", persistentPilotChat)
			trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
			if w.Code != tc.wantStatus || attempts.Load() != tc.wantSends || len(clock.waits) != tc.wantWaits || ojson.Get(trace, "send_count").Int() != int64(tc.wantSends) ||
				(tc.recover && !strings.Contains(w.Body.String(), "recovered-without-quota-authority")) {
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

func TestProviderSchedulingPersistentPilotTerminalEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, code, stop, public string
		status                   int
		local                    bool
	}{
		{"local validation", "", "local_validation", "invalid_request", 400, true},
		{"upstream validation", "invalid_value", "upstream_validation", "invalid_request", 400, false},
		{"upstream safety policy", "content_policy_violation", "upstream_policy", "upstream_policy", 400, false},
		{"route permission", "permission_denied", "route_permission_denied", "route_permission_denied", 502, false},
		{"credential revoked", "token_revoked", "credential_revoked", "credential_revoked", 502, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newProviderBudgetClock(time.Now(), true)
			var sends atomic.Int32
			logs := t.TempDir()
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
				if sends.Add(1) > 1 {
					persistentPilotStart(w, "resp-success")
					persistentPilotSucceed(w, "not-allowed")
					return
				}
				persistentPilotStart(w, "resp-hidden-CANARY")
				writePilotEvent(w, `{"type":"response.failed","response":{"error":{"message":"UPSTREAM-CANARY"}}}`, "response.error.code", tc.code)
			}, WithRequestLoggerFactory(func(*config.Config, string) logging.RequestLogger {
				return logging.NewFileRequestLogger(true, logs, logs, 10)
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			input := `{"model":"gpt-6.2-sol","stream":true,"input":"PAYLOAD-CANARY"}`
			if tc.local {
				input = `{"model":"gpt-6.2-sol","stream":true,"input":"PAYLOAD-CANARY","previous_response_id":"resp_ag_compact_123"}`
			}
			w := callPersistentPilot(ctx, f, "/v1/responses", input)
			trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
			wantSends := int32(1)
			if tc.local {
				wantSends = 0
			}
			if w.Code != tc.status || sends.Load() != wantSends || len(clock.waits) != 0 ||
				ojson.Get(w.Body.String(), "error.code").String() != tc.public || ojson.Get(trace, "send_count").Int() != int64(wantSends) ||
				ojson.Get(trace, "retry_stop_reason").String() != tc.stop || strings.Contains(w.Body.String()+trace, "CANARY") {
				t.Fatalf("wrong terminal: status=%d sends=%d body=%s trace=%s", w.Code, sends.Load(), w.Body, trace)
			}
			entries, err := os.ReadDir(logs)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatal("pilot created a full request/response log")
			}
		})
	}
}

func TestProviderSchedulingPilotMixedRouteDenialAtLimit(t *testing.T) {
	var a, b atomic.Int32
	f := newPersistentPilotHTTPWithYAML(t, "[gpt-6.2-sol]", 1, newProviderBudgetClock(time.Now(), true), 1, 2, "", func(w http.ResponseWriter, _ *http.Request) { a.Add(1); http.Error(w, "RAW-CANARY", 502) })
	addPersistentPilotCodex(t, f, "backup", "10", func(w http.ResponseWriter, _ *http.Request) {
		b.Add(1)
		http.Error(w, `{"error":{"code":"permission_denied","message":"RAW-CANARY"}}`, 403)
	})
	w := callPersistentPilot(t.Context(), f, "/v1/chat/completions", persistentPilotChat)
	trace := readSchedulingTraceForTest(t, f, w.Header().Get("X-Request-ID"))
	if w.Code != 502 || a.Load() != 1 || b.Load() != 1 || ojson.Get(w.Body.String(), "error.code").String() != "upstream_unavailable" || ojson.Get(trace, "retry_stop_reason").String() != "retry_limit" || strings.Contains(trace+w.Body.String(), "CANARY") {
		t.Fatalf("status=%d sends=%d+%d body=%s trace=%s", w.Code, a.Load(), b.Load(), w.Body, trace)
	}
}

func TestProviderSchedulingPersistentPilotStructuredFailureScope(t *testing.T) {
	for _, tc := range []struct {
		name, envelope, stop, result string
		status, wantStatus           int
		primary, backup              int32
		waits                        int
		primaryFailsFirst            bool
		credentials                  int
	}{
		{"model_denial_is_route_local", `{"error":{"type":"invalid_request_error","code":"model_not_found","param":"model","message":"RAW-CANARY"}}`, "", "backup-success", 404, 200, 1, 1, 0, false, 1},
		{"explicit_overload_is_transient", `{"error":{"type":"invalid_request_error","code":"server_is_overloaded","param":"model","message":"RAW-CANARY"}}`, "", "primary-recovered", 503, 200, 2, 0, 1, false, 1},
		{"specific_validation_without_param_is_terminal", `{"error":{"type":"invalid_request_error","code":"string_above_max_length","param":null,"message":"RAW-CANARY"}}`, "upstream_validation", "invalid_request", 400, 400, 1, 0, 0, false, 1},
		{"unknown_code_with_param_remains_recoverable", `{"error":{"type":"invalid_request_error","code":"unknown_rejection","param":"model","message":"RAW-CANARY"}}`, "", "primary-recovered", 400, 200, 2, 0, 1, false, 1},
		{"route_rejection_does_not_discard_prior_transient", `{"error":{"type":"permission_error","code":"permission_denied","message":"RAW-CANARY"}}`, "", "primary-recovered", 403, 200, 2, 1, 1, true, 1},
		{"same_round_rejection_does_not_discard_prior_transient", `{"error":{"type":"permission_error","code":"permission_denied","message":"RAW-CANARY"}}`, "", "primary-recovered", 403, 200, 2, 1, 1, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newProviderBudgetClock(time.Now(), true)
			var primary, backup atomic.Int32
			reject := func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.envelope)
			}
			f := newPersistentPilotHTTPWithYAML(t, "[gpt-6.2-sol]", -1, clock, 1, tc.credentials, "", func(w http.ResponseWriter, _ *http.Request) {
				if primary.Add(1) == 1 {
					if tc.primaryFailsFirst {
						http.Error(w, "RAW-CANARY", http.StatusBadGateway)
					} else {
						reject(w)
					}
					return
				}
				persistentPilotStart(w, "resp-fresh-primary")
				persistentPilotSucceed(w, "primary-recovered")
			})
			if tc.backup > 0 {
				addPersistentPilotCodex(t, f, "backup", "10", func(w http.ResponseWriter, _ *http.Request) {
					if backup.Add(1) == 1 && tc.primaryFailsFirst {
						reject(w)
						return
					}
					persistentPilotStart(w, "resp-fresh-backup")
					persistentPilotSucceed(w, "backup-success")
				})
			}
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			w := callPersistentPilot(ctx, f, "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"fixture"}`)
			trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
			body := w.Body.String()
			sends, stop := ojson.Get(trace, "send_count").Int(), ojson.Get(trace, "retry_stop_reason").String()
			resultOK := strings.Contains(body, tc.result) && ojson.Get(trace, "terminal.code").String() == "succeeded"
			if tc.wantStatus != http.StatusOK {
				resultOK = ojson.Get(body, "error.code").String() == tc.result && ojson.Get(trace, "terminal.code").String() == tc.result
			}
			if w.Code != tc.wantStatus || primary.Load() != tc.primary || backup.Load() != tc.backup || len(clock.waits) != tc.waits ||
				sends != int64(tc.primary+tc.backup) || stop != tc.stop || !resultOK || strings.Contains(body+trace, "RAW-CANARY") {
				t.Fatalf("status=%d primary=%d backup=%d waits=%d counted=%d stop=%q\nbody=%s\ntrace=%s", w.Code, primary.Load(), backup.Load(), len(clock.waits), sends, stop, body, trace)
			}
		})
	}
}

func TestProviderSchedulingPersistentPilotUnclassifiedUpstreamRecovers(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(*testing.T, http.ResponseWriter)
	}{
		{"ordinary-403", func(_ *testing.T, w http.ResponseWriter) { http.Error(w, "RAW-FAILURE-CANARY", 403) }},
		{"unrecognized-422", func(_ *testing.T, w http.ResponseWriter) {
			http.Error(w, `{"error":{"code":"unknown_rejection","message":"RAW-FAILURE-CANARY"}}`, 422)
		}},
		{"unknown-stream-failure", func(_ *testing.T, w http.ResponseWriter) {
			persistentPilotStart(w, "resp-hidden-CANARY")
			fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"status_code\":403,\"error\":{\"code\":\"unrecognized\",\"message\":\"RAW-FAILURE-CANARY\"}}}\n\n")
		}},
		{"disconnected-after-preamble", func(t *testing.T, w http.ResponseWriter) {
			// An incomplete chunked HTTP response, not a terminal SSE event.
			persistentPilotStart(w, "resp-hidden-CANARY")
			conn, _, errHijack := w.(http.Hijacker).Hijack()
			if errHijack != nil {
				t.Error(errHijack)
				return
			}
			_ = conn.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newProviderBudgetClock(time.Now(), true)
			var sends atomic.Int32
			f := newPersistentPilotHTTP(t, "[gpt-6.2-sol]", -1, clock, func(w http.ResponseWriter, _ *http.Request) {
				if sends.Add(1) == 1 {
					tc.fail(t, w)
					return
				}
				persistentPilotStart(w, "resp-success")
				persistentPilotSucceed(w, "recovered-request")
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			w := callPersistentPilot(ctx, f, "/v1/responses", `{"model":"gpt-6.2-sol","stream":true,"input":"PAYLOAD-CANARY"}`)
			trace := awaitPilotTerminalTrace(t, ctx, f, w.Header().Get("X-Request-ID"))
			body := w.Body.String()
			if w.Code != 200 || sends.Load() != 2 || len(clock.waits) != 1 || strings.Count(body, `"type":"response.created"`) != 1 ||
				strings.Count(body, `"type":"response.completed"`) != 1 || !strings.Contains(body, "recovered-request") || strings.Contains(body+trace, "CANARY") ||
				ojson.Get(trace, "send_count").Int() != 2 || ojson.Get(trace, "terminal.code").String() != "succeeded" {
				t.Fatalf("expected a single recovered response: status=%d sends=%d body=%s trace=%s", w.Code, sends.Load(), body, trace)
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
			w := callPersistentPilot(ctx, f, "/v1/chat/completions", setPilotFixtureField(persistentPilotChat, "model", model))
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
