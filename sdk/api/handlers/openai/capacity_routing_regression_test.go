package openai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gjson "github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const capacityRouteError = `{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","headers":{"x-retry-metadata":"NO_MORE_RETRY"},"message":"Our servers are currently overloaded. Please try again later."}}`

// Only the provider boundary is controlled: handler, conductor, credential
// selection, protocol translation and Codex executors are the real components.
type capacityRouteFixture struct {
	t        *testing.T
	manager  *coreauth.Manager
	url      string
	model    string
	mu       sync.Mutex
	attempts []string
	models   []string
	finished chan struct{}
}

func newCapacityRouteFixture(t *testing.T, transport string, limit int, upstreamReply func(string) (int, []string), configure ...func(*config.Config)) *capacityRouteFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := &capacityRouteFixture{t: t, model: "capacity-route-model", finished: make(chan struct{}, 1)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		var conn *websocket.Conn
		var payload []byte
		var err error
		if websocket.IsWebSocketUpgrade(r) {
			conn, err = (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				t.Error(err)
				return
			}
			defer func() { _ = conn.Close() }()
			_, payload, err = conn.ReadMessage()
		} else {
			payload, err = io.ReadAll(r.Body)
		}
		if err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		f.attempts = append(f.attempts, key)
		f.models = append(f.models, gjson.GetBytes(payload, "model").String())
		f.mu.Unlock()
		status, events := upstreamReply(key)
		if conn != nil {
			for {
				for _, event := range events {
					if err = conn.WriteMessage(websocket.TextMessage, []byte(event)); err != nil {
						return
					}
				}
				_, payload, err = conn.ReadMessage()
				if err != nil {
					return
				}
				f.mu.Lock()
				f.attempts = append(f.attempts, key)
				f.models = append(f.models, gjson.GetBytes(payload, "model").String())
				f.mu.Unlock()
				_, events = upstreamReply(key)
			}
		}
		if status != http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, events[0])
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, event := range events {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", event)
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(upstream.Close)
	cfg := &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: true}}
	for _, apply := range configure {
		apply(cfg)
	}
	manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	f.manager = manager
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, limit)
	manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(cfg))
	t.Cleanup(func() { manager.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID) })
	for i, key := range []string{"a", "disabled", "b", "c"} {
		id := t.Name() + "-" + key
		auth := &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive,
			Disabled: key == "disabled", Attributes: map[string]string{
				"api_key": key, "base_url": upstream.URL, "priority": fmt.Sprint(100 - i),
				"websockets": fmt.Sprint(transport == "ws"),
			}}
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: f.model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager))
	router := gin.New()
	router.POST("/v1/responses", func(c *gin.Context) {
		defer func() { f.finished <- struct{}{} }()
		h.Responses(c)
	})
	router.GET("/v1/responses", func(c *gin.Context) {
		defer func() { f.finished <- struct{}{} }()
		h.ResponsesWebsocket(c)
	})
	downstream := httptest.NewServer(router)
	t.Cleanup(downstream.Close)
	f.url = downstream.URL + "/v1/responses"
	return f
}

func (f *capacityRouteFixture) request(transport string, allowSilentClose ...bool) (int, string) {
	f.t.Helper()
	if transport == "ws" {
		conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(f.url, "http"), nil)
		if response != nil {
			_ = response.Body.Close()
		}
		if err != nil {
			f.t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[]}`, f.model))); err != nil {
			f.t.Fatal(err)
		}
		var frames []string
		for {
			_, payload, errRead := conn.ReadMessage()
			if errRead != nil {
				if len(allowSilentClose) > 0 && allowSilentClose[0] && websocket.IsCloseError(errRead, websocket.CloseAbnormalClosure) {
					return websocket.CloseAbnormalClosure, strings.Join(frames, "\n")
				}
				f.t.Fatalf("read downstream: %v; frames=%v", errRead, frames)
			}
			frames = append(frames, string(payload))
			switch gjson.GetBytes(payload, "type").String() {
			case "response.completed", "response.failed", "error":
				return 101, strings.Join(frames, "\n")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, strings.NewReader(fmt.Sprintf(`{"model":%q,"input":[],"stream":%t}`, f.model, transport == "sse")))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		f.t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

func (f *capacityRouteFixture) assertAttempts(want string) {
	f.t.Helper()
	select {
	case <-f.finished:
	case <-time.After(5 * time.Second):
		f.t.Fatal("CPA handler did not finish")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := strings.Join(f.attempts, ","); got != want {
		f.t.Fatalf("upstream attempts=%s, want %s", got, want)
	}
	for _, model := range f.models {
		if model != f.model {
			f.t.Fatalf("model changed to %q", model)
		}
	}
	f.t.Logf("upstream attempts=%v; unchanged models=%v", f.attempts, f.models)
}

func capacityRouteSuccess() []string {
	return []string{`{"type":"response.completed","response":{"id":"healthy","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"success-marker"}]}]}}`}
}

func TestResponsesIncompletePreambleRetriesInsideCPA(t *testing.T) {
	for _, event := range []string{
		`{"type":"response.output_item.added","item":{"id":"discarded","type":"reasoning","summary":[]}}`,
		`{"type":"response.output_item.added","item":{"id":"discarded","type":"reasoning","summary":[],"encrypted_content":"synthetic-signature"}}`,
		`{"type":"response.output_item.done","item":{"id":"discarded","type":"reasoning","summary":[],"encrypted_content":"synthetic-signature"}}`,
		`{"type":"response.output_item.added","item":{"id":"discarded","type":"message","content":[]}}`,
		`{"type":"response.reasoning_summary_part.added","part":{"type":"summary_text","text":""}}`,
	} {
		for _, buffering := range []bool{false, true} {
			t.Run(fmt.Sprintf("buffering=%t/%s", buffering, event), func(t *testing.T) {
				f := newCapacityRouteFixture(t, "sse", 3, func(key string) (int, []string) {
					if key == "a" {
						// The real upstream closes without response.completed. All components
						// between this HTTP boundary and the downstream client stay real.
						return 200, []string{`{"type":"response.created","response":{"id":"discarded"}}`, event}
					}
					return 200, capacityRouteSuccess()
				}, func(cfg *config.Config) {
					cfg.Codex.StreamBootstrapTimeout = "5m"
					cfg.Codex.StreamBootstrapBuffering = buffering
				})
				f.manager.SetUpstreamErrorRetryLimit(3)
				status, body := f.request("sse")
				if status != 200 || !strings.Contains(body, "success-marker") || strings.Contains(body, "discarded") || strings.Contains(body, "stream disconnected") {
					t.Fatalf("pre-output disconnect leaked to client: status=%d body=%s", status, body)
				}
				f.assertAttempts("a,b")
			})
		}
	}
}

func TestCapacityRoutingBeforeOutput(t *testing.T) {
	for _, transport := range []string{"http", "sse", "ws"} {
		t.Run(transport, func(t *testing.T) {
			f := newCapacityRouteFixture(t, transport, 3, func(key string) (int, []string) {
				if key == "a" {
					return 200, []string{
						`{"type":"response.created","response":{"id":"failed-preamble","output":[]}}`,
						`{"type":"response.output_text.delta","delta":""}`, capacityRouteError,
					}
				}
				return 200, capacityRouteSuccess()
			})
			status, body := f.request(transport)
			if !strings.Contains(body, "success-marker") || strings.Contains(body, "failed-preamble") || strings.Contains(body, "server_is_overloaded") {
				t.Fatalf("status=%d body=%s", status, body)
			}
			f.assertAttempts("a,b")
		})
	}
}

func TestCapacityRoutingVariants(t *testing.T) {
	variants := []struct {
		name   string
		status int
		event  string
	}{
		{"nested_502_message", 502, `{"error":{"message":"Selected Model is at capacity"}}`},
		{"inference_admission_503", 503, `{"error":{"message":"inference admission unavailable or restricted"}}`},
		{"overloaded_code", 200, `{"type":"error","error":{"code":"server_is_overloaded","message":"busy"}}`},
		{"unavailable_type", 200, `{"type":"error","error":{"type":"service_unavailable_error","message":"busy"}}`},
		{"model_capacity_code", 200, `{"type":"error","error":{"code":"model_at_capacity","message":"busy"}}`},
		{"codex_turn_capacity", 200, `{"type":"error","error":{"type":"rate_limit_error","code":"turn_rate_limit_exceeded","message":"Codex is at capacity, please try again later"}}`},
		{"bare_envelope", 200, `{"error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"busy"}}`},
		{"response_failed", 200, `{"type":"response.failed","response":{"id":"failed-preamble","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"busy"}}}`},
	}
	for _, variant := range variants {
		for _, transport := range []string{"http", "sse", "ws"} {
			t.Run(variant.name+"/"+transport, func(t *testing.T) {
				f := newCapacityRouteFixture(t, transport, 3, func(key string) (int, []string) {
					if key != "a" {
						return 200, capacityRouteSuccess()
					}
					if variant.status != 200 && transport != "ws" {
						return variant.status, []string{variant.event}
					}
					return 200, []string{
						`{"type":"response.created","response":{"id":"failed-preamble","output":[]}}`,
						`{"type":"response.in_progress","response":{"id":"failed-preamble"}}`,
						`{"type":"keepalive"}`,
						`{"type":"rate_limits.updated","rate_limits":[]}`,
						`{"type":"response.output_text.delta","delta":""}`,
						`{"type":"response.reasoning_text.delta","delta":""}`,
						`{"type":"response.reasoning_summary_text.delta","delta":""}`,
						`{"type":"response.function_call_arguments.delta","delta":""}`,
						`{"type":"response.custom_tool_call_input.delta","delta":""}`,
						`{"type":"response.refusal.delta","delta":""}`,
						variant.event,
					}
				})
				status, body := f.request(transport)
				if !strings.Contains(body, "success-marker") || strings.Contains(body, "failed-preamble") || strings.Contains(body, "busy") || strings.Contains(body, "at capacity") {
					t.Fatalf("status=%d body=%s", status, body)
				}
				f.assertAttempts("a,b")
			})
		}
	}
}

func TestCapacityRoutingNeverReplaysOutput(t *testing.T) {
	outputs := []struct{ name, event, marker string }{
		{"text", `{"type":"response.output_text.delta","delta":"text-once"}`, "text-once"},
		{"reasoning", `{"type":"response.reasoning_text.delta","delta":"reason-once"}`, "reason-once"},
		{"reasoning_summary", `{"type":"response.reasoning_summary_text.delta","delta":"summary-once"}`, "summary-once"},
		{"tool_arguments", `{"type":"response.function_call_arguments.delta","delta":"tool-once"}`, "tool-once"},
		{"custom_tool", `{"type":"response.custom_tool_call_input.delta","delta":"custom-once"}`, "custom-once"},
		{"server_tool", `{"type":"response.output_item.added","item":{"id":"search-once","type":"web_search_call","status":"in_progress"}}`, "search-once"},
		{"unknown_event", `{"type":"response.future_operation","id":"future-once"}`, "future-once"},
		{"tool_item", `{"type":"response.output_item.added","output_index":0,"item":{"id":"tool-once","type":"function_call","call_id":"call-once","name":"write_file","arguments":"{}"}}`, "call-once"},
	}
	for _, output := range outputs {
		for _, transport := range []string{"sse", "ws"} {
			t.Run(output.name+"/"+transport, func(t *testing.T) {
				f := newCapacityRouteFixture(t, transport, 3, func(key string) (int, []string) {
					if key != "a" {
						return 200, capacityRouteSuccess()
					}
					return 200, []string{`{"type":"response.created","response":{"id":"accepted","output":[]}}`, output.event, capacityRouteError}
				})
				_, body := f.request(transport)
				if strings.Count(body, output.marker) != 1 || strings.Contains(body, "success-marker") || !strings.Contains(body, "server_is_overloaded") {
					t.Fatalf("output must occur once with terminal failure, no replay: %s", body)
				}
				f.assertAttempts("a")
			})
		}
	}
}

func TestCapacityRoutingExhaustion(t *testing.T) {
	for _, limit := range []int{1, 2, 3, 6} {
		for _, transport := range []string{"http", "sse", "ws"} {
			t.Run(fmt.Sprintf("limit=%d/%s", limit, transport), func(t *testing.T) {
				f := newCapacityRouteFixture(t, transport, limit, func(string) (int, []string) { return 200, []string{capacityRouteError} })
				status, body := f.request(transport)
				if !strings.Contains(body, "server_is_overloaded") || strings.Contains(body, "success-marker") {
					t.Fatalf("expected diagnosable capacity terminal, status=%d body=%s", status, body)
				}
				if transport != "ws" && status != 503 && status != 502 {
					t.Fatalf("exhaustion status=%d, want upstream failure", status)
				}
				want := "a"
				if limit >= 2 {
					want += ",b"
				}
				if limit >= 3 {
					want += ",c"
				}
				f.assertAttempts(want)
			})
		}
	}
}

func TestCapacityRoutingDoesNotReclassifyRequestOrAuthErrors(t *testing.T) {
	for _, status := range []int{400, 401} {
		for _, transport := range []string{"http", "sse", "ws"} {
			t.Run(fmt.Sprintf("status=%d/%s", status, transport), func(t *testing.T) {
				errorType, code := "invalid_request_error", "invalid_value"
				if status == 401 {
					errorType, code = "authentication_error", "invalid_api_key"
				}
				f := newCapacityRouteFixture(t, transport, 1, func(string) (int, []string) {
					return status, []string{fmt.Sprintf(`{"type":"error","status":%d,"error":{"type":%q,"code":%q,"message":"Invalid model: diagnostic mentions model is at capacity"}}`, status, errorType, code)}
				})
				gotStatus, body := f.request(transport, status == 401)
				if strings.Contains(body, "server_is_overloaded") || strings.Contains(body, "success-marker") {
					t.Fatalf("misclassified: %s", body)
				}
				if transport != "ws" && gotStatus != status {
					t.Fatalf("status=%d, want %d; body=%s", gotStatus, status, body)
				}
				if status == 400 && !strings.Contains(body, "invalid_value") {
					t.Fatalf("request fault lost: %s", body)
				}
				if transport == "ws" && status == 401 && gotStatus != websocket.CloseAbnormalClosure {
					t.Fatalf("ordinary credential error exposure changed: %d %s", gotStatus, body)
				}
				f.assertAttempts("a")
			})
		}
	}
}

func TestCapacityRoutingCancellationStopsFailover(t *testing.T) {
	for _, transport := range []string{"http", "sse", "ws"} {
		t.Run(transport, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			var once sync.Once
			f := newCapacityRouteFixture(t, transport, 3, func(key string) (int, []string) {
				if key == "b" {
					once.Do(func() { close(started) })
					<-release
				}
				return 200, []string{capacityRouteError}
			})
			cancel := func() {}
			clientDone := make(chan error, 1)
			if transport == "ws" {
				conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(f.url, "http"), nil)
				if response != nil {
					_ = response.Body.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				cancel = func() { _ = conn.Close() }
				if err = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[]}`, f.model))); err != nil {
					t.Fatal(err)
				}
			} else {
				ctx, cancelRequest := context.WithCancel(context.Background())
				defer cancelRequest()
				cancel = cancelRequest
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, strings.NewReader(fmt.Sprintf(`{"model":%q,"input":[],"stream":%t}`, f.model, transport == "sse")))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				go func() {
					response, errRequest := http.DefaultClient.Do(req)
					if response != nil {
						_ = response.Body.Close()
					}
					clientDone <- errRequest
				}()
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("second candidate never admitted")
			}
			cancel()
			if transport != "ws" {
				select {
				case err := <-clientDone:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancel terminal=%v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("client did not cancel")
				}
			}
			// Wait for the real handler to exit while B is still held. No C, retry
			// round, or provider side effect may be accepted after cancellation.
			f.assertAttempts("a,b")
		})
	}
}

func TestCapacityRoutingCommittedResponseDoesNotReplay(t *testing.T) {
	for _, transport := range []string{"http", "sse", "ws"} {
		t.Run(transport, func(t *testing.T) {
			f := newCapacityRouteFixture(t, transport, 3, func(string) (int, []string) {
				return 200, append(capacityRouteSuccess(), capacityRouteError)
			})
			_, body := f.request(transport)
			if strings.Count(body, "success-marker") != 1 {
				t.Fatalf("committed result lost/duplicated: %s", body)
			}
			f.assertAttempts("a")
		})
	}
}

func TestCapacityRoutingBootstrapBudgetDoesNotReplay(t *testing.T) {
	for _, transport := range []string{"sse", "ws"} {
		t.Run(transport, func(t *testing.T) {
			f := newCapacityRouteFixture(t, transport, 3, func(key string) (int, []string) {
				if key != "a" {
					return 200, capacityRouteSuccess()
				}
				events := []string{`{"type":"response.created","response":{"id":"budget-committed","output":[]}}`}
				for i := 0; i < 60; i++ {
					events = append(events, `{"type":"rate_limits.updated","rate_limits":[]}`)
				}
				return 200, append(events, capacityRouteError)
			})
			_, body := f.request(transport)
			if !strings.Contains(body, "budget-committed") || !strings.Contains(body, "server_is_overloaded") || strings.Contains(body, "success-marker") {
				t.Fatalf("budget terminal missing or replayed: %s", body)
			}
			f.assertAttempts("a")
		})
	}
}

func TestCapacityRoutingRequestDeadlineStopsFailover(t *testing.T) {
	for _, transport := range []string{"http", "sse"} {
		t.Run(transport, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			var once sync.Once
			f := newCapacityRouteFixture(t, transport, 3, func(key string) (int, []string) {
				if key == "b" {
					once.Do(func() { close(started) })
					<-release
				}
				return 200, []string{capacityRouteError}
			})
			// This is the caller's total request budget, not a new inference
			// connection timeout. The provider is held by a channel, not a sleep.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, strings.NewReader(fmt.Sprintf(`{"model":%q,"input":[],"stream":%t}`, f.model, transport == "sse")))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(req)
			if response != nil {
				_ = response.Body.Close()
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("deadline terminal=%v", err)
			}
			select {
			case <-started:
			default:
				t.Fatal("deadline expired before failover was exercised")
			}
			f.assertAttempts("a,b")
		})
	}
}

func TestCapacityRoutingWebsocketStatusFailureAfterOutput(t *testing.T) {
	for _, status := range []int{429, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newCapacityRouteFixture(t, "ws", 3, func(key string) (int, []string) {
				if key != "a" {
					return 200, capacityRouteSuccess()
				}
				return 200, []string{
					`{"type":"response.created","response":{"id":"accepted","output":[]}}`,
					`{"type":"response.output_text.delta","delta":"text-once"}`,
					strings.Replace(capacityRouteError, `"type":"error",`, fmt.Sprintf(`"type":"error","status":%d,`, status), 1),
				}
			})
			_, body := f.request("ws")
			if strings.Count(body, "text-once") != 1 || !strings.Contains(body, "server_is_overloaded") || strings.Contains(body, "success-marker") {
				t.Fatalf("status error lost output or replayed: %s", body)
			}
			f.assertAttempts("a")
		})
	}
}

func TestCapacityRoutingPlainTurnLimitKeepsQuotaTerminalSilent(t *testing.T) {
	f := newCapacityRouteFixture(t, "ws", 1, func(string) (int, []string) {
		return 200, []string{`{"type":"error","status":429,"error":{"type":"rate_limit_error","code":"turn_rate_limit_exceeded","message":"Too many requests. Turn limit exceeded; wait before sending another request."}}`}
	})
	status, body := f.request("ws", true)
	if status != websocket.CloseAbnormalClosure || body != "" {
		t.Fatalf("ordinary turn limit must keep the existing silent quota terminal, got status=%d body=%s", status, body)
	}
	f.assertAttempts("a")
}

func TestCapacityRoutingTurnLimitWithoutMessageKeepsQuotaTerminalSilent(t *testing.T) {
	f := newCapacityRouteFixture(t, "ws", 1, func(string) (int, []string) {
		return 200, []string{`{"type":"error","status":429,"error":{"code":"turn_rate_limit_exceeded"}}`}
	})
	status, body := f.request("ws", true)
	if status != websocket.CloseAbnormalClosure || body != "" {
		t.Fatalf("code-only turn limit must not imply capacity exposure, got status=%d body=%s", status, body)
	}
	f.assertAttempts("a")
}

func TestCapacityRoutingExplicitTerminalCapacitySignals(t *testing.T) {
	for _, tc := range []struct{ name, event, marker string }{
		{"turn_capacity_message", `{"type":"error","status":429,"error":{"type":"rate_limit_error","code":"turn_rate_limit_exceeded","message":"Codex is at capacity, please try again later"}}`, "Codex is at capacity"},
		{"unavailable_type", `{"type":"error","error":{"type":"service_unavailable_error","message":"busy"}}`, "service_unavailable_error"},
		{"overloaded_code", `{"type":"error","error":{"code":"server_is_overloaded","message":"busy"}}`, "server_is_overloaded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCapacityRouteFixture(t, "ws", 1, func(string) (int, []string) { return 200, []string{tc.event} })
			_, body := f.request("ws")
			if !strings.Contains(body, tc.marker) {
				t.Fatalf("explicit capacity terminal lost: %s", body)
			}
			f.assertAttempts("a")
		})
	}
}

func TestCapacityRoutingUsageQuotaWithTurnCodeKeepsSilent(t *testing.T) {
	f := newCapacityRouteFixture(t, "ws", 1, func(string) (int, []string) {
		return 200, []string{`{"type":"error","status":429,"error":{"type":"usage_limit_reached","code":"turn_rate_limit_exceeded","message":"Codex is at capacity; your usage quota is exhausted","resets_in_seconds":3600}}`}
	})
	status, body := f.request("ws", true)
	if status != websocket.CloseAbnormalClosure || body != "" {
		t.Fatalf("explicit usage quota must take precedence over capacity wording, got status=%d body=%s", status, body)
	}
	f.assertAttempts("a")
}
