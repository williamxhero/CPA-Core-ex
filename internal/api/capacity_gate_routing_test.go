package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/tidwall/gjson"
)

// The exact known native capacity event used by capacity73, not a generic500.
const combinedCapacityError = `{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","headers":{"x-retry-metadata":"NO_MORE_RETRY"},"message":"Our servers are currently overloaded. Please try again later."}}`
const combinedCapacitySuccess = `{"type":"response.completed","response":{"id":"healthy","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"healthy-B"}]}]}}`

// Reuse the real inventory/gate harness. Only the external provider boundary is
// controlled; selection, capacity classification, admission and translation are real.
type capacityGateReply struct {
	status int
	body   string
}

type capacityGateRoute struct {
	inventory *inventoryHarness
	url       string
	sources   map[string]map[string]any
	finished  chan struct{}
	mu        sync.Mutex
	attempts  []string
}

func newCapacityGateRoute(t *testing.T, transport string, reply func(string, func(string))) *capacityGateRoute {
	t.Helper()
	f := &capacityGateRoute{sources: map[string]map[string]any{}, finished: make(chan struct{}, 1)}
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
			defer conn.Close()
			_, payload, err = conn.ReadMessage()
		} else {
			payload, err = io.ReadAll(r.Body)
		}
		emit := func(event string) {
			if conn != nil {
				if err := conn.WriteMessage(websocket.TextMessage, []byte(event)); err != nil {
					return
				}
			} else {
				// Use the canonical native event/data frame. Data-only fixtures may
				// intentionally stay pending in the downstream SSE framer until the next
				// event, so they cannot establish an observed-output pause barrier.
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", gjson.Get(event, "type").String(), event)
				w.(http.Flusher).Flush()
			}
		}
		if conn == nil {
			w.Header().Set("Content-Type", "text/event-stream")
		}
		for {
			if err != nil {
				return
			}
			if gjson.GetBytes(payload, "model").String() != "capacity-gate-model" {
				t.Error("actual upstream model changed")
				return
			}
			f.mu.Lock()
			f.attempts = append(f.attempts, key)
			f.mu.Unlock()
			reply(key, emit)
			if conn == nil {
				return
			}
			_, payload, err = conn.ReadMessage()
		}
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\nupstream: {codex: {stream-bootstrap-buffering: true}}\napi-keys:\n  codex:\n    - name: capacity-gate\n      base-url: %q\n      keys:\n        - {api-key: A, priority: 30, websockets: %t}\n        - {api-key: P, priority: 20, websockets: %t}\n        - {api-key: B, priority: 10, websockets: %t}\n", filepath.ToSlash(authDir), upstream.URL, transport == "ws", transport == "ws", transport == "ws")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	inventory := newInventoryHarness(t, dir)
	f.inventory = inventory
	inventory.manager.SetConfig(inventory.server.cfg)
	inventory.manager.SetSelector(&coreauth.FillFirstSelector{})
	inventory.manager.SetRetryConfig(0, 0, 3)
	inventory.manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(inventory.server.cfg))
	t.Cleanup(func() { inventory.manager.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID) })
	var view struct {
		Sources []map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(inventory.request("credential-quota/sources", 200), &view); err != nil {
		t.Fatal(err)
	}
	for _, a := range inventory.manager.List() {
		if a.Disabled {
			t.Fatal("manual disabled is not an independent gate")
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "capacity-gate-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
		for _, source := range view.Sources {
			if source["auth_index"] == a.Index {
				f.sources[a.Attributes["api_key"]] = source
			}
		}
	}
	if len(f.sources) != 3 {
		t.Fatal("three real configured sources not bound")
	}
	h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&inventory.server.cfg.SDKConfig, inventory.manager))
	inventory.server.engine.POST("/v1/responses", func(c *gin.Context) { defer func() { f.finished <- struct{}{} }(); h.Responses(c) })
	inventory.server.engine.GET("/v1/responses", func(c *gin.Context) { defer func() { f.finished <- struct{}{} }(); h.ResponsesWebsocket(c) })
	downstream := httptest.NewServer(inventory.server.engine)
	t.Cleanup(downstream.Close)
	f.url = downstream.URL + "/v1/responses"
	return f
}
func (f *capacityGateRoute) pause(t *testing.T, key string, revision int) {
	t.Helper()
	id := "ee33f731-6518-4f67-8b33-cd987d4f3411"
	if key == "A" {
		id = "ee33f731-6518-4f67-8b33-cd987d4f3412"
	}
	raw := gatePost(t, f.inventory, gateOp(f.sources[key], revision, id, "ticket94/"+key, "pause"), 200)
	var result resource.GateResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Durable || !result.Applied || result.AppliedRevision != uint64(revision+1) || result.DurableRevision != uint64(revision+1) {
		t.Fatalf("not durable shared-admission ACK: %s", raw)
	}
}
func (f *capacityGateRoute) request(t *testing.T, transport string, observed func(string)) (int, string) {
	t.Helper()
	if transport == "ws" {
		c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(f.url, "http"), nil)
		if resp != nil {
			resp.Body.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"capacity-gate-model","input":[]}`)); err != nil {
			t.Fatal(err)
		}
		var body strings.Builder
		for {
			_, frame, err := c.ReadMessage()
			if err != nil {
				t.Fatalf("actual WS read: %v body=%s", err, body.String())
			}
			body.Write(frame)
			body.WriteByte('\n')
			if observed != nil {
				observed(string(frame))
			}
			switch gjson.GetBytes(frame, "type").String() {
			case "response.completed", "response.failed", "error":
				return 101, body.String()
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", f.url, strings.NewReader(fmt.Sprintf(`{"model":"capacity-gate-model","input":[],"stream":%t}`, transport == "sse")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body bytes.Buffer
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		body.WriteString(scanner.Text())
		body.WriteByte('\n')
		if observed != nil {
			observed(scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body.String()
}
func (f *capacityGateRoute) assertAttempts(t *testing.T, want string) {
	t.Helper()
	select {
	case <-f.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("actual route did not finish")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if got := strings.Join(f.attempts, ","); got != want {
		t.Fatalf("actual upstream attempts=%s want=%s", got, want)
	}
	var state resource.GateState
	if err := json.Unmarshal(f.inventory.request("inference-gates", 200), &state); err != nil {
		t.Fatal(err)
	}
	if !state.Ready || len(state.Gates) != int(state.Revision) {
		t.Fatal("independent pauses lost after capacity/success")
	}
	for _, a := range f.inventory.manager.List() {
		if a.Disabled {
			t.Fatal("gate changed manual intent")
		}
	}
	t.Logf("actual upstream attempts=%s; applied gate revision=%d; manual intent unchanged", want, state.Revision)
}

func TestCapacityGateBeforeOutput(t *testing.T) {
	for _, transport := range []string{"http", "sse", "ws"} {
		t.Run(transport, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once, enteredOnce sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			f := newCapacityGateRoute(t, transport, func(key string, emit func(string)) {
				if key == "A" {
					enteredOnce.Do(func() { close(entered) })
					<-release
					emit(`{"type":"response.created","response":{"id":"hidden-capacity-preamble","output":[]}}`)
					emit(combinedCapacityError)
					return
				}
				emit(combinedCapacitySuccess)
			})
			f.pause(t, "P", 0)
			done := make(chan capacityGateReply, 1)
			go func() { status, body := f.request(t, transport, nil); done <- capacityGateReply{status, body} }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("A actual send missing")
			}
			f.pause(t, "A", 1)
			unblock()
			var result capacityGateReply
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("capacity failover did not finish")
			}
			body := result.body
			expectedStatus := 200
			if transport == "ws" {
				expectedStatus = 101
			}
			if result.status != expectedStatus {
				t.Fatalf("capacity status=%d want=%d body=%s", result.status, expectedStatus, body)
			}
			if strings.Count(body, "healthy-B") != 1 || strings.Contains(body, "hidden-capacity-preamble") || strings.Contains(body, "server_is_overloaded") {
				t.Fatalf("capacity not transparently routed: %s", body)
			}
			f.assertAttempts(t, "A,B")
		})
	}
}

func TestCapacityGateAfterActualOutputNeverReplays(t *testing.T) {
	for _, output := range []struct{ name, event, marker string }{
		{"text", `{"type":"response.output_text.delta","delta":"text-once"}`, "text-once"},
		{"tool", `{"type":"response.function_call_arguments.delta","delta":"tool-once"}`, "tool-once"},
	} {
		for _, transport := range []string{"sse", "ws"} {
			t.Run(output.name+"/"+transport, func(t *testing.T) {
				observed, release := make(chan struct{}), make(chan struct{})
				var outputOnce, releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				defer unblock()
				f := newCapacityGateRoute(t, transport, func(key string, emit func(string)) {
					if key != "A" {
						emit(combinedCapacitySuccess)
						return
					}
					emit(`{"type":"response.created","response":{"id":"accepted-A","output":[]}}`)
					emit(output.event)
					<-release
					emit(combinedCapacityError)
				})
				f.pause(t, "P", 0)
				done := make(chan capacityGateReply, 1)
				go func() {
					status, body := f.request(t, transport, func(frame string) {
						if strings.Contains(frame, output.marker) {
							outputOnce.Do(func() { close(observed) })
						}
					})
					done <- capacityGateReply{status, body}
				}()
				// Observe ACTUAL downstream content/tool output before the new A pause ACK,
				// not merely the provider's attempt to write an event into a bootstrap buffer.
				select {
				case <-observed:
				case <-time.After(5 * time.Second):
					t.Fatal("actual downstream output not observed")
				}
				f.pause(t, "A", 1)
				unblock()
				var result capacityGateReply
				select {
				case result = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("admitted output did not drain terminal capacity")
				}
				expectedStatus := 200
				if transport == "ws" {
					expectedStatus = 101
				}
				if result.status != expectedStatus || strings.Count(result.body, output.marker) != 1 || strings.Contains(result.body, "healthy-B") || !strings.Contains(result.body, "server_is_overloaded") {
					t.Fatalf("actual output replayed/lost terminal capacity: status=%d body=%s", result.status, result.body)
				}
				f.assertAttempts(t, "A")
			})
		}
	}
}

func TestCapacityGateCommittedHTTPNeverReplays(t *testing.T) {
	for _, output := range []struct{ name, event, marker string }{
		{"text", `{"type":"response.completed","response":{"id":"accepted-A","object":"response","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"committed-text-once"}]}]}}`, "committed-text-once"},
		{"tool", `{"type":"response.completed","response":{"id":"accepted-A","object":"response","status":"completed","output":[{"id":"function-item","type":"function_call","call_id":"tool-call-once","name":"write_file","arguments":"{}"}]}}`, "tool-call-once"},
	} {
		t.Run(output.name, func(t *testing.T) {
			f := newCapacityGateRoute(t, "http", func(key string, emit func(string)) {
				if key == "A" {
					emit(output.event)
					emit(combinedCapacityError)
					return
				}
				emit(combinedCapacitySuccess)
			})
			f.pause(t, "P", 0)
			status, body := f.request(t, "http", nil)
			if status != 200 || strings.Count(body, output.marker) != 1 || strings.Contains(body, "healthy-B") {
				t.Fatalf("committed HTTP output replayed: status=%d body=%s", status, body)
			}
			f.assertAttempts(t, "A")
		})
	}
}
