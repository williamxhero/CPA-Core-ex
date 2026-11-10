package api

import (
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func quotaStopPost(t *testing.T, f *inventoryHarness, source map[string]any, enabled bool, generation int, want int) {
	t.Helper()
	body := map[string]any{"version": 1, "scope": source["scope"], "targets": source["targets"], "auth_index": source["auth_index"], "sourceVersion": source["sourceVersion"], "subject": "credential", "owner": "cpa-manager.credential-policy.v1/test", "generation": generation, "enabled": enabled}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v8/management/inference-gates/quota-auto-stop", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("quota auto-stop status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}

func TestQuotaAutoStopActualTransportSendsExhaustedCredentialOnce(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			var failedSends, healthySends atomic.Int32
			var exhaustedKey string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if r.Header.Get("Authorization") == "Bearer "+exhaustedKey {
					failedSends.Add(1)
					if stream {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"type\":\"usage_limit_reached\",\"status_code\":429,\"message\":\"The usage limit has been reached\"}}}\n\n")
					} else {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(429)
						fmt.Fprint(w, `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached"}}`)
					}
					return
				}
				healthySends.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"object\":\"response\",\"model\":\"gate-test-model\",\"status\":\"completed\",\"output\":[]}}\n\n")
			}))
			defer upstream.Close()
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "auth"), 0700); err != nil {
				t.Fatal(err)
			}
			cfg := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex:\n    - name: first\n      base-url: %q\n      keys: [{api-key: synthetic-A}]\n    - name: second\n      base-url: %q\n      keys: [{api-key: synthetic-B}]\n", filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL, upstream.URL)
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			f := newInventoryHarness(t, dir)
			f.server.cfg.DisableCooling = true
			f.manager.SetConfig(f.server.cfg)
			f.manager.SetRetryConfig(10, time.Second, 0)
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
			for _, a := range f.manager.List() {
				registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "gate-test-model"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
			}
			source := gateSource(t, f)
			for _, a := range f.manager.List() {
				if a.Index == source["auth_index"] {
					exhaustedKey = a.Attributes["api_key"]
				}
			}
			f.manager.SetSelector(&gatePreferASelector{key: exhaustedKey})
			quotaStopPost(t, f, source, true, 1, 200)
			h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.POST("/v1/responses", h.Responses)
			for i := 0; i < 3; i++ {
				w := httptest.NewRecorder()
				r := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":"gate-test-model","input":[],"stream":%t}`, stream)))
				r.Header.Set("Content-Type", "application/json")
				f.server.engine.ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("healthy fallback failed status=%d body=%s", w.Code, w.Body.String())
				}
			}
			if failedSends.Load() != 1 || healthySends.Load() != 3 {
				t.Fatalf("upstream sends exhausted=%d healthy=%d", failedSends.Load(), healthySends.Load())
			}
		})
	}
}

func TestQuotaAutoStopFirstFailureIndependentOfCooling(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		for _, enabled := range []bool{true, false} {
			t.Run(fmt.Sprintf("disable_cooling=%t/auto_stop=%t", disabled, enabled), func(t *testing.T) {
				f := newInventoryHarness(t, t.TempDir())
				source := gateSource(t, f)
				f.server.cfg.DisableCooling = disabled
				f.manager.SetConfig(f.server.cfg)
				quotaStopPost(t, f, source, enabled, 1, 200)
				var selected *coreauth.Auth
				for _, a := range f.manager.List() {
					if a.Index == source["auth_index"] {
						selected = a
					}
				}
				if selected == nil {
					t.Fatal("missing current runtime credential")
				}
				retry := 542462 * time.Second
				failure := coreauth.Result{AuthID: selected.ID, Provider: selected.Provider, Model: "gpt-6.1-sol", CredentialScope: true, RetryAfter: &retry, Error: &coreauth.Error{HTTPStatus: 429, Message: `{"error":{"type":"usage_limit_reached","plan_type":"prolite","limit_window_minutes":10080,"resets_in_seconds":542462}}`}}
				// A transient 429 must not acquire an automatic quota pause.
				transient := failure
				transient.CredentialScope = false
				transient.Error = &coreauth.Error{HTTPStatus: 429, Code: "transient_rate_limit", Message: `{"error":{"type":"rate_limit_error"}}`}
				f.manager.MarkResult(context.Background(), transient)
				var before struct {
					Gates []map[string]any `json:"gates"`
				}
				json.Unmarshal(f.request("inference-gates", 200), &before)
				if len(before.Gates) != 0 {
					t.Fatal("transient rate limit acquired a quota pause")
				}
				f.manager.MarkResult(context.Background(), failure)
				var state struct {
					Gates    []map[string]any `json:"gates"`
					Revision uint64           `json:"gateRevision"`
				}
				json.Unmarshal(f.request("inference-gates", 200), &state)
				if (len(state.Gates) == 1) != enabled {
					t.Fatalf("first quota failure did not immediately respect auto-stop: %+v", state)
				}
				if enabled {
					if state.Gates[0]["reason"] != "quota_windows_exhausted" {
						t.Fatalf("wrong quota pause: %+v", state)
					}
					f.manager.MarkResult(context.Background(), failure)
					var duplicate struct {
						Revision uint64 `json:"gateRevision"`
					}
					json.Unmarshal(f.request("inference-gates", 200), &duplicate)
					if duplicate.Revision != state.Revision {
						t.Fatal("duplicate quota response wrote a second pause")
					}
				}
			})
		}
	}
}
