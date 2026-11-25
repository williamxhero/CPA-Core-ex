package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestUpstreamBalanceRejectionPausesCredentialAcrossRestart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"quota-code", 429, `{"error":{"code":"insufficient_user_quota","message":"Request rejected"}}`},
		{"balance-code", 402, `{"error":{"code":"INSUFFICIENT_BALANCE","message":"Request rejected"}}`},
		{"chinese-message", 403, `{"error":{"message":"预扣费额度失败，所余资金不足"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const a, sibling, rotated, other = "BALANCE-A-CANARY", "BALANCE-SIBLING-CANARY", "BALANCE-ROTATED-CANARY", "BALANCE-OTHER-CANARY"
			var mu sync.Mutex
			sends := map[string]int{}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				mu.Lock()
				sends[key]++
				first := sends[key] == 1
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if key == a && first {
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.body)
					return
				}
				fmt.Fprint(w, `{"id":"ok","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
			}))
			t.Cleanup(upstream.Close)
			count := func(key string) int {
				mu.Lock()
				defer mu.Unlock()
				return sends[key]
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			cfg := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys:
  openai-compatibility:
    - name: balance-pool
      base-url: %q
      models: [{name: balance-primary}, {name: balance-secondary}]
      keys: [{api-key: %s}, {api-key: %s}]
    - name: unaffected-pool
      base-url: %q
      models: [{name: balance-other}]
      keys: [{api-key: %s}]
`, filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL+"/v1", a, sibling, upstream.URL+"/v1", other)
			if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			open := func(preferred string) *inventoryHarness {
				f := newInventoryHarness(t, dir)
				f.manager.SetConfig(f.server.cfg)
				f.manager.SetRoundTripperProvider(scopedQuotaTransport{upstream.Client().Transport})
				f.manager.SetSelector(&gatePreferASelector{key: preferred})
				for _, auth := range f.manager.List() {
					f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(auth.Provider, f.server.cfg))
					models := []*registry.ModelInfo{{ID: "balance-primary"}, {ID: "balance-secondary"}}
					if auth.Attributes["api_key"] == other {
						models = []*registry.ModelInfo{{ID: "balance-other"}}
					}
					registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, models)
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
				}
				h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
				f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
				return f
			}
			infer := func(f *inventoryHarness, model string, wantOK bool) {
				t.Helper()
				w := balanceInference(f, model)
				if wantOK && (w.Code != 200 || !strings.Contains(w.Body.String(), `"content":"ok"`)) {
					t.Fatalf("%s status=%d body=%s", model, w.Code, w.Body)
				}
			}
			f := open(a)
			infer(f, "balance-primary", false)
			if got := count(a); got != 1 {
				t.Fatalf("first inference sent %d times on rejecting credential; want 1", got)
			}
			initial := readBalanceGates(t, f)
			if len(initial.Gates) != 1 {
				t.Fatalf("after real upstream denial: got %d durable pauses, want 1", len(initial.Gates))
			}
			gate := initial.Gates[0]
			if gate.Model != "" || gate.Reason != "upstream_balance_exhausted" || gate.Owner != "core.upstream-balance.v1" || gate.Applicability != "current" || len(gate.Targets) != 1 {
				t.Fatalf("wrong credential pause: %+v", gate)
			}
			expectBlocked := func(f *inventoryHarness) {
				t.Helper()
				before := count(sibling)
				infer(f, "balance-primary", true)
				infer(f, "balance-secondary", true)
				if count(a) != 1 || count(sibling) != before+2 {
					t.Fatalf("wanted zero more sends on paused credential and two on sibling; got total A=%d, sibling delta=%d", count(a), count(sibling)-before)
				}
			}
			expectBlocked(f)
			infer(f, "balance-other", true)
			if count(other) != 1 {
				t.Fatal("other provider did not dispatch")
			}
			f.close()
			f = open(a)
			restarted := readBalanceGates(t, f)
			if len(restarted.Gates) != 1 || restarted.Revision != initial.Revision || restarted.Gates[0].EvidenceID != gate.EvidenceID {
				t.Fatalf("restart lost original pause: %+v", restarted)
			}
			expectBlocked(f)

			f.close()
			persisted, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(strings.Replace(string(persisted), a, rotated, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			f = open(rotated)
			drifted := readBalanceGates(t, f)
			if len(drifted.Gates) != 1 || drifted.Gates[0].Applicability != "reconciliation_required" {
				t.Fatalf("key replacement did not invalidate former pause: %+v", drifted)
			}
			infer(f, "balance-secondary", true)
			if count(rotated) != 1 || count(a) != 1 {
				t.Fatal("credential replacement did not restore dispatch")
			}
		})
	}
}

func TestCodexBalanceResponsePausesWholeCredentialWithModelLevelCooling(t *testing.T) {
	var sends atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer CODEX-BALANCE-CANARY" {
			t.Error("unexpected inference destination or credential")
			w.WriteHeader(500)
			return
		}
		sends.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(402)
		fmt.Fprint(w, `{"error":{"code":"insufficient_balance","message":"account rejected"}}`)
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	cfg := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
codex: {model-level-cooling: true}
api-keys:
  codex:
    - name: balance-codex
      base-url: %q
      models: [{name: gpt-5.4}, {name: gpt-5.4-mini}]
      keys: [{api-key: CODEX-BALANCE-CANARY}]
`, filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL+"/v1")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	f.manager.SetRoundTripperProvider(scopedQuotaTransport{upstream.Client().Transport})
	f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
	for _, a := range f.manager.List() {
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "gpt-5.4"}, {ID: "gpt-5.4-mini"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	var scoped atomic.Bool
	f.manager.SetResultPolicy(coreauth.ResultPolicyFunc(func(_ context.Context, result coreauth.Result) coreauth.Result {
		if result.Error != nil && result.Error.HTTPStatus == 402 {
			scoped.Store(result.CredentialScope)
		}
		return result
	}))
	h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/responses", h.Responses)
	infer := func(model string) int {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"input":[]}`, model)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		return w.Code
	}
	if status := infer("gpt-5.4"); status != 402 || sends.Load() != 1 || !scoped.Load() {
		t.Fatalf("Codex balance denial not credential scoped: status=%d sends=%d scoped=%t", status, sends.Load(), scoped.Load())
	}
	if state := readBalanceGates(t, f); len(state.Gates) != 1 || state.Gates[0].Model != "" || state.Gates[0].Reason != "upstream_balance_exhausted" {
		t.Fatalf("Codex balance denial did not record a whole-credential pause: %+v", state)
	}
	if status := infer("gpt-5.4-mini"); status < 400 || sends.Load() != 1 {
		t.Fatalf("paused Codex credential sent a sibling model: status=%d sends=%d", status, sends.Load())
	}
}

func TestOrdinaryInferenceResultsDoNotPauseForBalance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"forbidden-key", 403, `{"error":{"code":"invalid_api_key","message":"invalid api key"}}`},
		{"transient-rate-limit", 429, `{"error":{"code":"rate_limit_exceeded","message":"temporarily unavailable"}}`},
		{"bad-gateway", 502, `{"error":{"message":"bad gateway"}}`},
		{"network-eof", 0, ""},
		{"success-text", 200, `{"id":"ok","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"余额不足"},"finish_reason":"stop"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(1)
				if tc.status == 0 {
					// Drop the transport without any upstream HTTP response.
					panic(http.ErrAbortHandler)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "600")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			t.Cleanup(upstream.Close)
			dir := t.TempDir()
			cfg := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys:
  openai-compatibility:
    - name: balance-negative
      base-url: %q
      models: [{name: balance-negative}]
      keys: [{api-key: NEGATIVE-CANARY}]
`, filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL+"/v1")
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0600); err != nil {
				t.Fatal(err)
			}
			f := newInventoryHarness(t, dir)
			f.manager.SetConfig(f.server.cfg)
			f.manager.SetRetryConfig(0, 0, 1)
			f.manager.SetRoundTripperProvider(scopedQuotaTransport{upstream.Client().Transport})
			for _, a := range f.manager.List() {
				f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
				registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "balance-negative"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
			}
			h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
			w := balanceInference(f, "balance-negative")
			if sent.Load() == 0 || (w.Code == 200) != (tc.status == 200) || (w.Code == 200 && !strings.Contains(w.Body.String(), "余额不足")) {
				t.Fatalf("fixture did not exercise upstream outcome: sends=%d status=%d body=%s", sent.Load(), w.Code, w.Body)
			}
			if state := readBalanceGates(t, f); len(state.Gates) != 0 || state.Revision != 0 {
				t.Fatalf("ordinary inference unexpectedly published a pause: %+v", state)
			}
		})
	}
}

func balanceInference(f *inventoryHarness, model string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"synthetic"}]}`, model)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	return w
}

func readBalanceGates(t *testing.T, f *inventoryHarness) resource.GateState {
	t.Helper()
	raw := f.request("inference-gates", 200)
	if strings.Contains(string(raw), "CANARY") || strings.Contains(string(raw), "预扣费额度失败") {
		t.Fatal("gate read exposed upstream credential or body")
	}
	var state resource.GateState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return state
}
