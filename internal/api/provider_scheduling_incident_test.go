package api

import (
	"crypto/sha256"
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

	"github.com/MoeForge/moego/ojson"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestProviderSchedulingCPA60IncidentReplay(t *testing.T) {
	const model = "gpt-6.2-sol"
	var a, b, c, quotaReads atomic.Int32
	resets := time.Now().UTC().Add(135 * time.Hour).Unix()
	codex, network := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backend-api/wham/usage" {
			quotaReads.Add(1)
			if r.Header.Get("Authorization") != "Bearer replay-A-CANARY" || r.Header.Get("Chatgpt-Account-Id") != "account-A-CANARY" {
				t.Error("quota confirmation did not use the rejected account")
			}
			w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
			fmt.Fprintf(w, `{"rate_limit":{"allowed":false,"limit_reached":true,"primary_window":{"used_percent":25,"reset_at":%d,"limit_window_seconds":18000},"secondary_window":{"used_percent":100,"reset_at":%d,"limit_window_seconds":604800}},"additional_rate_limits":[],"credits":{"has_credits":false,"unlimited":false,"balance":"0"}}`, resets, resets)
			return
		}
		if r.URL.Path != "/backend-api/codex/responses" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") == "Bearer replay-A-CANARY" {
			a.Add(1)
		} else {
			b.Add(1)
		}
		w.Header().Set("X-Codex-Active-Limit", "codex")
		w.Header().Set("X-Codex-Secondary-Used-Percent", "100")
		w.Header().Set("X-Codex-Secondary-Window-Minutes", "10080")
		w.Header().Set("X-Codex-Secondary-Reset-At", fmt.Sprint(resets))
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprintf(w, `{"error":{"type":"usage_limit_reached","limit_window_minutes":10080,"resets_at":%d,"message":"RAW-UPSTREAM-CANARY"}}`, resets)
	}))
	paid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		c.Add(1)
		raw, _ := io.ReadAll(r.Body)
		if got := ojson.GetBytesNoCopy(raw, "model").String(); got != model {
			t.Errorf("paid route received model %q", got)
		}
		schedulingReply(w, "paid-replay")
	}))
	t.Cleanup(paid.Close)

	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ key, flags string }{
		{"A", `,"priority":100`},
		{"B", `,"expired":"2000-01-01T00:00:00Z"`},
	} {
		path := filepath.Join(authDir, "replay-"+row.key+"-CANARY.json")
		body := fmt.Sprintf(`{"type":"codex","access_token":"replay-%s-CANARY","account_id":"account-%s-CANARY","email":"fixture-%s@example.invalid"%s}`, row.key, row.key, row.key, row.flags)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys:
  openai-compatibility:
    - name: internal-paid-label-CANARY
      base-url: %q
      keys: [{api-key: replay-C-CANARY}]
      models: [{name: gpt-6.2-sol, alias: gpt-6.2-sol}]
`, filepath.ToSlash(authDir), paid.URL+"/v1")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(base), 0600); err != nil {
		t.Fatal(err)
	}

	f := newInventoryHarness(t, dir)
	rt := codex.Client().Transport.(*http.Transport).Clone()
	rt.Proxy = nil
	rt.DialContext = network.DialContext
	t.Cleanup(rt.CloseIdleConnections)
	f.manager.SetRoundTripperProvider(cpa60ReplayTransport{codex: rt})
	f.handler.SetQuotaNetwork(network)
	f.manager.SetRetryConfig(9, time.Second, 0)
	ids := map[string]string{}
	var paidAuth *coreauth.Auth
	for _, r := range f.manager.List() {
		label := "C"
		if r.Provider == "codex" {
			label = "A"
			if r.Metadata["access_token"] == "replay-B-CANARY" {
				label = "B"
				if exp, ok := r.AccessTokenExpirationTime(); !ok || exp.After(time.Now()) {
					t.Fatalf("missing expired credential fixture: %v %t", exp, ok)
				}
			} else {
				r.Attributes["priority"] = "100"
				if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), r); err != nil {
					t.Fatal(err)
				}
			}
		} else {
			paidAuth = r
		}
		if r.ResourceIdentity == nil || len(r.ResourceIdentity.Targets) == 0 {
			t.Fatalf("missing binding for route %s", label)
		}
		ids[label] = r.ResourceIdentity.Targets[0].ResourceID
		registry.GetGlobalRegistry().RegisterClient(r.ID, r.Provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(r.ID) })
	}
	if len(ids) != 3 || paidAuth == nil {
		t.Fatalf("incomplete replay inventory: %d", len(ids))
	}
	policy := fmt.Sprintf(`
routing:
  upstream-error-retry-limit: -1
  provider-scheduling:
    mode: enforce
    models: [gpt-6.2-sol]
    resources:
      %q: {funding: subscription}
      %q: {funding: subscription}
      %q: {funding: prepaid}
    caller-funding:
      %q: [subscription]
`, ids["A"], ids["B"], ids["C"], schedulingCallerIDForTest("limited"))
	cfg, err := config.ParseConfigBytes([]byte(base + policy))
	if err != nil {
		t.Fatal(err)
	}
	f.manager.SetConfig(cfg)
	f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
	f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(paidAuth.Provider, cfg))
	access := sdkaccess.NewManager()
	access.SetProviders([]sdkaccess.Provider{schedulingHTTPAccess{}})
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/chat/completions", AuthMiddleware(access), h.ChatCompletions)
	call := func(caller string, status int) *httptest.ResponseRecorder {
		t.Helper()
		raw := fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"REQUEST-BODY-CANARY"}]}`, model)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+caller)
		req.Header.Set("X-Request-ID", "client-request-id-CANARY")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("%s: status=%d want=%d body=%s", caller, w.Code, status, w.Body.String())
		}
		return w
	}

	call("open", 200)
	if a.Load() != 1 || b.Load() != 0 || c.Load() != 1 {
		t.Fatalf("initial real rejection and paid fallback: %d/%d/%d", a.Load(), b.Load(), c.Load())
	}
	call("open", 200)
	if a.Load() != 1 || b.Load() != 0 || c.Load() != 2 {
		t.Fatalf("recorded quota must skip A and expired B: %d/%d/%d", a.Load(), b.Load(), c.Load())
	}
	if calls := quotaReads.Load(); calls != 1 {
		t.Fatalf("expected one separate quota confirmation, got %d", calls)
	}
	deny := call("limited", 503)
	if a.Load() != 1 || b.Load() != 0 || c.Load() != 2 {
		t.Fatalf("denied paid route should cause zero network sends: %d/%d/%d", a.Load(), b.Load(), c.Load())
	}
	assertCPA60ReplayDiagnostics(t, f, deny, model, ids, true, resets)
	registry.GetGlobalRegistry().UnregisterClient(paidAuth.ID)
	absent := call("open", 503)
	if a.Load() != 1 || b.Load() != 0 || c.Load() != 2 {
		t.Fatalf("zero eligible routes should cause zero network sends: %d/%d/%d", a.Load(), b.Load(), c.Load())
	}
	assertCPA60ReplayDiagnostics(t, f, absent, model, ids, false, resets)
}

type cpa60ReplayTransport struct{ codex http.RoundTripper }

func (r cpa60ReplayTransport) RoundTripperFor(a *coreauth.Auth) http.RoundTripper {
	if a != nil && a.Provider == "codex" {
		return r.codex
	}
	return nil
}

func schedulingCallerIDForTest(name string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte("scheduling-test\x00"+name)))
}

func assertCPA60ReplayDiagnostics(t *testing.T, f *inventoryHarness, w *httptest.ResponseRecorder, model string, ids map[string]string, paidRegistered bool, resetUnix int64) {
	t.Helper()
	raw := w.Body.String()
	id := ojson.Get(raw, "error.request_id").String()
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.Version() != 7 || w.Header().Get("X-Request-ID") != id {
		t.Fatalf("expected a server-generated, correlated UUIDv7, got body %s and header %q", raw, w.Header().Get("X-Request-ID"))
	}
	if code := ojson.Get(raw, "error.code").String(); code != "no_available_route" || ojson.Get(raw, "error.model").String() != model || w.Header().Get("Retry-After") != "" {
		t.Fatalf("bad local route error: %s (headers=%v)", raw, w.Header())
	}
	get := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/v8/management/observability/routing/"+id, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+auth)
		reply := httptest.NewRecorder()
		f.server.engine.ServeHTTP(reply, r)
		if reply.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("routing diagnostics response %d is cacheable", reply.Code)
		}
		return reply
	}
	if denied := get("open"); denied.Code != http.StatusUnauthorized {
		t.Fatalf("public key read privileged routing diagnostics: %d", denied.Code)
	}
	reply := get("test-password")
	raw = reply.Body.String()
	if reply.Code != 200 || ojson.Get(raw, "request_id").String() != id || ojson.Get(raw, "model").String() != model ||
		!ojson.Get(raw, "send_count").Exists() || ojson.Get(raw, "send_count").Int() != 0 ||
		!ojson.Get(raw, "wait_ms").Exists() || ojson.Get(raw, "wait_ms").Int() != 0 ||
		ojson.Get(raw, "terminal.code").String() != "no_available_route" {
		t.Fatalf("wrong or missing actual outcome: %d %s", reply.Code, raw)
	}
	for _, canary := range []string{"CANARY", "@example.invalid", ".json"} {
		if strings.Contains(raw, canary) {
			t.Fatalf("routing read leaked %q: %s", canary, raw)
		}
	}
	stage := ojson.Get(raw, "stages.0").Raw
	registered := int64(2)
	wantPaidReason := "model_not_registered"
	if paidRegistered {
		registered++
		wantPaidReason = "funding_ineligible"
	}
	if ojson.Get(stage, "counts.inventory").Int() != 3 || ojson.Get(stage, "counts.registered").Int() != registered ||
		ojson.Get(stage, "counts.eligible").Int() != 2 || !ojson.Get(stage, "counts.available").Exists() ||
		ojson.Get(stage, "counts.available").Int() != 0 {
		t.Fatalf("bad funnel: %s", stage)
	}
	wantReasons := map[string]string{ids["A"]: "credential_quota", ids["B"]: "access_token_expired", ids["C"]: wantPaidReason}
	for _, row := range ojson.Get(stage, "candidates").Array() {
		id := ojson.Get(row.Raw, "resource_id").String()
		for _, reason := range ojson.Get(row.Raw, "reasons").Array() {
			if wantReasons[id] == reason.String() {
				delete(wantReasons, id)
			}
		}
		if id == ids["A"] {
			recheck, err := time.Parse(time.RFC3339, ojson.Get(row.Raw, "recheck.at").String())
			if err != nil || recheck.Unix() != resetUnix {
				t.Fatalf("135h verified quota recheck not recorded: %s", row.Raw)
			}
		}
		if !ojson.Get(row.Raw, "refresh.state").Exists() || !ojson.Get(row.Raw, "recheck.state").Exists() {
			t.Fatalf("missing refresh/recheck knowledge state: %s", row.Raw)
		}
	}
	if len(wantReasons) != 0 {
		t.Fatalf("missing independent route reasons %v: %s", wantReasons, stage)
	}
}
