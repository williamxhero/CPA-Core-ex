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

func TestProviderSchedulingTrueTerminalClasses(t *testing.T) {
	for _, tc := range []struct {
		wantStatus     int
		upstreamStatus int
		code           string
	}{
		{429, 429, "rate_limit_exceeded"},
		{502, 502, "upstream_unavailable"},
		{502, 401, "upstream_authentication_required"},
		{502, 403, "upstream_authentication_required"},
	} {
		t.Run(fmt.Sprint(tc.upstreamStatus), func(t *testing.T) {
			f := newSchedulingHTTPFixture(t, func(w http.ResponseWriter, r *http.Request, key string) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "90")
				w.Header().Set("X-Upstream-Private", "SECRET-CANARY")
				w.WriteHeader(tc.upstreamStatus)
				fmt.Fprint(w, `{"error":{"message":"RAW-UPSTREAM-SECRET-CANARY","credentials":"PRIVATE"}}`)
			})
			f.manager.SetRetryConfig(0, 0, 0)
			w, err := f.requestModel(t.Context(), "limited", simpleSchedulingChat)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Body.Close()
			b, err := io.ReadAll(w.Body)
			if err != nil {
				t.Fatal(err)
			}
			raw := string(b)
			id := w.Header.Get("X-Request-ID")
			if w.StatusCode != tc.wantStatus || ojson.Get(raw, "error.code").String() != tc.code ||
				id == "" || ojson.Get(raw, "error.request_id").String() != id || ojson.Get(raw, "error.model").String() != "public-scheduling-model" ||
				strings.Contains(raw, "CANARY") || w.Header.Get("X-Upstream-Private") != "" || w.Header.Get("Retry-After") != "" {
				t.Fatalf("%d not preserved and sanitized: %d %v %s", tc.upstreamStatus, w.StatusCode, w.Header, raw)
			}
			diagnosis := readSchedulingTraceForTest(t, f.inventoryHarness, id)
			if ojson.Get(diagnosis, "terminal.code").String() != tc.code || ojson.Get(diagnosis, "send_count").Int() != 1 {
				t.Fatalf("bad terminal accounting: %s", diagnosis)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if fmt.Sprint(f.calls) != "[A]" {
				t.Fatalf("expected one upstream send, got %v", f.calls)
			}
		})
	}
}

func readSchedulingTraceForTest(t *testing.T, f *inventoryHarness, id string) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v8/management/observability/routing/"+id, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("routing diagnosis: %d %s", w.Code, w.Body.String())
	}
	return w.Body.String()
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

func TestProviderSchedulingCommittedStreamKeepsOneSanitizedTerminal(t *testing.T) {
	f := newSchedulingHTTPFixture(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"delivered-visible-text\"},\"finish_reason\":null}]}\n\n")
		w.(http.Flusher).Flush()
		fmt.Fprint(w, "event: error\ndata: {\"status\":429,\"error\":{\"message\":\"RAW-UPSTREAM-CANARY\"}}\n\n")
		w.(http.Flusher).Flush()
	})
	f.manager.SetRetryConfig(3, time.Second, 0)
	f.manager.SetUpstreamErrorRetryLimit(-1)
	w, err := f.requestModel(t.Context(), "open", strings.TrimSuffix(simpleSchedulingChat, "}")+",\"stream\":true}")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Body.Close()
	b, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	id := w.Header.Get("X-Request-ID")
	raw := string(b)
	if w.StatusCode != 200 || id == "" || !strings.Contains(raw, "delivered-visible-text") ||
		strings.Count(raw, "\"code\":\"rate_limit_exceeded\"") != 1 || !strings.Contains(raw, id) || strings.Contains(raw, "CANARY") {
		t.Fatalf("committed stream did not get one sanitized terminal event: %d %v %s", w.StatusCode, w.Header, raw)
	}
	diag := readSchedulingTraceForTest(t, f.inventoryHarness, id)
	if ojson.Get(diag, "terminal.code").String() != "rate_limit_exceeded" ||
		!ojson.Get(diag, "output_committed").Bool() || ojson.Get(diag, "send_count").Int() != 1 {
		t.Fatalf("wrong committed stream accounting: %s", diag)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.calls) != "[A]" {
		t.Fatalf("committed output was retried: %v", f.calls)
	}
}

func TestProviderSchedulingSuccessfulStreamTraceAtEOF(t *testing.T) {
	f := newSchedulingHTTPFixture(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"stream-completed\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chatcmpl-test\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	})
	res, err := f.requestModel(t.Context(), "open", strings.TrimSuffix(simpleSchedulingChat, "}")+",\"stream\":true}")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != 200 || !strings.Contains(string(raw), "stream-completed") || strings.Count(string(raw), "[DONE]") != 1 {
		t.Fatalf("stream did not terminate normally: %d %s %v", res.StatusCode, raw, err)
	}
	trace := readSchedulingTraceForTest(t, f.inventoryHarness, res.Header.Get("X-Request-ID"))
	if ojson.Get(trace, "terminal.code").String() != "succeeded" || ojson.Get(trace, "terminal.status").Int() != 200 ||
		!ojson.Get(trace, "output_committed").Bool() || ojson.Get(trace, "send_count").Int() != 1 {
		t.Fatalf("stream receipt was incomplete at EOF: %s", trace)
	}
}

func TestProviderSchedulingAnonymousEnforcementRetainsNoTrace(t *testing.T) {
	f := newSchedulingHTTPFixture(t, func(http.ResponseWriter, *http.Request, string) {
		t.Error("restricted anonymous request sent upstream")
	})
	cfg := *f.server.cfg
	cfg.Routing.ProviderScheduling = config.ProviderSchedulingConfig{
		Mode: "enforce",
	}
	f.manager.SetConfig(&cfg)
	for _, a := range f.auths {
		disabled := a.Clone()
		disabled.Disabled = true
		if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), disabled); err != nil {
			t.Fatal(err)
		}
	}
	handler := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, f.manager))
	f.server.engine.POST("/anonymous/chat/completions", handler.ChatCompletions)
	const supplied = "01902f6e-f973-7ae1-bed9-2d78231441a7"
	req := httptest.NewRequest(http.MethodPost, "/anonymous/chat/completions", strings.NewReader(simpleSchedulingChat))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", supplied)
	req.Header.Set("X-Access-Principal", "open")
	rec := httptest.NewRecorder()
	f.server.engine.ServeHTTP(rec, req)
	id := ojson.Get(rec.Body.String(), "error.request_id").String()
	parsed, err := uuid.Parse(id)
	if rec.Code != http.StatusServiceUnavailable || ojson.Get(rec.Body.String(), "error.code").String() != "no_available_route" ||
		rec.Header().Get("X-Request-ID") != id || err != nil || parsed.Version() != 7 || id == supplied || rec.Header().Get("Retry-After") != "" {
		t.Fatalf("anonymous denial has no safe correlation: %d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	f.request("observability/routing/"+id, http.StatusNotFound)
}

func TestProviderSchedulingShadowComparesWithoutDispatchOrReservation(t *testing.T) {
	f := newSchedulingHTTPFixture(t, nil)
	// The incident test above covers the native catalog gate. Isolate
	// scheduling policy here while retaining real catalog IDs and sends.
	f.manager.SetInferenceAdmission(nil)
	cfg, err := config.LoadConfig(f.path)
	if err != nil {
		t.Fatal(err)
	}
	policy := &cfg.Routing.ProviderScheduling
	policy.Models = []string{"public-scheduling-model"}
	policy.Callers = []string{schedulingCallerIDForTest("limited")}
	policy.CallerFunding = map[string][]string{schedulingCallerIDForTest("limited"): {"prepaid"}}
	policy.Resources = map[string]config.ProviderSchedulingResource{
		f.ids["A"]: {Funding: "subscription", MaxConcurrent: 1},
		f.ids["C"]: {Funding: "prepaid", MaxConcurrent: 1},
	}
	call := func(caller, body string, wantStatus int, wantText string) string {
		t.Helper()
		res, err := f.requestModel(t.Context(), caller, body)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != wantStatus || (wantText != "" && !strings.Contains(string(raw), wantText)) {
			t.Fatalf("caller=%s status=%d want=%d: %s", caller, res.StatusCode, wantStatus, raw)
		}
		return res.Header.Get("X-Request-ID")
	}
	policy.Mode = "shadow"
	f.manager.SetConfig(cfg)
	shadowID := call("limited", simpleSchedulingChat, 200, "\"content\":\"A\"")
	trace := readSchedulingTraceForTest(t, f.inventoryHarness, shadowID)
	if ojson.Get(trace, "mode").String() != "shadow" || ojson.Get(trace, "stages.0.actual_resource_id").String() != f.ids["A"] ||
		ojson.Get(trace, "stages.0.proposed_resource_id").String() != f.ids["C"] ||
		ojson.Get(trace, "stages.0.comparison").String() != "different" ||
		ojson.Get(trace, "stages.0.counts.reserved").Int() != 0 || ojson.Get(trace, "send_count").Int() != 1 {
		t.Fatalf("wrong read-only comparison: %s", trace)
	}
	if id := call("open", simpleSchedulingChat, 200, "\"content\":\"A\""); id != "" {
		t.Fatal("caller outside the rollout created a trace")
	}
	if id := call("not-authorized", simpleSchedulingChat, 401, ""); id != "" {
		t.Fatal("rejected caller created a trace")
	}
	if id := call("limited", strings.Replace(simpleSchedulingChat, "public-scheduling-model", "not-a-registered-model", 1), 400, "model_not_found"); id != "" {
		t.Fatal("unknown model created a trace")
	}
	policy.Mode = "enforce"
	f.manager.SetConfig(cfg)
	enforceID := call("limited", simpleSchedulingChat, 200, "\"content\":\"C\"")
	trace = readSchedulingTraceForTest(t, f.inventoryHarness, enforceID)
	if ojson.Get(trace, "stages.0.selected_resource_id").String() != f.ids["C"] ||
		ojson.Get(trace, "stages.0.counts.reserved").Int() != 1 || ojson.Get(trace, "send_count").Int() != 1 {
		t.Fatalf("wrong enforcing diagnosis: %s", trace)
	}
	policy.Mode = "off"
	f.manager.SetConfig(cfg)
	if id := call("limited", simpleSchedulingChat, 200, "\"content\":\"A\""); id != "" {
		t.Fatal("rolled-back request still entered diagnostics")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.calls) != "[A A C A]" {
		t.Fatalf("scope/rollback dispatched incorrectly: %v", f.calls)
	}
}
