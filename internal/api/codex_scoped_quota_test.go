package api

import (
	"fmt"
	"io"

	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

type scopedQuotaTransport struct{ rt http.RoundTripper }

func (p scopedQuotaTransport) RoundTripperFor(*coreauth.Auth) http.RoundTripper { return p.rt }

func TestScopedCodexQuotaInferenceAndRecovery(t *testing.T) {
	testNativeQuotaInferenceAndRecovery(t, false)
}

func TestWholeCodexQuotaInferenceAndRecovery(t *testing.T) {
	testNativeQuotaInferenceAndRecovery(t, true)
}

func testNativeQuotaInferenceAndRecovery(t *testing.T, whole bool) {
	model, sibling, gateModel := "gpt-5.3-codex-spark", "gpt-5.4", "gpt-5.3-codex-spark"
	if whole {
		model, sibling, gateModel = "gpt-5.4", "gpt-5.4-mini", ""
	}
	var mode atomic.Int32
	var hangingReads atomic.Int32
	var mu sync.Mutex
	sends := map[string]int{}
	reset := time.Now().Add(135 * time.Hour).Unix()
	weeklyWindow := func(percent int, seconds int64) string {
		return fmt.Sprintf(`{"used_percent":%d,"reset_at":%d,"limit_window_seconds":%d}`, percent, reset, seconds)
	}
	upstream, quotaNetwork := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Authorization")
		if r.URL.Path == "/backend-api/wham/usage" {
			if key != "Bearer quota-A-CANARY" || r.Header.Get("Chatgpt-Account-Id") != "acct-A-CANARY" {
				t.Error("query did not address the inference account")
			}
			if whole {
				switch mode.Load() {
				case 5:
					hangingReads.Add(1)
					<-r.Context().Done()
				case 0, 6:
					balance, credits := "0", false
					if mode.Load() == 6 {
						balance, credits = "1.25", true
					}
					fmt.Fprintf(w, `{"rate_limit":{"allowed":false,"limit_reached":true,"primary_window":%s,"secondary_window":%s},"additional_rate_limits":[],"credits":{"has_credits":%t,"unlimited":false,"balance":%q}}`, weeklyWindow(25, 18000), weeklyWindow(100, 604800), credits, balance)
				case 1:
					w.Header().Set("Date", time.Now().Add(-2*time.Second).UTC().Format(http.TimeFormat))
					fmt.Fprintf(w, `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":%s,"secondary_window":%s},"additional_rate_limits":[]}`, weeklyWindow(25, 18000), weeklyWindow(42, 604800))
				case 2:
					fmt.Fprint(w, `{"unverified":"observation"}`)
				default:
					seconds := int64(604800)
					if mode.Load() == 3 {
						seconds = 86400
					}
					w.Header().Set("Date", time.Now().Add(time.Second).UTC().Format(http.TimeFormat))
					fmt.Fprintf(w, `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":%s,"secondary_window":%s},"additional_rate_limits":[]}`, weeklyWindow(25, 18000), weeklyWindow(42, seconds))
				}
				return
			}
			clock := time.Now().Add(-2 * time.Second)
			if mode.Load() != 1 {
				clock = time.Now().Add(time.Second)
			}
			w.Header().Set("Date", clock.UTC().Format(http.TimeFormat))
			base := fmt.Sprintf(`"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":%s,"secondary_window":%s}`, weeklyWindow(12, 18000), weeklyWindow(25, 604800))
			additional := ""
			if mode.Load() != 2 {
				seconds := int64(604800)
				if mode.Load() == 3 {
					seconds = 86400
				}
				additional = fmt.Sprintf(`,"additional_rate_limits":[{"limit_name":"GPT-5.3-Codex-Spark","metered_feature":"codex_bengalfox","rate_limit":{"allowed":true,"limit_reached":false,"primary_window":%s,"secondary_window":%s}}]`, weeklyWindow(18, 18000), weeklyWindow(25, seconds))
			}
			fmt.Fprint(w, "{"+base+additional+"}")
			return
		}
		if r.URL.Path != "/backend-api/codex/responses" {
			t.Errorf("unexpected dispatch %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var req struct{ Model string }
		_ = json.Unmarshal(raw, &req)
		mu.Lock()
		sends[key+"/"+req.Model]++
		mu.Unlock()
		if key == "Bearer quota-A-CANARY" && req.Model == model && (mode.Load() == 0 || mode.Load() >= 5) {
			limit, header := "codex_bengalfox", "X-Codex-Bengalfox"
			if whole {
				limit, header = "codex", "X-Codex"
			} else {
				w.Header().Set("X-Codex-Bengalfox-Limit-Name", "GPT-5.3-Codex-Spark")
			}
			w.Header().Set("X-Codex-Active-Limit", limit)
			w.Header().Set(header+"-Secondary-Used-Percent", "100")
			w.Header().Set(header+"-Secondary-Window-Minutes", "10080")
			w.Header().Set(header+"-Secondary-Reset-At", fmt.Sprint(reset))
			w.WriteHeader(429)
			if mode.Load() == 7 {
				fmt.Fprint(w, `{"error":{"type":"rate_limit_error"}}`)
			} else {
				fmt.Fprintf(w, `{"error":{"type":"usage_limit_reached","limit_window_minutes":10080,"resets_at":%d}}`, reset)
			}
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"object\":\"response\",\"model\":%q,\"status\":\"completed\",\"output\":[]}}\n\n", req.Model)
	}))
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"A", "B"} {
		if err := os.WriteFile(filepath.Join(authDir, "fixture-"+label+"-CANARY.json"), []byte(fmt.Sprintf(`{"type":"codex","access_token":"quota-%s-CANARY","account_id":"acct-%s-CANARY","disabled":false}`, label, label)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\n", filepath.ToSlash(authDir))), 0600); err != nil {
		t.Fatal(err)
	}
	open := func() *inventoryHarness {
		f := newInventoryHarness(t, dir)
		f.handler.SetQuotaNetwork(quotaNetwork)
		f.manager.SetConfig(f.server.cfg)
		f.manager.SetRetryConfig(4, time.Second, 0)
		f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
		rt := upstream.Client().Transport.(*http.Transport).Clone()
		rt.Proxy = nil
		rt.DialContext = quotaNetwork.DialContext
		f.manager.SetRoundTripperProvider(scopedQuotaTransport{rt})
		for _, a := range f.manager.List() {
			// Explicit priority ensures A is selected before B every time A is available.
			if a.Metadata["access_token"] == "quota-A-CANARY" {
				a.Attributes["priority"] = "100"
				if _, err := f.manager.Update(coreauth.WithSkipPersist(t.Context()), a); err != nil {
					t.Fatal(err)
				}
			}
			registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: model}, {ID: sibling}})
		}
		h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
		f.server.engine.POST("/v1/responses", h.Responses)
		return f
	}
	infer := func(f *inventoryHarness, requested string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"input":[]}`, requested)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s inference status=%d body=%s", requested, w.Code, w.Body.String())
		}
	}
	expect := func(a, b, other int) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if sends["Bearer quota-A-CANARY/"+model] != a || sends["Bearer quota-B-CANARY/"+model] != b || sends["Bearer quota-A-CANARY/"+sibling] != other {
			t.Fatalf("unexpected inference dispatches: %v", sends)
		}
	}
	readGate := func(f *inventoryHarness, want int) resource.Gate {
		t.Helper()
		raw := f.request("inference-gates", 200)
		if strings.Contains(string(raw), "CANARY") {
			t.Fatal("quota status disclosed identity material")
		}
		var state struct {
			Gates []struct {
				resource.Gate
				Quota resource.QuotaGateEvidence
			}
		}
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatal(err)
		}
		if len(state.Gates) != want {
			t.Fatalf("quota status=%s; want %d gates", raw, want)
		}
		if want == 0 {
			return resource.Gate{}
		}
		row := state.Gates[0]
		if row.Model != gateModel || row.Reason != "quota_windows_exhausted" || row.Applicability != "current" || row.Quota.Window != "secondary" || row.Quota.WindowSeconds != 604800 || row.Quota.RecheckAtMS != reset*1000 {
			t.Fatalf("wrong model pause: %+v", row)
		}
		return row.Gate
	}
	f := open()
	t.Cleanup(func() {
		for _, a := range f.manager.List() {
			registry.GetGlobalRegistry().UnregisterClient(a.ID)
		}
	})
	infer(f, model)
	readGate(f, 1)
	infer(f, model)
	other := 1
	if whole {
		other = 0
	}
	infer(f, sibling)
	expect(1, 2, other)
	f.close()
	f = open()
	gate := readGate(f, 1)
	infer(f, model)
	expect(1, 3, other)
	var view struct{ Sources []resource.QuotaSource }
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &view); err != nil {
		t.Fatal(err)
	}
	var q resource.QuotaQuery
	for _, source := range view.Sources {
		if source.SubjectID == gate.Targets[0].ResourceID {
			q = resource.QuotaQuery{Binding: source.Binding, AuthIndex: source.AuthIndex, SourceVersion: source.SourceVersion, SourceID: source.SourceID, SubjectID: source.SubjectID}
		}
	}
	if q.AuthIndex == "" {
		t.Fatal("paused quota source unavailable")
	}
	wrongVersion := q
	wrongVersion.SourceVersion = strings.Repeat("f", 64)
	queryQuota(t, f, wrongVersion, 409)
	wrongIdentity := q
	wrongIdentity.SubjectID = "unrelated-resource"
	queryQuota(t, f, wrongIdentity, 409)
	readGate(f, 1)
	for _, invalid := range []int32{1, 2, 3} {
		mode.Store(invalid)
		queryQuota(t, f, q, 200)
		readGate(f, 1)
	}
	gateWrite := func(owner, action string, revision uint64, id string, want int) {
		t.Helper()
		op := resource.GateOperation{Version: 1, OpID: id, ExpectedRevision: revision, Binding: q.Binding, AuthIndex: q.AuthIndex, SourceVersion: q.SourceVersion, Subject: "credential", Owner: owner, Action: action, Reason: "manual_disabled", EvidenceID: "test-manual-observation"}
		raw, _ := json.Marshal(struct {
			resource.GateOperation
			ManualResume bool `json:"manualResume"`
		}{op, action == "clear"})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v8/management/inference-gates/operations", strings.NewReader(string(raw)))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		f.server.engine.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("gate write status=%d: %s", w.Code, w.Body.String())
		}
	}
	gateWrite(gate.Owner, "clear", gate.Revision, "5e12bc2e-130c-416f-ac31-6a8defef8321", 422)
	if whole {
		gateWrite("test.manual", "pause", gate.Revision, "5e12bc2e-130c-416f-ac31-6a8defef8322", 200)
	}
	mode.Store(4)
	obs := queryQuota(t, f, q, 200)
	if len(obs.ClearedQuotaWindows) != 1 {
		t.Fatalf("missing fresh recovery acknowledgement: %+v", obs)
	}
	if whole {
		infer(f, model)
		expect(1, 4, other)
		gateWrite("test.manual", "clear", gate.Revision+2, "5e12bc2e-130c-416f-ac31-6a8defef8323", 200)
	}
	readGate(f, 0)
	infer(f, model)
	if whole {
		expect(2, 4, other)
		for _, negative := range []int32{5, 6, 7} {
			f.close()
			f = open()
			mode.Store(negative)
			started := time.Now()
			infer(f, model)
			if negative == 5 && (hangingReads.Load() != 1 || time.Since(started) > time.Second) {
				t.Fatalf("hung WHAM read delayed healthy fallback: reads=%d delay=%s", hangingReads.Load(), time.Since(started))
			}
			readGate(f, 0)
			infer(f, sibling)
		}
		expect(5, 7, 3)
	} else {
		expect(2, 3, other)
	}
}
