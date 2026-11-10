package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInferenceGateDurableOwnerOperation(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	installGateFixtureExecutors(f)
	var sources struct {
		Sources []map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &sources); err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	for _, s := range sources.Sources {
		if s["auth_index"] != nil && s["auth_index"] != "" {
			source = s
			break
		}
	}
	if source == nil {
		t.Fatal("missing host-issued runtime source")
	}
	op := map[string]any{"version": 1, "opId": "4d413194-faca-4b73-826e-a55a0b5da304", "expectedGateRevision": 0, "scope": source["scope"], "targets": source["targets"], "auth_index": source["auth_index"], "sourceVersion": source["sourceVersion"], "subject": "credential", "model": "", "owner": "credential-auto/v1", "action": "pause", "reason": "quota_exhausted", "evidenceId": "test-evidence-1"}
	raw, _ := json.Marshal(op)
	req := httptest.NewRequest("POST", "/v8/management/inference-gates/operations", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("operation status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("gate result cacheable")
	}
	var result map[string]any
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["durable"] != true || result["applied"] != true || result["durableRevision"] != float64(1) || result["appliedRevision"] != float64(1) {
		t.Fatalf("not a durable applied ACK: %+v", result)
	}
	var state struct {
		Gates        []map[string]any `json:"gates"`
		GateRevision uint64           `json:"gateRevision"`
	}
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if state.GateRevision != 1 || len(state.Gates) != 1 || state.Gates[0]["owner"] != "credential-auto/v1" {
		t.Fatalf("owner not durably readable: %+v", state)
	}
}

func gateSource(t *testing.T, f *inventoryHarness) map[string]any {
	installGateFixtureExecutors(f)
	t.Helper()
	var view struct {
		Sources []map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &view); err != nil {
		t.Fatal(err)
	}
	for _, s := range view.Sources {
		if s["auth_index"] != nil && s["auth_index"] != "" {
			return s
		}
	}
	t.Fatal("no current runtime source")
	return nil
}
func gateOp(s map[string]any, revision int, id, owner, action string) map[string]any {
	return map[string]any{"version": 1, "opId": id, "expectedGateRevision": revision, "scope": s["scope"], "targets": s["targets"], "auth_index": s["auth_index"], "sourceVersion": s["sourceVersion"], "subject": "credential", "model": "", "owner": owner, "action": action, "reason": "quota_exhausted", "evidenceId": "test-evidence"}
}
func gatePost(t *testing.T, f *inventoryHarness, op map[string]any, want int) []byte {
	installGateFixtureExecutors(f)
	t.Helper()
	raw, _ := json.Marshal(op)
	req := httptest.NewRequest("POST", "/v8/management/inference-gates/operations", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("gate status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
	return w.Body.Bytes()
}
func TestInferenceGateOwnersCASIdempotencyRestart(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	s := gateSource(t, f)
	op := gateOp(s, 0, "bb0ca215-e7ad-4ef8-bc27-e6b70f7da3b8", "owner-a", "pause")
	first := gatePost(t, f, op, 200)
	if !bytes.Equal(first, gatePost(t, f, op, 200)) {
		t.Fatal("lost ACK retry changed receipt")
	}
	op["reason"] = "different"
	gatePost(t, f, op, 409)
	op["reason"] = "quota_exhausted"
	gatePost(t, f, gateOp(s, 0, "08b920ec-cd7e-42d4-9c8e-d5733fa43f6b", "owner-b", "pause"), 409)
	gatePost(t, f, gateOp(s, 1, "08b920ec-cd7e-42d4-9c8e-d5733fa43f6b", "owner-b", "pause"), 200)
	gatePost(t, f, gateOp(s, 2, "54ab5fdf-0176-427a-a314-a61e752186a7", "owner-a", "clear"), 200)
	f.close()
	f = newInventoryHarness(t, dir)
	if !bytes.Equal(first, gatePost(t, f, op, 200)) {
		t.Fatal("restart lost original receipt")
	}
	var state struct {
		Gates        []map[string]any `json:"gates"`
		GateRevision uint64           `json:"gateRevision"`
	}
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if state.GateRevision != 3 || len(state.Gates) != 1 || state.Gates[0]["owner"] != "owner-b" {
		t.Fatalf("restart or owner clear lost another owner: %+v", state)
	}
}

func TestInferenceGateActualNativeHTTPAndSSE(t *testing.T) {
	var sends atomic.Int32
	var aSends atomic.Int32
	var pausedKey string
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var hold atomic.Bool
	hold.Store(true)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sends.Add(1)
		if r.Header.Get("Authorization") == "Bearer "+pausedKey {
			aSends.Add(1)
			if hold.CompareAndSwap(true, false) {
				close(entered)
				<-release
			}
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"object\":\"response\",\"model\":\"gate-test-model\",\"status\":\"completed\",\"output\":[]}}\n\n")
	}))
	defer upstream.Close()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "auth"), 0700)
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex:\n    - name: first\n      base-url: %q\n      keys: [{api-key: synthetic-A}]\n    - name: second\n      base-url: %q\n      keys: [{api-key: synthetic-B}]\n", filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL, upstream.URL)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
	for _, a := range f.manager.List() {
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", []*registry.ModelInfo{{ID: "gate-test-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	source := gateSource(t, f)
	var authID string
	for _, a := range f.manager.List() {
		if a.Index == source["auth_index"] {
			authID = a.ID
			pausedKey = a.Attributes["api_key"]
		}
	}
	f.manager.SetSelector(&gatePreferASelector{key: pausedKey})
	h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/responses", func(c *gin.Context) {
		c.Request = c.Request.WithContext(handlers.WithPinnedAuthID(c.Request.Context(), authID))
		h.Responses(c)
	})
	server := httptest.NewServer(f.server.engine)
	defer server.Close()
	send := func(stream bool) int {
		t.Helper()
		r, err := http.Post(server.URL+"/v1/responses", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"gate-test-model","input":[],"stream":%t}`, stream)))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		_, _ = io.Copy(io.Discard, r.Body)
		return r.StatusCode
	}
	drained := make(chan int, 1)
	go func() { drained <- send(false) }()
	select {
	case <-entered:
	case <-time.After(6 * time.Second):
		t.Fatal("admitted A did not reach controlled upstream")
	}

	gatePost(t, f, gateOp(source, 0, "38291010-eb72-4b7f-8747-344bfe7dfd50", "owner-a", "pause"), 200)
	close(release)
	select {
	case code := <-drained:
		if code != 200 {
			t.Fatalf("admitted A did not drain %d", code)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("pause cancelled/stalled admitted A")
	}
	before := aSends.Load()
	for _, stream := range []bool{false, true} {
		if code := send(stream); code != 200 {
			t.Fatalf("healthy B fallback failed stream=%v", stream)
		}
	}
	if aSends.Load() != before {
		t.Fatal("NEW A inference reached real upstream after applied ACK")
	}
	if _, err := f.manager.VerifyInference(context.Background(), authID, "gate-test-model"); err == nil {
		t.Fatal("operator VerifyInference bypassed pause")
	}
	if aSends.Load() != before {
		t.Fatal("VerifyInference sent while paused")
	}
}

func TestInferenceGateEligibilityNeverInventsRouteCoverage(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	s := gateSource(t, f)
	f.manager.UnregisterExecutor("codex")
	body := map[string]any{"version": 1, "scope": s["scope"], "targets": s["targets"], "auth_index": s["auth_index"], "sourceVersion": s["sourceVersion"], "route": "all-current-source"}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/v8/management/inference-gates/eligibility", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("eligibility status=%d body=%s", w.Code, w.Body.String())
	}
	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)
	if response["version"] != float64(1) || response["auth_index"] != s["auth_index"] || response["sourceVersion"] != s["sourceVersion"] || response["supported"] != false || response["ready"] != false {
		t.Fatal("missing binding-scoped honest eligibility")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("eligibility cacheable")
	}
}

func TestInferenceGatePausedOAuthStillQueriesTrustedManagement(t *testing.T) {
	var calls atomic.Int32
	_, network := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/backend-api/wham/usage" {
			t.Error("management escaped trusted quota route")
		}
		fmt.Fprintf(w, `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":25,"reset_at":%d,"limit_window_seconds":18000},"secondary_window":{"used_percent":50,"reset_at":%d,"limit_window_seconds":604800}}}`, time.Now().Add(time.Hour).Unix(), time.Now().Add(time.Hour).Unix())
	}))
	f := quotaOAuthFixture(t, network)
	source := quotaSourceFor(t, f, "codex-oauth-wham")
	raw, _ := json.Marshal(source)
	var s map[string]any
	json.Unmarshal(raw, &s)
	gatePost(t, f, gateOp(s, 0, "68bf3510-a450-44f2-90f5-8a46f7ba8b55", "owner-wallet/v1", "pause"), 200)
	obs := queryQuota(t, f, resource.QuotaQuery{Binding: source.Binding, AuthIndex: source.AuthIndex, SourceVersion: source.SourceVersion}, 200)
	if obs.QueryStatus != "success" || calls.Load() != 1 {
		t.Fatal("paused management quota no longer usable")
	}
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if len(state.Gates) != 1 || state.Revision != 1 {
		t.Fatal("quota success implicitly cleared owner")
	}
}

func TestInferenceGateNativeRefreshContinuityVersusReplacement(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("unexpected token path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"ROTATED-SYNTHETIC","refresh_token":"ROTATED-GRANT","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokenServer.Close()
	tr := tokenServer.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = tokenServer.Certificate().DNSNames[0]
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, tokenServer.Listener.Addr().String())
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("controlled token TLS verification disabled")
	}
	original := http.DefaultTransport
	http.DefaultTransport = tr
	defer func() { http.DefaultTransport = original; tr.CloseIdleConnections() }()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	os.MkdirAll(authDir, 0700)
	os.WriteFile(filepath.Join(authDir, "oauth.json"), []byte(`{"type":"codex","access_token":"INITIAL-SYNTHETIC","refresh_token":"INITIAL-GRANT","account_id":"synthetic-account","expired":"2020-01-01T00:00:00Z"}`), 0600)
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
	source := quotaSourceFor(t, f, "codex-oauth-wham")
	raw, _ := json.Marshal(source)
	var s map[string]any
	json.Unmarshal(raw, &s)
	gatePost(t, f, gateOp(s, 0, "fab22899-19d8-463a-9fc9-ec689d665016", "owner-refresh", "pause"), 200)
	var id string
	for _, a := range f.manager.List() {
		if a.Index == source.AuthIndex {
			id = a.ID
		}
	}
	if _, err := f.manager.ForceRefreshAuth(context.Background(), id); err != nil {
		t.Fatal(err)
	}

	next := quotaSourceFor(t, f, "codex-oauth-wham")
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if len(state.Gates) != 1 || !reflect.DeepEqual(state.Gates[0].Targets, next.Targets) {
		t.Fatalf("host-proven refresh did not carry existing owner restriction: before=%+v after=%+v", source.Targets, next.Targets)
	}
	if out := readGateContinuity(t, f, source.Binding, next); out["proven"] != true {
		t.Fatal("paused refresh has no certified exact continuity")
	}

	// A direct same-path credential replacement is NOT a refresh certificate.
	a, _ := f.manager.GetByID(id)
	a.Metadata["access_token"] = "REPLACEMENT-SYNTHETIC"
	a.Metadata["account_id"] = "different-account"
	if _, err := f.manager.Storage().Save(coreauth.WithAuthCreationIntent(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	replaced := quotaSourceFor(t, f, "codex-oauth-wham")
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if reflect.DeepEqual(state.Gates[0].Targets, replaced.Targets) || state.AllSourcesReady {
		t.Fatal("unproven replacement inherited old account pause or silently restored traffic")
	}
	if out := readGateContinuity(t, f, source.Binding, replaced); out["proven"] != false {
		t.Fatal("replacement borrowed paused refresh proof")
	}
	gatePost(t, f, gateOp(s, int(state.Revision), "b45cc377-3556-4f06-a2f9-e7daf8d1d106", "owner-refresh", "clear"), 409)

}

type gateEgressCounter struct{ calls atomic.Int32 }

func (d *gateEgressCounter) RoundTrip(*http.Request) (*http.Response, error) {
	d.calls.Add(1)
	return nil, errors.New("controlled egress reached")
}
func TestInferenceGateRestoreAndManagedDisableFailClosed(t *testing.T) {
	for _, failure := range []string{"lost_catalog", "corrupt_catalog", "lost_floor", "disabled_config"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			f := newInventoryHarness(t, dir)
			source := gateSource(t, f)
			gatePost(t, f, gateOp(source, 0, "9dce175f-01ae-43b8-b119-a3949d72c05e", "owner-a", "pause"), 200)
			f.close()
			switch failure {
			case "lost_catalog":
				if err := os.Rename(filepath.Join(dir, ".resource-catalog", "catalog.json"), filepath.Join(dir, ".resource-catalog", "saved-catalog.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt_catalog":
				if err := os.WriteFile(filepath.Join(dir, ".resource-catalog", "catalog.json"), []byte(`{"format":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "lost_floor":
				if err := os.Remove(filepath.Join(dir, ".resource-catalog", "gate-floor-v1")); err != nil {
					t.Fatal(err)
				}
			case "disabled_config":
				editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) { testField(testField(root, "resource-catalog"), "enabled").Value = "false" })
			}
			f = newInventoryHarness(t, dir)
			f.request("inference-gates", 503)
			f.manager.SetConfig(f.server.cfg)
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
			egress := &gateEgressCounter{}
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", egress)
			auths := f.manager.List()
			if len(auths) == 0 {
				t.Fatal("fixture has no auths")
			}
			_, err := f.manager.VerifyInference(ctx, auths[0].ID, "gate-model")
			if !coreexecutor.IsInferenceAdmissionError(err) || egress.calls.Load() != 0 {
				t.Fatalf("restore failure warned and allowed: %T, sends=%d", err, egress.calls.Load())
			}
		})
	}
}

func TestInferenceGateOrphanAStillAllowsIndependentBReconciliation(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	var view struct {
		Sources []map[string]any `json:"sources"`
	}
	json.Unmarshal(f.request("credential-quota/sources", 200), &view)
	var live []map[string]any
	for _, s := range view.Sources {
		if s["auth_index"] != "" && s["auth_index"] != nil {
			live = append(live, s)
		}
	}
	if len(live) != 2 {
		t.Fatal("fixture requires two bound sources")
	}
	a, b := live[0], live[1]
	gatePost(t, f, gateOp(a, 0, "4326b5d2-2b4c-4889-b5fc-d6386cc4cce5", "owner-a", "pause"), 200)
	gatePost(t, f, gateOp(b, 1, "211f5da7-28a6-4df4-a8aa-125502d6e394", "owner-b", "pause"), 200)
	var oldA resource.Binding
	raw, _ := json.Marshal(a)
	json.Unmarshal(raw, &oldA)
	f.close()
	editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
		groups := testField(testField(root, "api-keys"), "codex")
		kept := []*yaml.Node{}
		for _, group := range groups.Content {
			keys := testField(group, "keys")
			if testField(keys.Content[0], "resource-id").Value != oldA.Targets[0].ResourceID {
				kept = append(kept, group)
			}
		}
		groups.Content = kept
	})
	f = newInventoryHarness(t, dir)
	b = gateSource(t, f)
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if !state.Ready || state.AllSourcesReady || len(state.Gates) != 2 {
		t.Fatal("orphan disappeared or became globally ready")
	}
	eligibility := func(source map[string]any) map[string]any {
		body := map[string]any{"version": 1, "scope": source["scope"], "targets": source["targets"], "auth_index": source["auth_index"], "sourceVersion": source["sourceVersion"], "route": "all-current-source"}
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/v8/management/inference-gates/eligibility", bytes.NewReader(raw))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("B eligibility=%d", w.Code)
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	if out := eligibility(b); out["ready"] != true || out["supported"] != true {
		t.Fatal("orphan A globally blocked valid B eligibility")
	}
	gatePost(t, f, gateOp(b, 2, "0b330db7-10dc-4ac6-b472-df8c87ef991a", "owner-b", "clear"), 200)
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if len(state.Gates) != 1 || state.Gates[0].Owner != "owner-a" || state.AllSourcesReady {
		t.Fatal("B recovery purged or restored orphan A")
	}
	if out := eligibility(b); out["ready"] != true {
		t.Fatal("orphan A blocked independent B after own-clear")
	}
}

// The shared identity harness omits service executor registration. Gate tests
// install the same concrete native executor, never a selector/transport fake.
func installGateFixtureExecutors(f *inventoryHarness) {
	f.manager.SetConfig(f.server.cfg)
	for _, a := range f.manager.List() {
		if _, ok := f.manager.Executor(a.Provider); !ok && a.Provider == "codex" {
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(f.server.cfg))
		}
	}
}

func TestInferenceGateActualClaudeAndOpenAICompat(t *testing.T) {
	for _, family := range []string{"claude", "openai-compatibility"} {
		t.Run(family, func(t *testing.T) {
			var aSends, bSends atomic.Int32
			var failB atomic.Bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key := r.Header.Get("Authorization")
				if key == "" {
					key = "Bearer " + r.Header.Get("X-Api-Key")
				}
				switch key {
				case "Bearer SYNTHETIC-A":
					aSends.Add(1)
				case "Bearer SYNTHETIC-B":
					bSends.Add(1)
					if failB.Load() {
						w.WriteHeader(502)
						fmt.Fprint(w, `{"error":{"message":"CONTROLLED-B-FAIL"}}`)
						return
					}
				default:
					t.Errorf("unattributed %s", key)
				}
				raw, _ := io.ReadAll(r.Body)
				var body struct {
					Stream bool `json:"stream"`
				}
				json.Unmarshal(raw, &body)
				if family == "claude" {
					if r.URL.Path != "/v1/messages" {
						t.Errorf("unexpected Claude path %s", r.URL.Path)
					}
					if body.Stream {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
					} else {
						fmt.Fprint(w, `{"id":"m","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
					}
				} else {
					if r.URL.Path != "/v1/chat/completions" {
						t.Errorf("unexpected compat path %s", r.URL.Path)
					}
					if body.Stream {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
					} else {
						fmt.Fprint(w, `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
					}
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "auth"), 0700)
			base := upstream.URL
			if family == "openai-compatibility" {
				base += "/v1"
			}
			text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  %s:\n    - name: gate-native\n      base-url: %q\n      keys: [{api-key: SYNTHETIC-A}, {api-key: SYNTHETIC-B}]\n", filepath.ToSlash(filepath.Join(dir, "auth")), family, base)
			os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600)
			f := newInventoryHarness(t, dir)
			f.manager.SetSelector(&gatePreferASelector{})
			f.manager.SetConfig(f.server.cfg)
			var source map[string]any
			var sources struct {
				Sources []map[string]any `json:"sources"`
			}
			json.Unmarshal(f.request("credential-quota/sources", 200), &sources)
			for _, a := range f.manager.List() {
				if family == "claude" {
					f.manager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(f.server.cfg))
				} else {
					f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
				}
				registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "claude-sonnet-4-5"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
				if a.Attributes["api_key"] == "SYNTHETIC-A" {
					for _, s := range sources.Sources {
						if s["auth_index"] == a.Index {
							source = s
						}
					}
				}
			}
			if source == nil {
				t.Fatal("missing real selected source")
			}
			h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
			rh := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.GET("/v1/responses", rh.ResponsesWebsocket)
			downstream := httptest.NewServer(f.server.engine)
			defer downstream.Close()
			send := func(stream bool) {
				t.Helper()
				r, err := http.Post(downstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"synthetic"}],"stream":%t}`, stream)))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Body.Close()
				body, _ := io.ReadAll(r.Body)
				if r.StatusCode != 200 || !bytes.Contains(body, []byte("ok")) {
					t.Fatalf("route %d: %s", r.StatusCode, body)
				}
			}
			send(false)
			send(true)
			wsTurn := gateWSTurns(t, downstream.URL, "claude-sonnet-4-5")
			wsTurn()
			gatePost(t, f, gateOp(source, 0, "aa5a2fcf-069b-4dd0-a0db-51f676dc805c", "owner-a", "pause"), 200)
			before := aSends.Load()
			beforeB := bSends.Load()
			send(false)
			send(true)
			wsTurn()
			if aSends.Load() != before || bSends.Load() != beforeB+3 {
				t.Fatalf("new A after ACK A=%d->%d B=%d->%d", before, aSends.Load(), beforeB, bSends.Load())
			}
			failB.Store(true)
			r, err := http.Post(downstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"claude-sonnet-4-5","messages":[{"role":"user","content":"synthetic"}]}`))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(r.Body)
			r.Body.Close()
			if r.StatusCode != 502 || !bytes.Contains(body, []byte("CONTROLLED-B-FAIL")) {
				t.Fatalf("A denial contaminated actual B error %d: %s", r.StatusCode, body)
			}
			for _, a := range f.manager.List() {
				if a.Attributes["api_key"] == "SYNTHETIC-A" && (a.LastError != nil || a.Quota.Exceeded) {
					t.Fatal("gate denial poisoned paused A health/quota")
				}
			}

		})
	}
}

func TestInferenceGateAdminBoundaryAndSafeErrors(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	s := gateSource(t, f)
	for _, tc := range []struct {
		method, path, token, body string
		want                      int
	}{
		{"GET", "inference-gates", "", "", 401},
		{"POST", "inference-gates/operations", "", "{}", 401},
		{"POST", "inference-gates/eligibility", "", "{}", 401},
		{"POST", "inference-gates/continuity", "", "{}", 401},
		{"POST", "inference-gates/continuity", "test-password", `{"secret":"SECRET-CANARY-NOT-RETURNED"}`, 400},
		{"GET", "inference-gates/operations/not-present", "test-password", "", 404},
		{"POST", "inference-gates/operations", "test-password", `{"secret":"SECRET-CANARY-NOT-RETURNED"}`, 400},
	} {
		req := httptest.NewRequest(tc.method, "/v8/management/"+tc.path, strings.NewReader(tc.body))
		req.RemoteAddr = "127.0.0.1:1234"
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		req.Header.Set("X-Inference-Gate-Bypass", "true")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" || bytes.Contains(w.Body.Bytes(), []byte("SECRET-CANARY")) {
			t.Errorf("admin/safe error %s %s: status=%d cache=%q", tc.method, tc.path, w.Code, w.Header().Get("Cache-Control"))
		}
	}
	op := gateOp(s, 0, "d218391e-8d75-4dbc-ab24-6a9ff95b95d1", "owner-a", "pause")
	op["model"] = "specific-model"
	gatePost(t, f, op, 422)
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if state.Revision != 0 || len(state.Gates) != 0 {
		t.Fatal("rejected model-scoped operation widened to credential pause")
	}
}

func TestInferenceGatePublicationFailuresNoAppliedACK(t *testing.T) {
	for _, stage := range []string{"journal", "invalid-anchor"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			f := newInventoryHarness(t, dir)
			s := gateSource(t, f)
			block := filepath.Join(dir, ".resource-catalog", "journal.json")
			if stage == "invalid-anchor" {
				block = filepath.Join(dir, "config.yaml.gate-floor-v1")
			}
			if err := os.Mkdir(block, 0700); err != nil {
				t.Fatal(err)
			}
			op := gateOp(s, 0, "02f5b936-1e6d-412a-bb26-40275c3a15ee", "owner-a", "pause")
			body := gatePost(t, f, op, 503)
			if bytes.Contains(body, []byte(`"applied":true`)) {
				t.Fatal("publication failure acknowledged applied")
			}
			f.request("inference-gates", 503)
			egress := &gateEgressCounter{}
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", egress)
			a := f.manager.List()[0]
			_, err := f.manager.VerifyInference(ctx, a.ID, "gate-model")
			if !coreexecutor.IsInferenceAdmissionError(err) || egress.calls.Load() != 0 {
				t.Fatal("failed publication allowed business send")
			}
			f.close()
			if err := os.Remove(block); err != nil {
				t.Fatal(err)
			}
			f = newInventoryHarness(t, dir)

			var state resource.GateState
			json.Unmarshal(f.request("inference-gates", 200), &state)
			if state.Revision != 0 {
				t.Fatal("operation rejected before durable publication invented a receipt")
			}

		})
	}
}

// Selection is deliberately A-first; real executors and transports remain unchanged.
type gatePreferASelector struct{ key string }

func (selector *gatePreferASelector) Pick(_ context.Context, _, _ string, _ coreexecutor.Options, auths []*coreauth.Auth) (*coreauth.Auth, error) {
	for _, a := range auths {
		if key := selector.key; (key != "" && a.Attributes["api_key"] == key) || (key == "" && a.Attributes["api_key"] == "SYNTHETIC-A") {
			return a, nil
		}
	}
	if len(auths) > 0 {
		return auths[0], nil
	}
	return nil, errors.New("no candidate")
}

func TestInferenceGateActual401RefreshRetryRechecksAfterACK(t *testing.T) {
	for _, mode := range []string{"http", "sse-setup", "sse-bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			stream := mode != "http"
			tokenEntered, releaseToken := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-releaseToken:
				default:
					close(releaseToken)
				}
			}()
			var sends atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/oauth/token" {
					close(tokenEntered)
					<-releaseToken
					fmt.Fprint(w, `{"access_token":"ROTATED-SYNTHETIC","refresh_token":"ROTATED-GRANT","token_type":"Bearer","expires_in":3600}`)
					return
				}
				if !strings.HasSuffix(r.URL.Path, "/responses") {
					t.Errorf("unexpected controlled upstream path %s", r.URL.Path)
					w.WriteHeader(404)
					return
				}
				sends.Add(1)
				if mode == "sse-bootstrap" {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"type\":\"authentication_error\",\"code\":\"invalid_api_key\",\"message\":\"controlled bootstrap401\"}}}\n\n")
					return
				}
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":{"message":"controlled refresh required","type":"invalid_api_key"}}`)
			}))
			defer upstream.Close()
			tr := upstream.Client().Transport.(*http.Transport).Clone()
			tr.TLSClientConfig.ServerName = upstream.Certificate().DNSNames[0]
			tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			}
			original := http.DefaultTransport
			http.DefaultTransport = tr
			defer func() { http.DefaultTransport = original; tr.CloseIdleConnections() }()
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			os.MkdirAll(authDir, 0700)
			os.WriteFile(filepath.Join(authDir, "oauth.json"), []byte(`{"type":"codex","access_token":"INITIAL-SYNTHETIC","refresh_token":"INITIAL-GRANT","account_id":"synthetic-account","expired":"2099-01-01T00:00:00Z"}`), 0600)
			text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\n", filepath.ToSlash(authDir))
			os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600)
			f := newInventoryHarness(t, dir)
			f.manager.SetConfig(f.server.cfg)
			f.manager.SetRoundTripperProvider(gateFixedTransport{tr})
			f.manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(f.server.cfg))
			for _, a := range f.manager.List() {
				registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "gate-model"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
			}
			source := gateSource(t, f)
			h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.POST("/v1/responses", func(c *gin.Context) {
				c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "cliproxy.roundtripper", tr))
				h.Responses(c)
			})
			downstream := httptest.NewServer(f.server.engine)
			defer downstream.Close()
			done := make(chan error, 1)
			go func() {
				client := &http.Client{Transport: &http.Transport{}}
				defer client.CloseIdleConnections()
				r, err := client.Post(downstream.URL+"/v1/responses", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"gate-model","input":[],"stream":%t}`, stream)))
				if err == nil {
					io.Copy(io.Discard, r.Body)
					r.Body.Close()
				}
				done <- err
			}()
			select {
			case <-tokenEntered:
			case err := <-done:
				t.Fatalf("no actual 401 refresh: %v", err)
			case <-time.After(8 * time.Second):
				t.Fatal("401 refresh barrier not reached")
			}
			if sends.Load() != 1 {
				t.Fatalf("token barrier was not actual inference 401: sends=%d", sends.Load())
			}
			gatePost(t, f, gateOp(source, 0, "a887072f-0b49-4f2d-9c9f-7d0cf5c4a309", "owner-a", "pause"), 200)
			close(releaseToken)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("gated retry did not settle")
			}
			if sends.Load() != 1 {
				t.Fatalf("same-auth 401 refresh retry bypassed ACK: %d sends", sends.Load())
			}
			var state resource.GateState
			json.Unmarshal(f.request("inference-gates", 200), &state)
			if len(state.Gates) != 1 || state.Gates[0].Applicability != "current" {
				t.Fatal("refresh lost owner continuity")
			}
		})
	}
}

type gateFixedTransport struct{ rt http.RoundTripper }

func (p gateFixedTransport) RoundTripperFor(*coreauth.Auth) http.RoundTripper { return p.rt }

func TestInferenceGateConcurrentCASAndBindingFences(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	s := gateSource(t, f)
	start := make(chan struct{})
	done := make(chan int, 2)
	for i, id := range []string{"dbe65fb7-1a87-49ec-a2eb-ab8e9f6603fa", "d48a1a53-a95d-4a41-978c-af83acf594a0"} {
		op := gateOp(s, 0, id, fmt.Sprintf("owner-%d", i), "pause")
		go func() {
			<-start
			raw, _ := json.Marshal(op)
			req := httptest.NewRequest("POST", "/v8/management/inference-gates/operations", bytes.NewReader(raw))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Authorization", "Bearer test-password")
			w := httptest.NewRecorder()
			f.server.engine.ServeHTTP(w, req)
			done <- w.Code
		}()
	}
	close(start)
	a, b := <-done, <-done
	if !((a == 200 && b == 409) || (a == 409 && b == 200)) {
		t.Fatalf("concurrent CAS=%d,%d", a, b)
	}
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if state.Revision != 1 || len(state.Gates) != 1 {
		t.Fatal("concurrent CAS published more than one revision")
	}
	for _, field := range []string{"scope", "targets", "auth_index", "sourceVersion"} {
		op := gateOp(s, 1, "f32c972f-a9e9-4128-b3f1-63c52d11adae", "owner-x", "clear")
		switch field {
		case "scope":
			op[field] = resource.Version{}
		case "targets":
			op[field] = []resource.Target{}
		case "auth_index":
			op[field] = "not-current"
		case "sourceVersion":
			op[field] = strings.Repeat("b", 64)
		}
		want := 409
		if field == "targets" {
			want = 400
		}
		gatePost(t, f, op, want)
	}
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if state.Revision != 1 || len(state.Gates) != 1 {
		t.Fatal("old/missing authority cleared current owner")
	}
}

func TestInferenceGateActualModelPoolRetryAndFailover(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var aSends, bSends atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				var body struct {
					Stream bool `json:"stream"`
				}
				json.Unmarshal(raw, &body)
				if r.Header.Get("Authorization") == "Bearer SYNTHETIC-A" {
					if aSends.Add(1) == 1 {
						close(entered)
						<-release
					}
					w.WriteHeader(500)
					fmt.Fprint(w, `{"error":{"message":"controlled pool failure"}}`)
					return
				}
				bSends.Add(1)
				if body.Stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
				} else {
					fmt.Fprint(w, `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
				}
			}))
			defer upstream.Close()
			dir := t.TempDir()
			os.MkdirAll(filepath.Join(dir, "auth"), 0700)
			text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  openai-compatibility:\n    - name: gate-pool\n      base-url: %q\n      models: [{name: actual-one, alias: route-model}, {name: actual-two, alias: route-model}]\n      keys: [{api-key: SYNTHETIC-A}, {api-key: SYNTHETIC-B}]\n", filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL+"/v1")
			os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600)
			f := newInventoryHarness(t, dir)
			f.manager.SetConfig(f.server.cfg)
			f.manager.SetSelector(&gatePreferASelector{})
			var source map[string]any
			var view struct {
				Sources []map[string]any `json:"sources"`
			}
			json.Unmarshal(f.request("credential-quota/sources", 200), &view)
			for _, a := range f.manager.List() {
				f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
				registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "route-model"}, {ID: "actual-one"}, {ID: "actual-two"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
				if a.Attributes["api_key"] == "SYNTHETIC-A" {
					for _, s := range view.Sources {
						if s["auth_index"] == a.Index {
							source = s
						}
					}
				}
			}
			if source == nil {
				t.Fatal("pool source not bound")
			}
			h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
			f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
			downstream := httptest.NewServer(f.server.engine)
			defer downstream.Close()
			done := make(chan error, 1)
			go func() {
				r, err := http.Post(downstream.URL+"/v1/chat/completions", "application/json", strings.NewReader(fmt.Sprintf(`{"model":"route-model","messages":[{"role":"user","content":"synthetic"}],"stream":%t}`, stream)))
				if err == nil {
					body, _ := io.ReadAll(r.Body)
					r.Body.Close()
					if r.StatusCode != 200 || !bytes.Contains(body, []byte("ok")) {
						err = fmt.Errorf("pool failover status=%d", r.StatusCode)
					}
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(6 * time.Second):
				t.Fatal("pool first actual send missing")
			}
			gatePost(t, f, gateOp(source, 0, "7d8841e4-d6d7-4a7c-9855-c41397099711", "owner-a", "pause"), 200)
			close(release)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("pool fallback did not settle")
			}
			if aSends.Load() != 1 || bSends.Load() != 1 {
				t.Fatalf("pool retry/failover A=%d B=%d", aSends.Load(), bSends.Load())
			}
		})
	}
}

func TestInferenceGateHealthyRefreshContinuityReadSurvivesRestartAndRejectsReplacement(t *testing.T) {
	runHealthyRefreshContinuity(t, false)
}

func TestInferenceGateRefreshContinuityAcrossPriorityEdits(t *testing.T) {
	runHealthyRefreshContinuity(t, true)
}

func runHealthyRefreshContinuity(t *testing.T, editPriority bool) {
	var rotations atomic.Int32
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Error("refresh escaped controlled token endpoint")
			w.WriteHeader(404)
			return
		}
		n := rotations.Add(1)
		fmt.Fprintf(w, `{"access_token":"ROTATED-%d","refresh_token":"GRANT-%d","token_type":"Bearer","expires_in":3600}`, n, n)
	}))
	defer tokenServer.Close()
	tr := tokenServer.Client().Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.ServerName = tokenServer.Certificate().DNSNames[0]
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, tokenServer.Listener.Addr().String())
	}
	original := http.DefaultTransport
	http.DefaultTransport = tr
	defer func() { http.DefaultTransport = original; tr.CloseIdleConnections() }()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	os.MkdirAll(authDir, 0700)
	os.WriteFile(filepath.Join(authDir, "oauth.json"), []byte(fmt.Sprintf(`{"type":"codex","access_token":"INITIAL-SYNTHETIC","refresh_token":"INITIAL-GRANT","account_id":"synthetic-account","id_token":%q,"expired":"2099-01-01T00:00:00Z"}`, "a."+base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"controlled-issuer","sub":"controlled-subject","https://api.openai.com/auth":{"chatgpt_account_id":"synthetic-account"}}`))+".b")), 0600)
	f := newInventoryHarness(t, dir)
	installGateFixtureExecutors(f)
	previous := quotaSourceFor(t, f, "codex-oauth-wham")
	if len(previous.Targets) != 1 {
		t.Fatal("expected one issued native subject")
	}
	resourceID := previous.Targets[0].ResourceID
	selectedSource := func() resource.QuotaSource {
		t.Helper()
		var view struct {
			Sources []resource.QuotaSource `json:"sources"`
		}
		if err := json.Unmarshal(f.request("credential-quota/sources", 200), &view); err != nil {
			t.Fatal(err)
		}
		selected, ok := inferenceGateSourceByIssuedResource(view.Sources, "codex-oauth-wham", resourceID)
		if !ok {
			t.Fatal("original issued native subject unavailable or ambiguous")
		}
		return selected
	}
	var id string
	for _, a := range f.manager.List() {
		if a.Index == previous.AuthIndex {
			if filepath.Clean(a.Attributes[coreauth.AttributePath]) != filepath.Join(authDir, "oauth.json") {
				t.Fatal("initial source is not the enrolled OAuth fixture")
			}
			id = a.ID
		}
	}
	if id == "" {
		t.Fatal("missing selected native auth")
	}
	query := func(prev resource.Binding, current resource.QuotaSource, want int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(map[string]any{"version": 1, "previous": prev, "current": current.Binding, "auth_index": current.AuthIndex, "sourceVersion": current.SourceVersion})
		req := httptest.NewRequest("POST", "/v8/management/inference-gates/continuity", bytes.NewReader(raw))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("continuity status=%d want=%d body=%s", w.Code, want, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("continuity cacheable")
		}
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	// An unrelated publication can advance ephemeral global scope while the
	// intent still references the same complete durable target tuple.
	if err := os.WriteFile(filepath.Join(authDir, "unrelated.json"), []byte(`{"type":"codex","access_token":"UNRELATED-SYNTHETIC"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	interim := selectedSource()
	if interim.Scope == previous.Scope || !reflect.DeepEqual(interim.Targets, previous.Targets) {
		t.Fatal("unrelated publication did not preserve target tuple while advancing scope")
	}
	patchPriority := func(raw string) {
		t.Helper()
		req := httptest.NewRequest("PATCH", "/v8/management/credentials/fields", strings.NewReader(raw))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		w := httptest.NewRecorder()
		f.server.engine.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("priority update failed: status=%d", w.Code)
		}
	}
	if editPriority {
		patchPriority(`{"name":"oauth.json","priority":210}`)
		changed := selectedSource()
		if changed.Targets[0].ConfigVersion <= previous.Targets[0].ConfigVersion || changed.Targets[0].Incarnation != previous.Targets[0].Incarnation {
			t.Fatal("priority edit did not preserve the native credential lifecycle")
		}
		if out := query(previous.Binding, changed, 200); out["proven"] != false {
			t.Fatal("priority edit alone invented a native grant certificate")
		}
	}
	for range 2 {
		if _, err := f.manager.ForceRefreshAuth(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if editPriority {
		patchPriority(`{"name":"oauth.json","priority":220}`)
	}
	current := selectedSource()
	if reflect.DeepEqual(previous.Targets, current.Targets) {
		t.Fatal("fixture did not rotate issued target versions")
	}
	if out := query(previous.Binding, current, 200); out["proven"] != true || out["kind"] != "native_oauth_refresh" {
		t.Fatal("healthy no-pause rotations have no certified intent continuation")
	}
	if rotations.Load() != 2 {
		t.Fatal("controlled native grants were not both executed")
	}
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if len(state.Gates) != 0 {
		t.Fatal("healthy continuity invented a quota pause")
	}
	f.close()
	f = newInventoryHarness(t, dir)
	installGateFixtureExecutors(f)
	current = selectedSource()
	// The unrelated OAuth record must remain present. Use both real source
	// permutations to prove subject selection is independent of map/list order.
	var restartSources struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &restartSources); err != nil {
		t.Fatal(err)
	}
	var unrelated resource.QuotaSource
	count := 0
	for _, candidate := range restartSources.Sources {
		if candidate.Protocol != "codex-oauth-wham" {
			continue
		}
		count++
		if len(candidate.Targets) == 1 && candidate.Targets[0].ResourceID != resourceID {
			unrelated = candidate
		}
	}
	if count != 2 || unrelated.AuthIndex == "" {
		t.Fatal("unrelated OAuth record was not loaded alongside selected subject")
	}
	for _, order := range [][]resource.QuotaSource{{current, unrelated}, {unrelated, current}} {
		selected, ok := inferenceGateSourceByIssuedResource(order, "codex-oauth-wham", resourceID)
		if !ok || !reflect.DeepEqual(selected, current) {
			t.Fatal("issued-subject lookup depends on source list order")
		}
		if out := query(previous.Binding, selected, 200); out["proven"] != true {
			t.Fatal("ordered source lookup lost exact selected refresh chain")
		}
	}
	if _, ok := inferenceGateSourceByIssuedResource([]resource.QuotaSource{current, current}, "codex-oauth-wham", resourceID); ok {
		t.Fatal("duplicate source subject accepted")
	}
	if out := query(previous.Binding, unrelated, 200); out["proven"] != false {
		t.Fatal("selected refresh chain incorrectly certifies unrelated OAuth record")
	}
	t.Logf("RESTART_SELECTED_RESOURCE resource=%s unrelated_resource=%s both_orders_verified=true", resourceID, unrelated.Targets[0].ResourceID)
	if out := query(previous.Binding, current, 200); out["proven"] != true {
		t.Fatal("restart lost durable exact refresh chain")
	}
	var a *coreauth.Auth
	for _, candidate := range f.manager.List() {
		if candidate.Index == current.AuthIndex {
			a = candidate
		}
	}
	a.Metadata["access_token"] = "REPLACEMENT-SYNTHETIC"
	a.Metadata["account_id"] = "different-account"
	if _, err := f.manager.Storage().Save(coreauth.WithAuthCreationIntent(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.Update(coreauth.WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	replaced := selectedSource()
	if out := query(previous.Binding, replaced, 200); out["proven"] != false || out["kind"] != "" {
		t.Fatal("account replacement borrowed native refresh continuity")
	}
	query(previous.Binding, current, 409)
}

// inferenceGateSourceByIssuedResource is test-only selection of one exact native
// subject from genuine public API sources. Protocol labels and list order alone
// cannot identify a selected credential after another OAuth source is loaded.
func inferenceGateSourceByIssuedResource(sources []resource.QuotaSource, protocol, resourceID string) (resource.QuotaSource, bool) {
	var selected resource.QuotaSource
	count := 0
	for _, source := range sources {
		if source.Protocol == protocol && source.AuthIndex != "" && len(source.Targets) == 1 && source.Targets[0].ResourceID == resourceID {
			selected = source
			count++
		}
	}
	return selected, resourceID != "" && count == 1
}

func readGateContinuity(t *testing.T, f *inventoryHarness, previous resource.Binding, current resource.QuotaSource) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"version": 1, "previous": previous, "current": current.Binding, "auth_index": current.AuthIndex, "sourceVersion": current.SourceVersion})
	req := httptest.NewRequest("POST", "/v8/management/inference-gates/continuity", bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("continuity status=%d", w.Code)
	}
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestInferenceGateActualVerify501FallbackRechecksAfterACK(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var sends atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sends.Add(1) == 1 {
			close(entered)
			<-release
		}
		w.WriteHeader(501)
		fmt.Fprint(w, `{"error":{"message":"controlled stream not implemented"}}`)
	}))
	defer upstream.Close()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "auth"), 0700)
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  openai-compatibility:\n    - name: gate-verify\n      base-url: %q\n      keys: [{api-key: SYNTHETIC-A}]\n", filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL+"/v1")
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600)
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	a := f.manager.List()[0]
	f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
	source := gateSource(t, f)
	done := make(chan error, 1)
	go func() { _, err := f.manager.VerifyInference(context.Background(), a.ID, "gate-model"); done <- err }()
	select {
	case <-entered:
	case <-time.After(6 * time.Second):
		t.Fatal("actual VerifyInference stream did not reach upstream")
	}
	gatePost(t, f, gateOp(source, 0, "cf01bd74-75a1-4311-b4a9-cc09446824d7", "owner-a", "pause"), 200)
	close(release)
	select {
	case err := <-done:
		if !coreexecutor.IsInferenceAdmissionError(err) {
			t.Fatalf("501 fallback did not return gate denial: %T", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("501 fallback did not settle")
	}
	if sends.Load() != 1 {
		t.Fatalf("501 fallback reused old admission: sends=%d", sends.Load())
	}
}

func TestInferenceGateNativeRefreshAccountDisagreementIsNotContinuity(t *testing.T) {
	for _, paused := range []bool{false, true} {
		t.Run(fmt.Sprintf("paused=%v", paused), func(t *testing.T) {
			token := func(account string) string {
				raw, _ := json.Marshal(map[string]any{"iss": "controlled-issuer", "sub": "controlled-subject", "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": account}})
				return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(raw) + ".synthetic"
			}
			tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/oauth/token" {
					t.Error("wrong controlled refresh path")
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"access_token": "ROTATED-SYNTHETIC", "refresh_token": "ROTATED-GRANT", "id_token": token("DIFFERENT-ACCOUNT"), "expires_in": 3600})
			}))
			defer tokenServer.Close()
			tr := tokenServer.Client().Transport.(*http.Transport).Clone()
			tr.TLSClientConfig.ServerName = tokenServer.Certificate().DNSNames[0]
			tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, tokenServer.Listener.Addr().String())
			}
			original := http.DefaultTransport
			http.DefaultTransport = tr
			defer func() { http.DefaultTransport = original; tr.CloseIdleConnections() }()
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			os.MkdirAll(authDir, 0700)
			raw, _ := json.Marshal(map[string]any{"type": "codex", "access_token": "INITIAL-SYNTHETIC", "refresh_token": "INITIAL-GRANT", "account_id": "ORIGINAL-ACCOUNT", "id_token": token("ORIGINAL-ACCOUNT"), "expired": "2099-01-01T00:00:00Z"})
			os.WriteFile(filepath.Join(authDir, "oauth.json"), raw, 0600)
			f := newInventoryHarness(t, dir)
			installGateFixtureExecutors(f)
			previous := quotaSourceFor(t, f, "codex-oauth-wham")
			var id string
			for _, a := range f.manager.List() {
				if a.Index == previous.AuthIndex {
					id = a.ID
				}
			}
			if paused {
				var source map[string]any
				raw, _ = json.Marshal(previous)
				json.Unmarshal(raw, &source)
				gatePost(t, f, gateOp(source, 0, "b3d32b46-27db-4f7a-8e22-7d47c02acfe6", "owner-a", "pause"), 200)
			}
			if _, err := f.manager.ForceRefreshAuth(context.Background(), id); err != nil {
				t.Fatal(err)
			}
			current := quotaSourceFor(t, f, "codex-oauth-wham")
			if out := readGateContinuity(t, f, previous.Binding, current); out["proven"] != false {
				t.Fatal("successful refresh with explicit account disagreement falsely certified continuation")
			}
			var state resource.GateState
			json.Unmarshal(f.request("inference-gates", 200), &state)
			if paused && (len(state.Gates) != 1 || state.Gates[0].Applicability != "reconciliation_required" || reflect.DeepEqual(state.Gates[0].Targets, current.Targets)) {
				t.Fatal("old-account pause carried into different token-response account")
			}
		})
	}
}

func TestInferenceGateRevisionConflictIsTypedOnlyForCurrentAuthority(t *testing.T) {
	f := newInventoryHarness(t, t.TempDir())
	source := gateSource(t, f)
	gatePost(t, f, gateOp(source, 0, "8c974e88-9fc6-4ea3-983b-4dcedd0374c4", "owner-a", "pause"), 200)
	conflict := gateOp(source, 0, "60c7983f-74b2-41e4-a21a-32575fa1a932", "owner-b", "pause")
	raw := gatePost(t, f, conflict, 409)
	var reply map[string]any
	json.Unmarshal(raw, &reply)
	if reply["error"] != "gate_conflict" || reply["conflict"] != "gate_revision" {
		t.Fatal("current-binding revision-only conflict lacks safe typed reason")
	}
	f.request("inference-gates/operations/60c7983f-74b2-41e4-a21a-32575fa1a932", 404)
	conflict["scope"] = resource.Version{}
	raw = gatePost(t, f, conflict, 409)
	json.Unmarshal(raw, &reply)
	if bytes.Contains(raw, []byte("gate_revision")) {
		t.Fatal("binding failure mislabeled revision-only")
	}
	var state resource.GateState
	json.Unmarshal(f.request("inference-gates", 200), &state)
	if state.Revision != 1 || len(state.Gates) != 1 {
		t.Fatal("CAS rejection durably created successor operation")
	}
}
