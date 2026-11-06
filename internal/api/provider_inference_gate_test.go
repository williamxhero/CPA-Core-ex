package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	gjson "github.com/MoeForge/moego/ojson"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

type providerGateEligibility struct {
	resource.Binding
	Version       int    `json:"version"`
	SourceVersion string `json:"sourceVersion"`
	Ready         bool   `json:"ready"`
	Supported     bool   `json:"supported"`
	Reason        string `json:"reason"`
	Authority     string `json:"authority"`
	Members       []struct {
		resource.Binding
		AuthIndex     string `json:"auth_index"`
		SourceVersion string `json:"sourceVersion"`
	} `json:"members"`
}

type providerGateFixture struct {
	f     *inventoryHarness
	mu    sync.Mutex
	sends map[string]int
	url   string
}

func newProviderGateFixture(t *testing.T) *providerGateFixture {
	return newProviderGateStreamFixture(t, nil, nil)
}

func newProviderGateStreamFixture(t *testing.T, entered chan<- struct{}, release <-chan struct{}) *providerGateFixture {
	t.Helper()
	x := &providerGateFixture{sends: make(map[string]int)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.mu.Lock()
		x.sends[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]++
		x.mu.Unlock()
		var body struct {
			Stream bool `json:"stream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("controlled upstream body: %v", err)
		}
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":null}]}\n\n")
			if entered != nil && r.Header.Get("Authorization") == "Bearer SYNTHETIC-A1" {
				w.(http.Flusher).Flush()
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			fmt.Fprint(w, "data: {\"id\":\"x\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(upstream.Close)
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("server: {port: 0}\nmanagement: {secret-key: test-password}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  openai-compatibility:\n    - name: provider-a\n      base-url: %q\n      keys: [{api-key: SYNTHETIC-A1}, {api-key: SYNTHETIC-A2}]\n    - name: provider-b\n      base-url: %q\n      keys: [{api-key: SYNTHETIC-B1}, {api-key: SYNTHETIC-B2}]\n", filepath.ToSlash(authDir), upstream.URL+"/v1", upstream.URL+"/v1")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	x.f = newInventoryHarness(t, dir)
	x.startRuntime(t)
	return x
}

func (x *providerGateFixture) startRuntime(t *testing.T) {
	t.Helper()
	x.f.manager.SetConfig(x.f.server.cfg)
	for _, a := range x.f.manager.List() {
		x.f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, x.f.server.cfg))
		model := "provider-b-model"
		if strings.HasPrefix(a.Attributes["api_key"], "SYNTHETIC-A") {
			model = "provider-a-model"
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: model}})
		id := a.ID
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&x.f.server.cfg.SDKConfig, x.f.manager))
	x.f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
	rh := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&x.f.server.cfg.SDKConfig, x.f.manager))
	x.f.server.engine.GET("/v1/responses", rh.ResponsesWebsocket)
	downstream := httptest.NewServer(x.f.server.engine)
	t.Cleanup(downstream.Close)
	x.url = downstream.URL
}

func (x *providerGateFixture) send(t *testing.T, model, key string, stream bool, allowed bool) {
	t.Helper()
	x.f.manager.SetSelector(&gatePreferASelector{key: key})
	c := &http.Client{Timeout: 10 * time.Second}
	r, err := c.Post(x.url+"/v1/chat/completions", "application/json", strings.NewReader(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"synthetic"}],"stream":%t}`, model, stream)))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if allowed && (r.StatusCode != 200 || !bytes.Contains(body, []byte("ok"))) {
		t.Fatalf("allowed actual request status=%d body=%s", r.StatusCode, body)
	}
	if !allowed && r.StatusCode < 400 {
		t.Fatalf("paused actual request not rejected: %d %s", r.StatusCode, body)
	}
}

func providerOperation(t *testing.T, f *inventoryHarness, e providerGateEligibility, revision uint64, owner, action string) resource.GateResult {
	t.Helper()
	op := resource.GateOperation{Version: 1, OpID: uuid.NewString(), Binding: e.Binding,
		ExpectedRevision: revision, Subject: "provider", SourceVersion: e.SourceVersion, Owner: owner,
		Action: action, Reason: "low_balance", EvidenceID: "controlled-money-observation"}
	var result resource.GateResult
	if err := json.Unmarshal(providerGatePost(t, f, "inference-gates/operations", op, 200), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Durable || !result.Applied || result.AppliedRevision == 0 {
		t.Fatal("provider restriction was not durably acknowledged")
	}
	return result
}

func (x *providerGateFixture) binding(t *testing.T, key string) resource.Binding {
	t.Helper()
	snapshot := x.f.snapshot()
	parent := ""
	for _, a := range x.f.manager.List() {
		if a.Attributes["api_key"] == key {
			parent = a.Attributes[coreauth.AttributeProviderResourceID]
		}
	}
	if parent == "" {
		t.Fatal("missing issued parent for controlled actual runtime key")
	}
	var root resource.Target
	children := []resource.Target{}
	for _, row := range snapshot.Resources {
		if row.ResourceID == parent && row.Kind == "provider" {
			root = row.Target
		}
		if row.ParentID == parent && row.Kind == "credential" {
			children = append(children, row.Target)
		}
	}
	sort.Slice(children, func(i, j int) bool { return children[i].ResourceID < children[j].ResourceID })
	if root.ResourceID == "" || len(children) < 2 {
		t.Fatal("fixture must contain complete multi-member provider")
	}
	return resource.Binding{Scope: snapshot.Version, Targets: append([]resource.Target{root}, children...)}
}

func providerGatePost(t *testing.T, f *inventoryHarness, route string, body any, want int) []byte {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v8/management/"+route, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("%s status=%d want=%d body=%s", route, w.Code, want, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("provider gate management result must not be cached")
	}
	return w.Body.Bytes()
}

func providerEligibility(t *testing.T, f *inventoryHarness, b resource.Binding) providerGateEligibility {
	t.Helper()
	var out providerGateEligibility
	if err := json.Unmarshal(providerGatePost(t, f, "inference-gates/providers/eligibility", struct {
		resource.Binding
		Version int    `json:"version"`
		Route   string `json:"route"`
	}{b, 1, "all-current-provider"}, 200), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProviderGateEligibilityUsesWholeCurrentProvider(t *testing.T) {
	x := newProviderGateFixture(t)
	b := x.binding(t, "SYNTHETIC-A1")
	got := providerEligibility(t, x.f, b)
	if !got.Ready || !got.Supported || got.SourceVersion == "" || len(got.Members) != 2 || got.Authority != "routing_only" {
		t.Fatalf("no whole-group route proof: %+v", got)
	}
	if !bytes.Equal(mustProviderJSON(t, got.Binding), mustProviderJSON(t, b)) {
		t.Fatal("eligibility changed issued group")
	}
	for _, member := range got.Members {
		if member.AuthIndex == "" || member.SourceVersion == "" || len(member.Targets) != 1 {
			t.Fatal("provider proof is not backed by each actual runtime member")
		}
	}
}

func mustProviderJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProviderGatePausesAllActualMembersWithoutAffectingB(t *testing.T) {
	x := newProviderGateFixture(t)
	eligible := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	if !eligible.Ready {
		t.Fatal("provider is not eligible")
	}
	for _, key := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2"} {
		x.send(t, "provider-a-model", key, false, true)
	}
	x.mu.Lock()
	beforeA := x.sends["SYNTHETIC-A1"] + x.sends["SYNTHETIC-A2"]
	x.mu.Unlock()
	providerOperation(t, x.f, eligible, 0, "provider-auto/v1", "pause")
	for _, key := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2"} {
		for _, stream := range []bool{false, true} {
			x.send(t, "provider-a-model", key, stream, false)
		}
	}
	for _, key := range []string{"SYNTHETIC-B1", "SYNTHETIC-B2"} {
		x.send(t, "provider-b-model", key, true, true)
	}
	var sources struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(x.f.request("credential-quota/sources", 200), &sources); err != nil {
		t.Fatal(err)
	}
	queried := false
	for _, source := range sources.Sources {
		if len(source.Targets) != 1 {
			continue
		}
		for _, member := range eligible.Members {
			if member.AuthIndex != source.AuthIndex {
				continue
			}
			q := resource.QuotaQuery{Binding: source.Binding, SourceVersion: source.SourceVersion, SourceID: source.SourceID, SubjectID: source.SubjectID, AuthIndex: source.AuthIndex}
			var obs resource.QuotaObservation
			if err := json.Unmarshal(providerGatePost(t, x.f, "credential-quota/query", q, 200), &obs); err != nil {
				t.Fatal(err)
			}
			if obs.QueryStatus != "unsupported" || obs.Complete || obs.RecoveryEligible {
				t.Fatal("unsupported balance query acquired invented monetary authority")
			}
			queried = true
		}
	}
	if !queried {
		t.Fatal("provider pause hid quota query authority")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sends["SYNTHETIC-A1"]+x.sends["SYNTHETIC-A2"] != beforeA || x.sends["SYNTHETIC-B1"]+x.sends["SYNTHETIC-B2"] != 2 {
		t.Fatal("provider A escaped or independent provider B was blocked")
	}
}

func TestProviderGateAdmittedSSEDrainsAfterPause(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	x := newProviderGateStreamFixture(t, entered, release)
	t.Cleanup(unblock)
	x.f.manager.SetSelector(&gatePreferASelector{key: "SYNTHETIC-A1"})
	c := &http.Client{Timeout: 10 * time.Second}
	r, err := c.Post(x.url+"/v1/chat/completions", "application/json", strings.NewReader(`{"model":"provider-a-model","messages":[{"role":"user","content":"synthetic"}],"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("initial stream did not reach controlled upstream")
	}
	e := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	providerOperation(t, x.f, e, 0, "provider-auto/v1", "pause")
	x.send(t, "provider-a-model", "SYNTHETIC-A2", false, false)
	unblock()
	body, err := io.ReadAll(r.Body)
	if err != nil || r.StatusCode != 200 || !bytes.Contains(body, []byte("ok")) || !bytes.Contains(body, []byte("[DONE]")) {
		t.Fatalf("admitted stream failed to drain: %d %s %v", r.StatusCode, body, err)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sends["SYNTHETIC-A1"] != 1 || x.sends["SYNTHETIC-A2"] != 0 {
		t.Fatal("pause replayed stream or admitted new member")
	}
}

func TestProviderGateReusedDownstreamWSChecksEveryTurn(t *testing.T) {
	x := newProviderGateFixture(t)
	connect := func(model, key string) func(bool) {
		t.Helper()
		c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(x.url, "http")+"/v1/responses", nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return func(allowed bool) {
			t.Helper()
			x.f.manager.SetSelector(&gatePreferASelector{key: key})
			_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
			body := fmt.Sprintf(`{"type":"response.create","model":%q,"input":[{"role":"user","content":"synthetic"}]}`, model)
			if err := c.WriteMessage(websocket.TextMessage, []byte(body)); err != nil {
				t.Fatal(err)
			}
			for {
				_, b, err := c.ReadMessage()
				if err != nil {
					// Existing downstream protocol silently closes terminal local
					// 503s. Require an actual close, not a test timeout; the
					// independent upstream counters below prove no business send.
					var closed *websocket.CloseError
					if !allowed && errors.As(err, &closed) && closed.Code == websocket.CloseAbnormalClosure {
						return
					}
					t.Fatal(err)
				}
				switch gjson.GetBytes(b, "type").String() {
				case "response.completed":
					if !allowed {
						t.Fatal("paused WS turn completed instead of rejecting")
					}
					return
				case "error", "response.failed":
					if allowed {
						t.Fatalf("allowed WS turn rejected: %s", b)
					}
					return
				}
			}
		}
	}
	a1 := connect("provider-a-model", "SYNTHETIC-A1")
	a2 := connect("provider-a-model", "SYNTHETIC-A2")
	b := connect("provider-b-model", "SYNTHETIC-B1")
	a1(true)
	a2(true)
	b(true)
	e := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	providerOperation(t, x.f, e, 0, "provider-auto/v1", "pause")
	a1(false)
	a2(false)
	b(true)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sends["SYNTHETIC-A1"] != 1 || x.sends["SYNTHETIC-A2"] != 1 || x.sends["SYNTHETIC-B1"] != 2 {
		t.Fatalf("reused WS bypass or B contamination: %v", x.sends)
	}
}

func TestProviderGateSafeAuthorityAndAdminBoundary(t *testing.T) {
	x := newProviderGateFixture(t)
	b := x.binding(t, "SYNTHETIC-A1")
	e := providerEligibility(t, x.f, b)
	permuted := b
	permuted.Targets = []resource.Target{b.Targets[2], b.Targets[0], b.Targets[1]}
	if p := providerEligibility(t, x.f, permuted); p.SourceVersion != e.SourceVersion {
		t.Fatal("complete target permutation changed route authority")
	}
	query := func(binding resource.Binding) any {
		return struct {
			resource.Binding
			Version int    `json:"version"`
			Route   string `json:"route"`
		}{binding, 1, "all-current-provider"}
	}
	partial := b
	partial.Targets = partial.Targets[:2]
	providerGatePost(t, x.f, "inference-gates/providers/eligibility", query(partial), 409)
	forged := b
	forged.Targets = append([]resource.Target(nil), b.Targets...)
	forged.Targets[1].CredentialVersion++
	providerGatePost(t, x.f, "inference-gates/providers/eligibility", query(forged), 409)
	op := resource.GateOperation{Version: 1, OpID: uuid.NewString(), Binding: e.Binding,
		Subject: "provider", SourceVersion: strings.Repeat("f", 64), Owner: "provider-auto/v1",
		Action: "pause", Reason: "low_balance", EvidenceID: "controlled"}
	providerGatePost(t, x.f, "inference-gates/operations", op, 409)
	op.SourceVersion, op.AuthIndex = e.SourceVersion, "forged-locator"
	providerGatePost(t, x.f, "inference-gates/operations", op, 400)
	for _, tc := range []struct {
		token, body string
		want        int
	}{
		{"", `{}`, 401},
		{"test-password", `{"secret":"CANARY-DO-NOT-ECHO"}`, 400},
	} {
		req := httptest.NewRequest("POST", "/v8/management/inference-gates/providers/eligibility", strings.NewReader(tc.body))
		req.RemoteAddr = "127.0.0.1:1234"
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		x.f.server.engine.ServeHTTP(w, req)
		if w.Code != tc.want || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "CANARY") {
			t.Fatalf("admin/safe response: %d %s", w.Code, w.Body.String())
		}
	}
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, true)
	// An unverified executor cannot make all-current-provider ready. A known
	// executor for the other member/provider is not transitive proof.
	for _, a := range x.f.manager.List() {
		if a.Attributes["api_key"] == "SYNTHETIC-A1" {
			x.f.manager.UnregisterExecutor(a.Provider)
		}
	}
	if p := providerEligibility(t, x.f, b); p.Ready || p.Supported {
		t.Fatal("missing executor was represented as complete route proof")
	}
	op.AuthIndex, op.SourceVersion, op.OpID = "", e.SourceVersion, uuid.NewString()
	providerGatePost(t, x.f, "inference-gates/operations", op, 409)
}

func TestProviderGateRestartMembershipChangeAndOwnReconciliation(t *testing.T) {
	x := newProviderGateFixture(t)
	initial := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	providerOperation(t, x.f, initial, 0, "provider-auto/v1", "pause")
	dir := x.f.dir
	x.f.close()
	x.f = newInventoryHarness(t, dir)
	x.startRuntime(t)
	next := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	if next.Scope.BootEpoch == initial.Scope.BootEpoch || next.Targets[0] != initial.Targets[0] {
		t.Fatal("restart did not preserve stable provider lifecycle with a new boot")
	}
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, false)
	x.send(t, "provider-b-model", "SYNTHETIC-B1", true, true)
	x.f.close()
	editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
		groups := testField(testField(root, "api-keys"), "openai-compatibility")
		var key yaml.Node
		if err := yaml.Unmarshal([]byte("{api-key: SYNTHETIC-A3}"), &key); err != nil {
			t.Fatal(err)
		}
		keys := testField(groups.Content[0], "keys")
		keys.Content = append(keys.Content, key.Content[0])
	})
	x.f = newInventoryHarness(t, dir)
	x.startRuntime(t)
	changed := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	if len(changed.Targets) != 4 || changed.Targets[0].MembershipVersion == next.Targets[0].MembershipVersion {
		t.Fatal("fixture failed to publish membership change")
	}
	for _, key := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2", "SYNTHETIC-A3"} {
		x.send(t, "provider-a-model", key, false, false)
	}
	x.send(t, "provider-b-model", "SYNTHETIC-B2", false, true)
	var state resource.GateState
	if err := json.Unmarshal(x.f.request("inference-gates", 200), &state); err != nil {
		t.Fatal(err)
	}
	if state.AllSourcesReady || len(state.Gates) != 1 || state.Gates[0].Applicability != "reconciliation_required" {
		t.Fatal("stale membership restriction was silently discarded or declared current")
	}
	stale := resource.GateOperation{Version: 1, OpID: uuid.NewString(), ExpectedRevision: 1, Binding: initial.Binding,
		Subject: "provider", SourceVersion: initial.SourceVersion, Owner: "provider-auto/v1", Action: "clear", Reason: "recovered", EvidenceID: "controlled-new"}
	providerGatePost(t, x.f, "inference-gates/operations", stale, 409)
	providerOperation(t, x.f, changed, 1, "provider-auto/v1", "clear")
	x.send(t, "provider-a-model", "SYNTHETIC-A3", true, true)
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sends["SYNTHETIC-A1"] != 0 || x.sends["SYNTHETIC-A2"] != 0 || x.sends["SYNTHETIC-A3"] != 1 {
		t.Fatalf("restart/member change allowed old pause escape: %v", x.sends)
	}
}

func TestProviderGateCASIdempotencyAndIndependentCredentialOwner(t *testing.T) {
	x := newProviderGateFixture(t)
	e := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	op := resource.GateOperation{Version: 1, OpID: uuid.NewString(), Binding: e.Binding,
		Subject: "provider", SourceVersion: e.SourceVersion, Owner: "provider-auto/v1", Action: "pause", Reason: "low_balance", EvidenceID: "controlled"}
	first := providerGatePost(t, x.f, "inference-gates/operations", op, 200)
	if repeat := providerGatePost(t, x.f, "inference-gates/operations", op, 200); !bytes.Equal(first, repeat) {
		t.Fatal("exact retry changed provider operation receipt")
	}
	op.Action = "clear"
	providerGatePost(t, x.f, "inference-gates/operations", op, 409)
	op.OpID = uuid.NewString()
	providerGatePost(t, x.f, "inference-gates/operations", op, 409)
	var member struct {
		resource.Binding
		AuthIndex     string `json:"auth_index"`
		SourceVersion string `json:"sourceVersion"`
	}
	// Use the actual credential source receipt; a provider routing receipt cannot
	// impersonate a credential authority or clear its independent owner.
	var sources struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(x.f.request("credential-quota/sources", 200), &sources); err != nil {
		t.Fatal(err)
	}
	keyTarget := ""
	for _, a := range x.f.manager.List() {
		if a.Attributes["api_key"] == "SYNTHETIC-A1" {
			keyTarget = a.ResourceIdentity.Targets[0].ResourceID
		}
	}
	for _, s := range sources.Sources {
		if len(s.Targets) == 1 && s.Targets[0].ResourceID == keyTarget {
			member.Binding, member.AuthIndex, member.SourceVersion = s.Binding, s.AuthIndex, s.SourceVersion
		}
	}
	if member.AuthIndex == "" {
		t.Fatal("missing actual credential source")
	}
	credential := resource.GateOperation{Version: 1, OpID: uuid.NewString(), ExpectedRevision: 1, Binding: member.Binding,
		Subject: "credential", AuthIndex: member.AuthIndex, SourceVersion: member.SourceVersion,
		Owner: "credential-auto/v1", Action: "pause", Reason: "quota_exhausted", EvidenceID: "controlled-credential"}
	providerGatePost(t, x.f, "inference-gates/operations", credential, 200)
	providerOperation(t, x.f, e, 2, "independent-owner", "pause")
	providerOperation(t, x.f, e, 3, "provider-auto/v1", "clear")
	x.send(t, "provider-a-model", "SYNTHETIC-A2", false, false)
	providerOperation(t, x.f, e, 4, "independent-owner", "clear")
	x.send(t, "provider-a-model", "SYNTHETIC-A2", false, true)
	var state resource.GateState
	if err := json.Unmarshal(x.f.request("inference-gates", 200), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Gates) != 1 || state.Gates[0].Owner != "credential-auto/v1" || state.Gates[0].Targets[0].ResourceID != keyTarget {
		t.Fatal("provider clear removed or changed independent credential restriction")
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.sends["SYNTHETIC-A1"] != 0 || x.sends["SYNTHETIC-A2"] != 1 {
		t.Fatalf("provider recovery bypassed credential restriction: %v", x.sends)
	}
}

func TestProviderGateManualDisableRequiresReconciliationWithoutImplicitRecovery(t *testing.T) {
	x := newProviderGateFixture(t)
	e := providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	providerOperation(t, x.f, e, 0, "provider-auto/v1", "pause")
	dir := x.f.dir
	reloadDisabled := func(disabled bool) {
		t.Helper()
		x.f.close()
		editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
			groups := testField(testField(root, "api-keys"), "openai-compatibility")
			group := groups.Content[0]
			for i := 0; i+1 < len(group.Content); i += 2 {
				if group.Content[i].Value == "disabled" {
					group.Content[i+1].Value = fmt.Sprint(disabled)
					return
				}
			}
			group.Content = append(group.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "disabled"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(disabled)})
		})
		x.f = newInventoryHarness(t, dir)
		x.startRuntime(t)
	}
	reloadDisabled(true)
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, false)
	snapshot := x.f.snapshot()
	current := resource.Binding{Scope: snapshot.Version}
	for _, row := range snapshot.Resources {
		if row.ResourceID == e.Targets[0].ResourceID {
			if !row.Manual.Disabled {
				t.Fatal("provider pause changed manual disable")
			}
			current.Targets = append(current.Targets, row.Target)
		}
	}
	for _, row := range snapshot.Resources {
		if row.ParentID == e.Targets[0].ResourceID {
			current.Targets = append(current.Targets, row.Target)
		}
	}
	// Disabled compatibility providers intentionally have no runtime auths.
	// Do not invent route authority from configuration-only identities to ACK
	// a clear. The consumer must show pending/unavailable until reconciled.
	query := struct {
		resource.Binding
		Version int    `json:"version"`
		Route   string `json:"route"`
	}{current, 1, "all-current-provider"}
	providerGatePost(t, x.f, "inference-gates/providers/eligibility", query, 503)
	clear := resource.GateOperation{Version: 1, OpID: uuid.NewString(), ExpectedRevision: 1, Binding: current,
		Subject: "provider", SourceVersion: e.SourceVersion, Owner: "provider-auto/v1", Action: "clear", Reason: "recovered", EvidenceID: "controlled-new"}
	providerGatePost(t, x.f, "inference-gates/operations", clear, 503)
	var state resource.GateState
	if err := json.Unmarshal(x.f.request("inference-gates", 200), &state); err != nil {
		t.Fatal(err)
	}
	if state.Revision != 1 || len(state.Gates) != 1 {
		t.Fatal("unavailable clear changed durable intent")
	}
	x.send(t, "provider-b-model", "SYNTHETIC-B1", false, true)
	reloadDisabled(false)
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, false)
	e = providerEligibility(t, x.f, x.binding(t, "SYNTHETIC-A1"))
	providerOperation(t, x.f, e, 1, "provider-auto/v1", "clear")
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, true)
}
