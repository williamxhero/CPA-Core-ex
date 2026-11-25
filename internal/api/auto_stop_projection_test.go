package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

type autoStopView struct {
	Version   int    `json:"version"`
	Ready     bool   `json:"ready"`
	Revision  uint64 `json:"revision"`
	Providers []struct {
		ResourceID  string `json:"resourceId"`
		State       string `json:"state"`
		MemberCount int    `json:"memberCount"`
		PausedCount int    `json:"pausedCount"`
		Reasons     []struct {
			Owner        string `json:"owner"`
			Reason       string `json:"reason"`
			ObservedAtMS int64  `json:"observedAtMs"`
			ResourceID   string `json:"resourceId"`
		} `json:"reasons"`
		Members []struct {
			ResourceID string `json:"resourceId"`
			State      string `json:"state"`
			Reasons    []struct {
				Owner        string `json:"owner"`
				Reason       string `json:"reason"`
				ObservedAtMS int64  `json:"observedAtMs"`
				ResourceID   string `json:"resourceId"`
			} `json:"reasons"`
		} `json:"members"`
	} `json:"providers"`
}

// readAutoStop asserts the management projection is served and parses it while
// keeping the raw body for leak and absence checks.
func readAutoStop(t *testing.T, f *inventoryHarness) (autoStopView, string) {
	t.Helper()
	raw := f.request("inference-gates/auto-stop", 200)
	var view autoStopView
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("decode auto-stop projection: %v body=%s", err, raw)
	}
	return view, string(raw)
}

// An idle ledger still enumerates every configured provider group. An empty
// provider list would be indistinguishable from "nothing is configured".
func TestAutoStopProjectionReportsAvailableProvidersWhenLedgerEmpty(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	view, raw := readAutoStop(t, f)
	if view.Version != 1 || !view.Ready || view.Revision != 0 {
		t.Fatalf("idle projection envelope: %+v", view)
	}
	if len(view.Providers) != 2 {
		t.Fatalf("idle ledger reported %d providers, want the 2 configured groups: %s", len(view.Providers), raw)
	}
	for _, p := range view.Providers {
		if p.State != "available" || p.MemberCount != 1 || p.PausedCount != 0 || len(p.Reasons) != 0 {
			t.Fatalf("provider %s without a gate is not available: %+v", p.ResourceID, p)
		}
		if len(p.Members) != 1 || p.Members[0].State != "available" || len(p.Members[0].Reasons) != 0 {
			t.Fatalf("provider %s member is not available: %+v", p.ResourceID, p.Members)
		}
	}
	if strings.Contains(raw, "disabled") || strings.Contains(raw, "auto-held") {
		t.Fatalf("projection exposed manual config fields: %s", raw)
	}
}

// autoStopProviderFor returns the projected group owning one member resource id.
func autoStopProviderFor(t *testing.T, view autoStopView, memberID string) (int, int) {
	t.Helper()
	for gi, provider := range view.Providers {
		for mi, member := range provider.Members {
			if member.ResourceID == memberID {
				return gi, mi
			}
		}
	}
	t.Fatalf("member %s is absent from the projection", memberID)
	return -1, -1
}

// A current credential pause makes its provider group temporarily unusable and
// names the owner, reason and member; clearing it returns both to available.
func TestAutoStopProjectionReportsCredentialPauseAndClears(t *testing.T) {
	dir := t.TempDir()
	f := newInventoryHarness(t, dir)
	source := gateSource(t, f)
	var binding resource.Binding
	rawSource, _ := json.Marshal(source)
	if err := json.Unmarshal(rawSource, &binding); err != nil || len(binding.Targets) != 1 {
		t.Fatalf("fixture source binding: %v %s", err, rawSource)
	}
	pausedID := binding.Targets[0].ResourceID
	if view, _ := readAutoStop(t, f); view.Revision != 0 {
		t.Fatalf("fixture published a gate before the pause: %+v", view)
	}
	gatePost(t, f, gateOp(source, 0, "7f3a41b1-8f31-4b53-9d4e-5c40b3f1ad11", "owner-a", "pause"), 200)
	view, raw := readAutoStop(t, f)
	if view.Revision != 1 {
		t.Fatalf("projection ignored the published revision: %+v", view)
	}
	gi, mi := autoStopProviderFor(t, view, pausedID)
	provider := view.Providers[gi]
	if provider.State != "auto_paused" || provider.PausedCount != 1 || provider.MemberCount != 1 {
		t.Fatalf("paused provider group did not report auto_paused: %+v", provider)
	}
	if provider.Members[mi].State != "paused" || len(provider.Members[mi].Reasons) != 1 {
		t.Fatalf("paused member detail: %+v", provider.Members[mi])
	}
	reason := provider.Members[mi].Reasons[0]
	if reason.Owner != "owner-a" || reason.Reason != "quota_exhausted" || reason.ResourceID != pausedID || reason.ObservedAtMS != 0 {
		t.Fatalf("member reason does not attribute the pause: %+v", reason)
	}
	if len(provider.Reasons) != 1 || provider.Reasons[0] != reason {
		t.Fatalf("group reasons are not the member reasons: %+v", provider.Reasons)
	}
	for _, other := range view.Providers {
		if other.ResourceID != provider.ResourceID && (other.State != "available" || other.PausedCount != 0) {
			t.Fatalf("unrelated provider %s was reported paused: %+v", other.ResourceID, other)
		}
	}
	if strings.Contains(raw, "CANARY") || strings.Contains(raw, "test-evidence") {
		t.Fatalf("projection leaked credential or evidence material: %s", raw)
	}

	gatePost(t, f, gateOp(source, 1, "cb70b0a2-2f6e-4bd2-8f2b-3b3a6c6a0d21", "owner-a", "clear"), 200)
	cleared, _ := readAutoStop(t, f)
	if cleared.Providers[gi].State != "available" || cleared.Providers[gi].PausedCount != 0 {
		t.Fatalf("clear did not restore availability: %+v", cleared.Providers[gi])
	}
}

// autoStopSourceFor returns the live credential source of one member resource id.
func autoStopSourceFor(t *testing.T, f *inventoryHarness, memberIDs map[string]bool) map[string]any {
	t.Helper()
	installGateFixtureExecutors(f)
	var view struct {
		Sources []map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", 200), &view); err != nil {
		t.Fatal(err)
	}
	for _, s := range view.Sources {
		if s["auth_index"] == nil || s["auth_index"] == "" {
			continue
		}
		var binding resource.Binding
		raw, _ := json.Marshal(s)
		if err := json.Unmarshal(raw, &binding); err != nil {
			t.Fatal(err)
		}
		for _, target := range binding.Targets {
			if memberIDs[target.ResourceID] {
				return s
			}
		}
	}
	t.Fatal("no current source for the target group")
	return nil
}

// A manual disable is not an automatic pause: it never makes a group look
// auto-paused, and pausing one member of two reports a partial stop that names
// only the paused credential.
func TestAutoStopProjectionPartialPauseIgnoresManualDisable(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys:
  openai-compatibility:
    - name: mixed-pool
      base-url: https://synthetic.invalid/v1
      models: [{name: mixed-model}]
      keys: [{api-key: MIXED-A}, {api-key: MIXED-B, disabled: true}]
`, filepath.ToSlash(authDir))
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.manager.SetConfig(f.server.cfg)
	for _, a := range f.manager.List() {
		f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "mixed-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	idle, rawIdle := readAutoStop(t, f)
	if len(idle.Providers) != 1 || idle.Providers[0].State != "available" || idle.Providers[0].MemberCount != 2 {
		t.Fatalf("manual disabled key changed automatic state: %s", rawIdle)
	}
	if strings.Contains(rawIdle, "disabled") || strings.Contains(rawIdle, "MIXED-") {
		t.Fatalf("projection leaked manual config: %s", rawIdle)
	}
	members := map[string]bool{}
	for _, m := range idle.Providers[0].Members {
		if m.State != "available" {
			t.Fatalf("manually disabled or idle member reported paused: %+v", m)
		}
		members[m.ResourceID] = true
	}
	if len(members) != 2 {
		t.Fatalf("a disabled member is missing from the group: %s", rawIdle)
	}
	source := autoStopSourceFor(t, f, members)
	var binding resource.Binding
	rawSource, _ := json.Marshal(source)
	if err := json.Unmarshal(rawSource, &binding); err != nil || len(binding.Targets) != 1 {
		t.Fatalf("fixture source binding: %v %s", err, rawSource)
	}
	pausedID := binding.Targets[0].ResourceID
	gatePost(t, f, gateOp(source, 0, "1b6cd3aa-6c2e-4cbb-bd5d-9d1c4b3f2a01", "owner-b", "pause"), 200)
	partial, _ := readAutoStop(t, f)
	provider := partial.Providers[0]
	if provider.State != "partially_auto_paused" || provider.MemberCount != 2 || provider.PausedCount != 1 {
		t.Fatalf("one paused member of two was not reported partial: %+v", provider)
	}
	if len(provider.Reasons) != 1 || provider.Reasons[0].ResourceID != pausedID || provider.Reasons[0].Owner != "owner-b" {
		t.Fatalf("partial reasons do not name the paused credential: %+v", provider.Reasons)
	}
	for _, m := range provider.Members {
		want := "available"
		if m.ResourceID == pausedID {
			want = "paused"
		}
		if m.State != want {
			t.Fatalf("member %s state=%s want=%s", m.ResourceID, m.State, want)
		}
	}
}

// A real upstream balance denial publishes a timestamped pause that the
// projection reports and that survives a restart unchanged.
func TestAutoStopProjectionRealBalancePauseSurvivesRestart(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer SOLO-BALANCE-CANARY" {
			t.Errorf("unexpected credential %q", r.Header.Get("Authorization"))
		}
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
api-keys:
  openai-compatibility:
    - name: solo-pool
      base-url: %q
      models: [{name: solo-primary}]
      keys: [{api-key: SOLO-BALANCE-CANARY}]
`, filepath.ToSlash(filepath.Join(dir, "auth")), upstream.URL+"/v1")
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	open := func() *inventoryHarness {
		f := newInventoryHarness(t, dir)
		f.manager.SetConfig(f.server.cfg)
		f.manager.SetRoundTripperProvider(scopedQuotaTransport{upstream.Client().Transport})
		for _, a := range f.manager.List() {
			f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(a.Provider, f.server.cfg))
			registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "solo-primary"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
		}
		return f
	}
	f := open()
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
	if w := balanceInference(f, "solo-primary"); w.Code != 402 {
		t.Fatalf("fixture did not reach the upstream balance denial: status=%d body=%s", w.Code, w.Body)
	}
	if gates := readBalanceGates(t, f); len(gates.Gates) != 1 || gates.Gates[0].Owner != "core.upstream-balance.v1" {
		t.Fatalf("balance denial did not publish the core pause: %+v", gates)
	}
	before, rawBefore := readAutoStop(t, f)
	if len(before.Providers) != 1 {
		t.Fatalf("projection lost the single access: %s", rawBefore)
	}
	provider := before.Providers[0]
	if provider.State != "auto_paused" || provider.MemberCount != 1 || provider.PausedCount != 1 {
		t.Fatalf("real balance pause not projected: %+v", provider)
	}
	if len(provider.Reasons) != 1 {
		t.Fatalf("expected exactly one pause reason: %+v", provider.Reasons)
	}
	reason := provider.Reasons[0]
	now := time.Now().UnixMilli()
	if reason.Owner != "core.upstream-balance.v1" || reason.Reason != "upstream_balance_exhausted" || reason.ObservedAtMS <= 0 || reason.ObservedAtMS > now || now-reason.ObservedAtMS > 10*60*1000 {
		t.Fatalf("pause reason lacks a real observation time: %+v (now=%d)", reason, now)
	}
	if provider.Members[0].ResourceID != reason.ResourceID || provider.Members[0].State != "paused" {
		t.Fatalf("member detail does not match the pause: %+v", provider.Members)
	}

	f.close()
	f = open()
	after, rawAfter := readAutoStop(t, f)
	if after.Providers[0].State != "auto_paused" || rawAfter != rawBefore {
		t.Fatalf("restart changed the projection:\nbefore %s\nafter  %s", rawBefore, rawAfter)
	}
}

// An unreadable or disabled ledger is an explicit unavailability, never an
// empty "all available" answer.
func TestAutoStopProjectionReportsUnavailableLedger(t *testing.T) {
	for _, tc := range []struct {
		name string
		fail func(t *testing.T, dir string)
	}{
		{"disabled_config", func(t *testing.T, dir string) {
			editInventoryConfig(t, filepath.Join(dir, "config.yaml"), func(root *yaml.Node) {
				testField(testField(root, "resource-catalog"), "enabled").Value = "false"
			})
		}},
		{"lost_floor", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, ".resource-catalog", "gate-floor-v1")); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt_catalog", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, ".resource-catalog", "catalog.json"), []byte(`{"format":1}`), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f := newInventoryHarness(t, dir)
			gatePost(t, f, gateOp(gateSource(t, f), 0, "a92c4d3e-51f4-4b57-9a2e-77ee60d5b101", "owner-c", "pause"), 200)
			if view, _ := readAutoStop(t, f); view.Revision != 1 {
				t.Fatalf("fixture pause was not projected: %+v", view)
			}
			f.close()
			tc.fail(t, dir)
			f = newInventoryHarness(t, dir)
			raw := f.request("inference-gates/auto-stop", 503)
			if strings.TrimSpace(string(raw)) != `{"error":"gate_unavailable"}` {
				t.Fatalf("unavailable ledger was not reported explicitly: %s", raw)
			}
		})
	}
}
