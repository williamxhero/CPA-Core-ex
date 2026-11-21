package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestNativeFundingRejectsLegacyAutoHeldMutations(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com/v1")
	for _, tc := range []struct{ method, path, data string }{
		{http.MethodPatch, "/v0/management/openai-compatibility", `{"index":0,"value":{"auto-held":true}}`},
		{http.MethodPatch, "/v0/management/openai-compatibility", `{"name":"not-an-account-a","value":{"auto-held":true}}`},
		{http.MethodPut, "/v0/management/openai-compatibility", `[{"name":"not-an-account-a","base-url":"https://api.deepseek.com/v1","auto-held":true,"api-key-entries":[{"api-key":"SYNTHETIC-A1"}]}]`},
		{http.MethodPut, "/v8/management/config/api-keys/openai-compatibility", `[{"name":"not-an-account-a","base-url":"https://api.deepseek.com/v1","auto-held":true,"keys":[{"api-key":"SYNTHETIC-A1"}]}]`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.data))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		x.f.server.engine.ServeHTTP(w, req)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "native_funding_owns_auto_hold") {
			t.Errorf("%s %s = %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
}

func TestNativeFundingFencesStaleReorderedIndexAndRawConfig(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com/v1", func(raw string) string {
		raw = strings.Replace(raw, "- name: not-an-account-a", "- name: not-an-account-a\n      auto-held: true", 1)
		first := strings.Index(raw, "    - name: not-an-account-a")
		second := strings.Index(raw, "    - name: not-an-account-b")
		return raw[:first] + raw[second:] + raw[first:second]
	})
	request := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer test-password")
		if strings.HasSuffix(path, "/config.yaml") {
			req.Header.Set("Content-Type", "application/yaml")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		x.f.server.engine.ServeHTTP(w, req)
		return w
	}
	v8 := request(http.MethodGet, "/v8/management/config/api-keys/openai-compatibility", "")
	var list []map[string]any
	if v8.Code != 200 || json.Unmarshal(v8.Body.Bytes(), &list) != nil || len(list) != 2 || list[0]["name"] != "not-an-account-b" || list[1]["name"] != "not-an-account-a" || list[0]["native-funding"] != true || list[1]["native-funding"] != true {
		t.Fatalf("unexpected authoritative readback: %d %s", v8.Code, v8.Body.String())
	}
	before, err := os.ReadFile(x.f.path)
	if err != nil {
		t.Fatal(err)
	}
	yaml := strings.Replace(string(before), "auto-held: true", "auto-held: false", 1)
	if yaml == string(before) {
		t.Fatal("fixture missing persisted marker")
	}
	const v0RawConfigPath = "/v0/management/config.yaml"
	const retryEdit = "routing: {retry: {request-retry: 7}}\n"
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPatch, "/v0/management/openai-compatibility", `{"index":0,"value":{"auto-held":true}}`, 409},
		{http.MethodPatch, "/v0/management/openai-compatibility", `{"index":1,"value":{"auto-held":false}}`, 409},
		{http.MethodPut, v0RawConfigPath, retryEdit + yaml, 500},
		{http.MethodPut, "/v8/management/config.yaml", yaml, 409},
	} {
		got := request(tc.method, tc.path, tc.body)
		if got.Code != tc.status {
			t.Fatalf("%s got %d %s", tc.path, got.Code, got.Body.String())
		}
		after, err := os.ReadFile(x.f.path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("rejected stale write reached disk: %v", err)
		}
	}

	// The same v0 raw write may edit unrelated settings when it keeps the marker.
	got := request(http.MethodPut, v0RawConfigPath, retryEdit+string(before))
	if got.Code != http.StatusOK {
		t.Fatalf("marker-preserving %s got %d %s", v0RawConfigPath, got.Code, got.Body.String())
	}
	saved, err := config.LoadConfig(x.f.path)
	if err != nil {
		t.Fatalf("reload config after allowed raw write: %v", err)
	}
	if saved.RequestRetry != 7 {
		t.Fatalf("raw write did not persist request-retry: got %d, want 7", saved.RequestRetry)
	}
	if len(saved.OpenAICompatibility) != 2 || saved.OpenAICompatibility[1].Name != "not-an-account-a" || !saved.OpenAICompatibility[1].AutoHeld {
		t.Fatal("raw write did not preserve the held marker on its original provider")
	}
}

func TestNativeFundingRestoresLegacyGroupOnlyWithAllCurrentMembersFunded(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com/v1", func(s string) string {
		return strings.Replace(s, "- name: not-an-account-a", "- name: not-an-account-a\n      auto-held: true", 1)
	})
	x.f.manager.SetRetryConfig(0, 0, 0)
	x.startRuntime(t)
	var sends int
	x.f.manager.SetRoundTripperProvider(scopedQuotaTransport{nativeFundingTestTransport(func(r *http.Request) (*http.Response, error) {
		sends++
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))}, nil
	})})
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, false)
	var gate resource.GateState
	if err := json.Unmarshal(x.f.request("inference-gates", 200), &gate); err != nil {
		t.Fatal(err)
	}
	if len(gate.Gates) != 2 || gate.Gates[0].Reason != "legacy_funding_unverified" || gate.Gates[1].Reason != "legacy_funding_unverified" {
		t.Fatalf("historical unknown hold is not durable across rollback: %+v", gate.Gates)
	}
	proof := x.binding(t, "SYNTHETIC-A1")
	eligibility := providerEligibility(t, x.f, proof)
	for _, key := range []string{"SYNTHETIC-A1", "SYNTHETIC-A2"} {
		match := providerKeyMatchQuery(t, x, key)
		available := true
		reading := resource.FundingReading{QueryID: uuid.NewString(), ObservedAtMS: time.Now().UnixMilli(), Available: &available,
			Balances: []resource.FundingCurrency{{Currency: "USD", Total: "0.0001", Granted: "0", ToppedUp: "0.0001"}}}
		raw, err := json.Marshal(reading)
		if err != nil {
			t.Fatal(err)
		}
		stamp := sha256.Sum256(raw)
		mac := hmac.New(sha256.New, []byte(key))
		_, _ = io.WriteString(mac, "cpa-provider-funding-v1\n"+match["nonce"].(string)+"\n"+eligibility.SourceVersion+"\n"+match["auth_index"].(string)+"\n"+hex.EncodeToString(stamp[:]))
		match["digest"] = hex.EncodeToString(mac.Sum(nil))
		result := providerGatePost(t, x.f, "inference-gates/providers/funding", map[string]any{"proof": match, "reading": reading}, 200)
		if !strings.Contains(string(result), `{"accepted":true}`) {
			t.Fatalf("route did not accept current funding result: %s", result)
		}
		if key == "SYNTHETIC-A1" {
			x.send(t, "provider-a-model", "SYNTHETIC-A1", false, false)
		}
	}
	x.send(t, "provider-a-model", "SYNTHETIC-A1", false, true)
	if sends != 1 {
		t.Fatalf("eligible route forwarded %d requests", sends)
	}
	if err := json.Unmarshal(x.f.request("inference-gates", 200), &gate); err != nil {
		t.Fatal(err)
	}
	for _, row := range gate.Gates {
		if row.Reason == "legacy_funding_unverified" && row.Applicability != "rollback_guard" {
			t.Fatalf("released rollback-only row shown as active: %+v", row)
		}
	}
}

func TestNativeFundingRollbackFenceDoesNotSpendOnlyCredentialAttempt(t *testing.T) {
	x := newProviderKeyMatchFixture(t, "https://api.deepseek.com/v1", func(raw string) string {
		return strings.Replace(raw, "- name: not-an-account-a", "- name: not-an-account-a\n      auto-held: true\n      priority: 99", 1)
	})
	var gate resource.GateState
	if err := json.Unmarshal(x.f.request("inference-gates", 200), &gate); err != nil || len(gate.Gates) != 2 {
		t.Fatalf("expected both historical members durably fenced before rollback: %+v, %v", gate.Gates, err)
	}
	dir, path := x.f.dir, x.f.path
	x.f.close()
	// This is the YAML change the predecessor accepts at its legacy v0 PATCH.
	// Leave the durable catalog ledger intact and restart the current Core.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := bytes.Replace(raw, []byte("auto-held: true"), []byte("auto-held: false"), 1)
	if bytes.Equal(raw, updated) {
		t.Fatal("fixture missing legacy marker")
	}
	if err := os.WriteFile(path, updated, 0600); err != nil {
		t.Fatal(err)
	}
	x.f = newInventoryHarness(t, dir)
	x.startRuntime(t)
	const alias = "shared-funded-model"
	for _, a := range x.f.manager.List() {
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: alias}})
	}
	x.f.manager.SetRetryConfig(0, 0, 1)
	sends := make(chan string, 4)
	x.f.manager.SetRoundTripperProvider(scopedQuotaTransport{nativeFundingTestTransport(func(r *http.Request) (*http.Response, error) {
		sends <- r.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))}, nil
	})})
	x.send(t, alias, "SYNTHETIC-A1", false, true)
	if len(sends) != 1 {
		t.Fatalf("upstream sends = %d; want 1", len(sends))
	}
	if got := <-sends; !strings.HasPrefix(got, "Bearer SYNTHETIC-B") {
		t.Fatalf("unexpected upstream for sole credential attempt: %q", got)
	}
}

type nativeFundingTestTransport func(*http.Request) (*http.Response, error)

func (f nativeFundingTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
