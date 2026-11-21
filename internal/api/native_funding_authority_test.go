package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/google/uuid"
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
}

type nativeFundingTestTransport func(*http.Request) (*http.Response, error)

func (f nativeFundingTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
