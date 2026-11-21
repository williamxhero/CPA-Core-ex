package executor

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestCodexHTTPQuotaRejectsInexactExhaustionPercent(t *testing.T) {
	for _, tc := range []struct {
		name, used string
		trusted    bool
	}{
		{"integer", "100", true},
		{"decimal", "100.0000", true},
		{"exponent", "1e2", true},
		{"below", "99.9999999999999999", false},
		{"above", "100.0000000000000001", false},
		{"nondecimal", "0x1.9p+6", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			date := time.Now().UTC().Truncate(time.Second)
			reset := date.Add(time.Hour).Unix()
			a := &auth.Auth{
				ResourceIdentity: &resource.Binding{},
				Metadata:         map[string]any{"access_token": "test", "account_id": "acct"},
			}
			request, err := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer test")
			request.Header.Set("Chatgpt-Account-Id", "acct")
			h := make(http.Header)
			h.Set("Date", date.Format(http.TimeFormat))
			h.Set("X-Codex-Active-Limit", resource.CodexSparkLimit)
			h.Set("X-Codex-Bengalfox-Limit-Name", resource.CodexSparkLimitName)
			h.Set("X-Codex-Bengalfox-Secondary-Used-Percent", tc.used)
			h.Set("X-Codex-Bengalfox-Secondary-Window-Minutes", "10080")
			h.Set("X-Codex-Bengalfox-Secondary-Reset-At", fmt.Sprint(reset))
			response := &http.Response{Request: request, StatusCode: http.StatusTooManyRequests, Header: h}
			body := fmt.Appendf(nil, "{\"error\":{\"type\":\"usage_limit_reached\",\"limit_window_minutes\":10080,\"resets_at\":%d}}", reset)
			sent := fmt.Appendf(nil, "{\"model\":%q}", resource.CodexSparkModel)
			observed := false
			ctx := executor.WithCodexQuotaObserver(t.Context(), func(evidence resource.CodexQuotaRejection) bool {
				observed = true
				if evidence.Model != resource.CodexSparkModel || evidence.Window != "secondary" || evidence.ResetAtMS != reset*1000 {
					t.Errorf("unexpected quota evidence: %+v", evidence)
				}
				return true
			})
			result := NewCodexExecutor(nil).codexHTTPBusinessError(ctx, a, response, body, sent, resource.CodexSparkModel)
			if observed != tc.trusted || result.persistentQuotaGate != tc.trusted {
				t.Fatalf("used percent %q: observed=%v durable=%v, want %v", tc.used, observed, result.persistentQuotaGate, tc.trusted)
			}
		})
	}
}
