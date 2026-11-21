package executor

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// codexHTTPBusinessError recognizes only the reviewed Codex OAuth HTTP quota
// rejection. The official Codex client specifies the usage_limit_reached
// envelope and active-limit header (codex-api/api_bridge.rs), and the named
// window headers nested under that limit ID (codex-api/rate_limits.rs).
// Without direct support for a scope, use the existing failure policy.
func codexHTTPBusinessError(ctx context.Context, a *cliproxyauth.Auth, res *http.Response, body, sent []byte, model string, modelLevelCooling bool) statusErr {
	result := newCodexStatusErrWithHeadersAndCooling(res.StatusCode, res.Header, body, modelLevelCooling)
	if res.StatusCode != http.StatusTooManyRequests || a == nil || a.SourcePluginID != "" || a.ResourceIdentity == nil || model == "" || ojson.GetBytes(sent, "model").String() != model {
		return result
	}
	r := res.Request
	if r == nil || r.URL == nil || r.Method != http.MethodPost || r.URL.Scheme != "https" || r.URL.Host != "chatgpt.com" || r.URL.Path != "/backend-api/codex/responses" ||
		r.URL.User != nil || a.Attributes["api_key"] != "" || a.Attributes["base_url"] != "" {
		return result
	}
	token, _ := a.Metadata["access_token"].(string)
	account, _ := a.Metadata["account_id"].(string)
	if token == "" || account == "" || uniqueQuotaHeader(r.Header, "Authorization") != "Bearer "+token || uniqueQuotaHeader(r.Header, "Chatgpt-Account-Id") != account {
		return result
	}
	h := res.Header
	var scopedModel, header string
	switch uniqueQuotaHeader(h, "X-Codex-Active-Limit") {
	case resource.CodexSparkLimit:
		if model != resource.CodexSparkModel || uniqueQuotaHeader(h, "X-Codex-Bengalfox-Limit-Name") != resource.CodexSparkLimitName {
			return result
		}
		scopedModel, header = resource.CodexSparkModel, "X-Codex-Bengalfox-"
	case "codex":
		if model == resource.CodexSparkModel {
			return result
		}
		header = "X-Codex-"
	default:
		return result
	}
	details := ojson.GetBytes(body, "error")
	if details.Get("type").String() != "usage_limit_reached" {
		return result
	}
	minutes := details.Get("limit_window_minutes")
	seconds := minutes.Int() * 60
	if minutes.Type != ojson.Number || minutes.Int() <= 0 || minutes.Int() > 100800 || strconv.FormatInt(minutes.Int(), 10) != minutes.Raw {
		return result
	}
	date, errDate := http.ParseTime(uniqueQuotaHeader(h, "Date"))
	now := time.Now()
	if errDate != nil || date.Before(now.Add(-time.Minute)) || date.After(now.Add(time.Minute)) {
		return result
	}
	window := ""
	reset := int64(0)
	for _, name := range []string{"primary", "secondary"} {
		prefix := header + name + "-"
		if uniqueQuotaHeader(h, prefix+"Window-Minutes") != minutes.Raw {
			continue
		}
		used, errUsed := strconv.ParseFloat(uniqueQuotaHeader(h, prefix+"Used-Percent"), 64)
		at, errAt := strconv.ParseInt(uniqueQuotaHeader(h, prefix+"Reset-At"), 10, 64)
		bodyReset := details.Get("resets_at")
		if errUsed != nil || used != 100 || errAt != nil || at != bodyReset.Int() || bodyReset.Type != ojson.Number ||
			strconv.FormatInt(at, 10) != bodyReset.Raw || at <= date.Unix() || at > date.Add(time.Duration(seconds)*time.Second).Unix() || window != "" {
			return result
		}
		window, reset = name, at
	}
	if window == "" {
		return result
	}
	installed, handled := cliproxyexecutor.ObserveCodexQuotaRejection(ctx, resource.CodexQuotaRejection{
		Model: scopedModel, Window: window, WindowSeconds: seconds, ObservedAtMS: date.UnixMilli(), ResetAtMS: time.Unix(reset, 0).UnixMilli(),
	})
	if installed {
		result.persistentQuotaGate = handled
		result.credentialScoped = false
		if !handled {
			// The rejection is real but account-wide exhaustion is not proven.
			// The reset hint is a quota window, not a transient retry delay.
			result.transientRateLimit = true
			result.retryAfter = nil
		}
	}
	return result
}

func uniqueQuotaHeader(h http.Header, name string) string {
	values := h.Values(name)
	if len(values) != 1 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
