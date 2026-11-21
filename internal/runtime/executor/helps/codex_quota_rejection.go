package helps

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// ExtractCodexQuotaRejection recognizes only the reviewed Codex OAuth HTTP quota
// rejection. The official Codex client specifies the usage_limit_reached
// envelope and active-limit header (codex-api/api_bridge.rs), and the named
// window headers nested under that limit ID (codex-api/rate_limits.rs).
// Without direct support for a scope, use the existing failure policy.
func ExtractCodexQuotaRejection(a *cliproxyauth.Auth, res *http.Response, body, sent []byte, model string, now time.Time) (resource.CodexQuotaRejection, bool) {
	if res.StatusCode != http.StatusTooManyRequests || a == nil || a.SourcePluginID != "" || a.ResourceIdentity == nil || model == "" || ojson.GetBytes(sent, "model").String() != model {
		return resource.CodexQuotaRejection{}, false
	}
	r := res.Request
	if r == nil || r.URL == nil || r.Method != http.MethodPost || r.URL.Scheme != "https" || r.URL.Host != "chatgpt.com" || r.URL.Path != "/backend-api/codex/responses" ||
		r.URL.User != nil || a.Attributes["api_key"] != "" || a.Attributes["base_url"] != "" {
		return resource.CodexQuotaRejection{}, false
	}
	token, _ := a.Metadata["access_token"].(string)
	account, _ := a.Metadata["account_id"].(string)
	if token == "" || account == "" || uniqueQuotaHeader(r.Header, "Authorization") != "Bearer "+token || uniqueQuotaHeader(r.Header, "Chatgpt-Account-Id") != account {
		return resource.CodexQuotaRejection{}, false
	}
	h := res.Header
	var scopedModel, header string
	switch uniqueQuotaHeader(h, "X-Codex-Active-Limit") {
	case resource.CodexSparkLimit:
		if model != resource.CodexSparkModel || uniqueQuotaHeader(h, "X-Codex-Bengalfox-Limit-Name") != resource.CodexSparkLimitName {
			return resource.CodexQuotaRejection{}, false
		}
		scopedModel, header = resource.CodexSparkModel, "X-Codex-Bengalfox-"
	case "codex":
		if model == resource.CodexSparkModel {
			return resource.CodexQuotaRejection{}, false
		}
		header = "X-Codex-"
	default:
		return resource.CodexQuotaRejection{}, false
	}
	details := ojson.GetBytes(body, "error")
	if details.Get("type").String() != "usage_limit_reached" {
		return resource.CodexQuotaRejection{}, false
	}
	minutes := details.Get("limit_window_minutes")
	seconds := minutes.Int() * 60
	if minutes.Type != ojson.Number || minutes.Int() <= 0 || minutes.Int() > 100800 || strconv.FormatInt(minutes.Int(), 10) != minutes.Raw {
		return resource.CodexQuotaRejection{}, false
	}
	date, errDate := http.ParseTime(uniqueQuotaHeader(h, "Date"))
	if errDate != nil || date.Before(now.Add(-time.Minute)) || date.After(now.Add(time.Minute)) {
		return resource.CodexQuotaRejection{}, false
	}
	window := ""
	reset := int64(0)
	for _, name := range []string{"primary", "secondary"} {
		prefix := header + name + "-"
		if uniqueQuotaHeader(h, prefix+"Window-Minutes") != minutes.Raw {
			continue
		}
		usage, _, _ := credentialquota.ParseCodexUsedPercent(uniqueQuotaHeader(h, prefix+"Used-Percent"))
		at, errAt := strconv.ParseInt(uniqueQuotaHeader(h, prefix+"Reset-At"), 10, 64)
		bodyReset := details.Get("resets_at")
		if usage != resource.CodexWindowUsageAtLimit || errAt != nil || at != bodyReset.Int() || bodyReset.Type != ojson.Number ||
			strconv.FormatInt(at, 10) != bodyReset.Raw || at <= date.Unix() || at > date.Add(time.Duration(seconds)*time.Second).Unix() || window != "" {
			return resource.CodexQuotaRejection{}, false
		}
		window, reset = name, at
	}
	if window == "" {
		return resource.CodexQuotaRejection{}, false
	}
	return resource.CodexQuotaRejection{
		Model: scopedModel, Window: window, WindowSeconds: seconds, ObservedAtMS: date.UnixMilli(), ResetAtMS: time.Unix(reset, 0).UnixMilli(),
	}, true
}

func uniqueQuotaHeader(h http.Header, name string) string {
	values := h.Values(name)
	if len(values) != 1 {
		return ""
	}
	return strings.TrimSpace(values[0])
}
