// Package credentialquota contains bounded selected-credential management reads.
// It never uses inference execution, refreshes tokens or changes account state.
package credentialquota

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type NetworkOptions struct {
	RootCAs     *x509.CertPool
	LookupIP    func(context.Context, string) ([]net.IPAddr, error)
	DialContext func(context.Context, string, string) (net.Conn, error)
	// RecoverLookup runs only when every system answer is in 198.18.0.0/15.
	// Nil uses DNS-over-HTTPS to a pinned resolver. It cannot receive credentials.
	RecoverLookup func(context.Context, string) ([]net.IPAddr, error)
}
type QueryTarget struct {
	EndpointURL    string
	PrivateTargets []string
}

func AllowedEndpoint(endpoint string) bool {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return false
	}
	return endpoint == "https://chatgpt.com/backend-api/wham/usage" || u.Host == "opencode.ai" && (u.Path == "/zen/go/v1/usage" || u.Path == "/inference/go/v1/usage")
}

func read(ctx context.Context, endpoint, token, account string, n NetworkOptions) ([]byte, string, time.Time) {
	if !AllowedEndpoint(endpoint) {
		return nil, "needs_configuration", time.Time{}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if account != "" {
		req.Header.Set("Chatgpt-Account-Id", account)
	}
	res, err := secureClient(QueryTarget{EndpointURL: endpoint}, n).Do(req)
	if err != nil {
		return nil, "network_error", time.Time{}
	}
	defer func() {
		if errClose := res.Body.Close(); errClose != nil {
			// Transport errors can contain credential-bearing URLs; keep the diagnostic fixed.
			log.WithField("component", "credential_quota").Warn("Failed to close quota response body")
		}
	}()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return nil, "auth_error", time.Time{}
	}
	if res.StatusCode == 429 {
		return nil, "rate_limited", time.Time{}
	}
	if res.StatusCode != 200 {
		return nil, "network_error", time.Time{}
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if err != nil {
		return nil, "network_error", time.Time{}
	}
	if len(data) > 2<<20 {
		return nil, "parse_error", time.Time{}
	}
	date, err := http.ParseTime(res.Header.Get("Date"))
	if err != nil || time.Since(date) > 5*time.Minute || time.Until(date) > time.Minute {
		return nil, "parse_error", time.Time{}
	}
	return data, "success", date
}

func freshWindows(obs *resource.QuotaObservation) {
	obs.ProtocolVersion = 1
	obs.ReceivedAtMS = time.Now().UnixMilli()
	obs.TimestampProvenance = "upstream_http_date"
	obs.RecoveryEligible = obs.QueryStatus == "success" && obs.Complete && obs.AccountProvenance != "unverified"
	for _, w := range obs.Windows {
		reset, e := time.Parse(time.RFC3339Nano, w.ResetAt)
		hasRemaining := w.RemainingFraction > 0
		if obs.Protocol == "codex-oauth-wham" {
			hasRemaining = w.CodexUsage == resource.CodexWindowUsageBelowLimit
		}
		if e != nil || !reset.After(time.Now()) || !hasRemaining || w.SourceStatus == "rate-limited" {
			obs.RecoveryEligible = false
		}
	}
	if len(obs.Windows) == 0 {
		obs.RecoveryEligible = false
	}
}

func Codex(ctx context.Context, b resource.Binding, metadata map[string]any, n NetworkOptions) resource.QuotaObservation {
	token, _ := metadata["access_token"].(string)
	account, _ := metadata["account_id"].(string)
	obs := resource.QuotaObservation{Binding: b, Protocol: "codex-oauth-wham", AccountProvenance: "unverified"}
	if account != "" {
		obs.AccountProvenance = "selected_oauth_account"
	}
	data, status, date := read(ctx, "https://chatgpt.com/backend-api/wham/usage", token, account, n)
	obs.QueryStatus = status
	obs.ObservedAtMS = date.UnixMilli()
	if status != "success" {
		obs.ObservedAtMS = time.Now().UnixMilli()
		obs.ErrorCode = "QUOTA_" + strings.ToUpper(status)
		return obs
	}
	return codexUsageWindows(obs, data)
}

func codexUsageWindows(obs resource.QuotaObservation, data []byte) resource.QuotaObservation {
	var root struct {
		RateLimit  *codexLimit `json:"rate_limit"`
		Additional []struct {
			Name      string      `json:"limit_name"`
			Model     string      `json:"metered_feature"`
			RateLimit *codexLimit `json:"rate_limit"`
		} `json:"additional_rate_limits"`
	}
	if !unambiguousQuotaReading(data) || json.Unmarshal(data, &root) != nil || root.RateLimit == nil {
		obs.QueryStatus = "parse_error"
		obs.ErrorCode = "INVALID_QUOTA_WINDOWS"
		return obs
	}
	obs.Complete = true
	appendLimit := func(limit *codexLimit, model, limitName string) bool {
		if limit == nil || limit.Allowed == nil || limit.Reached == nil {
			return false
		}
		for _, v := range []struct {
			name   string
			window *codexWindow
		}{{"primary", limit.Primary}, {"secondary", limit.Secondary}} {
			if v.window == nil {
				obs.Complete = false
				continue
			}
			w := v.window
			usage, used, remaining := ParseCodexUsedPercent(string(w.Used))
			if usage == resource.CodexWindowUsageUnknown || w.Reset == nil || *w.Reset <= 0 || *w.Reset > 253402300799 || w.Seconds == nil || *w.Seconds <= 0 {
				return false
			}
			status := "allowed"
			if !*limit.Allowed || *limit.Reached {
				status = "rate-limited"
				remaining = 0
			}
			obs.Windows = append(obs.Windows, resource.QuotaWindow{Name: v.name, Model: model, LimitName: limitName, CodexUsage: usage, UsedPercent: used, RemainingFraction: remaining, ResetAt: time.Unix(*w.Reset, 0).UTC().Format(time.RFC3339), SourceStatus: status, LimitWindowSeconds: *w.Seconds})
		}
		return true
	}
	if !appendLimit(root.RateLimit, "", "") {
		obs.QueryStatus = "parse_error"
	}
	for _, a := range root.Additional {
		limitName := ""
		if a.Model == resource.CodexSparkLimit && a.Name == resource.CodexSparkLimitName {
			limitName = resource.CodexSparkLimitName
		}
		if len(a.Model) > 128 || len(a.Name) > 128 || !appendLimit(a.RateLimit, a.Model, limitName) {
			obs.QueryStatus = "parse_error"
		}
	}
	if len(obs.Windows) == 0 {
		obs.QueryStatus = "parse_error"
	}
	if obs.QueryStatus != "success" {
		obs.Windows = nil
		obs.Complete = false
		obs.ErrorCode = "INVALID_QUOTA_WINDOWS"
	} else {
		// Prolite can explicitly report one weekly window and no other limits.
		var shape struct {
			Plan       string          `json:"plan_type"`
			Additional json.RawMessage `json:"additional_rate_limits"`
			Rate       struct {
				Secondary json.RawMessage `json:"secondary_window"`
			} `json:"rate_limit"`
		}
		_ = json.Unmarshal(data, &shape)
		single := shape.Plan == "prolite" && string(shape.Rate.Secondary) == "null" && (string(shape.Additional) == "null" || string(shape.Additional) == "[]") && len(obs.Windows) == 1 && obs.Windows[0].Name == "primary" && obs.Windows[0].LimitWindowSeconds == 604800
		if single {
			obs.Complete = true
		}
		obs.StandardOnlyNoCredits = codexStandardOnlyNoCredits(data, single)
		obs.StandardPaidFunding = codexStandardPaidFunding(data, single)
		obs.Credits = codexCreditsFromUsage(data)
		obs.ResetCredits = codexResetCreditsFromUsage(data)
	}
	freshWindows(&obs)
	return obs
}

// Only explicit absence of any independent limits and an exact depleted
// wallet may corroborate a standard plan rejection as account-wide.
func codexStandardOnlyNoCredits(data []byte, single bool) bool {
	var root struct {
		Additional *[]json.RawMessage `json:"additional_rate_limits"`
		Credits    *struct {
			Has       *bool           `json:"has_credits"`
			Unlimited *bool           `json:"unlimited"`
			Balance   json.RawMessage `json:"balance"`
		} `json:"credits"`
	}
	if json.Unmarshal(data, &root) != nil || (root.Additional == nil && !single) || (root.Additional != nil && len(*root.Additional) != 0) ||
		root.Credits == nil || root.Credits.Has == nil || *root.Credits.Has ||
		root.Credits.Unlimited == nil || *root.Credits.Unlimited {
		return false
	}
	whole, fraction, hasFraction := strings.Cut(creditBalanceText(root.Credits.Balance), ".")
	return whole == "0" && (!hasFraction || fraction != "" && strings.Trim(fraction, "0") == "")
}

// codexResetCreditsFromUsage reads the one-time rate-limit reset allowance that
// ships with the same usage read. It never invents a count: a missing, non
// integer, negative or implausible field yields no evidence instead of zero.
func codexResetCreditsFromUsage(data []byte) *resource.QuotaResetCredits {
	var root struct {
		ResetCredits *struct {
			Available           *int64 `json:"available_count"`
			ApplicableAvailable *int64 `json:"applicable_available_count"`
		} `json:"rate_limit_reset_credits"`
	}
	if json.Unmarshal(data, &root) != nil || root.ResetCredits == nil || root.ResetCredits.Available == nil {
		return nil
	}
	count := *root.ResetCredits.Available
	if count < 0 || count > maxCodexResetCredits {
		return nil
	}
	out := &resource.QuotaResetCredits{AvailableCount: int(count)}
	if applicable := root.ResetCredits.ApplicableAvailable; applicable != nil && *applicable >= 0 && *applicable <= count {
		value := int(*applicable)
		out.ApplicableAvailableCount = &value
	}
	return out
}

func codexCreditsFromUsage(data []byte) *resource.QuotaCredits {
	var root struct {
		Credits *struct {
			HasCredits *bool           `json:"has_credits"`
			Unlimited  *bool           `json:"unlimited"`
			Balance    json.RawMessage `json:"balance"`
			Overage    *bool           `json:"overage_limit_reached"`
		} `json:"credits"`
	}
	if json.Unmarshal(data, &root) != nil || root.Credits == nil {
		return nil
	}
	out := &resource.QuotaCredits{}
	if root.Credits.HasCredits != nil {
		out.HasCredits = *root.Credits.HasCredits
	}
	if root.Credits.Unlimited != nil {
		out.Unlimited = *root.Credits.Unlimited
	}
	if root.Credits.Overage != nil {
		out.OverageLimitReached = *root.Credits.Overage
	}
	out.Balance = creditBalanceText(root.Credits.Balance)
	return out
}

func creditBalanceText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

type codexWindow struct {
	Used    json.RawMessage `json:"used_percent"`
	Reset   *int64          `json:"reset_at"`
	Seconds *int64          `json:"limit_window_seconds"`
}
type codexLimit struct {
	Allowed   *bool        `json:"allowed"`
	Reached   *bool        `json:"limit_reached"`
	Primary   *codexWindow `json:"primary_window"`
	Secondary *codexWindow `json:"secondary_window"`
}

func finitePercent(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 100 }

// maxCodexResetCredits bounds an upstream allowance that is only ever earned a
// few times per billing cycle. Larger values are treated as unparsable rather
// than published as truth.
const maxCodexResetCredits = 1000

// PluginRead accepts at most ONE GET to the exact host-selected endpoint/key.
// Raw status/window completeness is preserved from that very same request.
type PluginRead struct {
	mu            sync.Mutex
	endpoint, key string
	n             NetworkOptions
	calls         int
	data          []byte
	status        string
	date          time.Time
}

func NewPluginRead(endpoint, key string, n NetworkOptions) *PluginRead {
	return &PluginRead{endpoint: endpoint, key: key, n: n, status: "network_error"}
}
func (p *PluginRead) Do(ctx context.Context, r pluginapi.HTTPRequest) (pluginapi.HTTPResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.calls != 1 || r.Method != "GET" || r.URL != p.endpoint || len(r.Body) != 0 || r.Headers.Get("Authorization") != "Bearer "+p.key || p.key == "" {
		p.status = "parse_error"
		return pluginapi.HTTPResponse{}, errors.New("quota request refused")
	}
	// Never copy arbitrary plugin headers or follow plugin destinations.
	p.data, p.status, p.date = read(ctx, p.endpoint, p.key, "", p.n)
	code := 200
	if p.status != "success" {
		code = 502
	}
	if p.status == "auth_error" {
		code = 401
	}
	if p.status == "rate_limited" {
		code = 429
	}
	return pluginapi.HTTPResponse{StatusCode: code, Body: p.data}, nil
}
func (p *PluginRead) DoStream(context.Context, pluginapi.HTTPRequest) (pluginapi.HTTPStreamResponse, error) {
	return pluginapi.HTTPStreamResponse{}, errors.New("quota stream refused")
}
func (p *PluginRead) Observation(b resource.Binding) resource.QuotaObservation {
	p.mu.Lock()
	defer p.mu.Unlock()
	obs := resource.QuotaObservation{Binding: b, Protocol: "opencode-go-usage", QueryStatus: p.status, ObservedAtMS: p.date.UnixMilli(), AccountProvenance: "selected_key_subscription"}
	if p.status != "success" {
		obs.ObservedAtMS = time.Now().UnixMilli()
		obs.ErrorCode = "QUOTA_" + strings.ToUpper(p.status)
		return obs
	}
	var root struct {
		Usage map[string]struct {
			Percent *float64 `json:"percent"`
			Reset   string   `json:"resetsAt"`
			Status  string   `json:"status"`
		} `json:"usage"`
	}
	if json.Unmarshal(p.data, &root) != nil {
		obs.QueryStatus = "parse_error"
		return obs
	}
	obs.Complete = true
	for _, name := range []string{"rolling", "weekly", "monthly"} {
		w, ok := root.Usage[name]
		if !ok || w.Percent == nil {
			obs.Complete = false
			continue
		}
		reset, err := time.Parse(time.RFC3339Nano, w.Reset)
		if !finitePercent(*w.Percent) || err != nil || (w.Status != "allowed" && w.Status != "rate-limited" && w.Status != "ok") {
			obs.QueryStatus = "parse_error"
			obs.Windows = nil
			obs.Complete = false
			break
		}
		remaining := 1 - *w.Percent/100
		if w.Status == "rate-limited" {
			remaining = 0
		}
		obs.Windows = append(obs.Windows, resource.QuotaWindow{Name: name, UsedPercent: *w.Percent, RemainingFraction: remaining, ResetAt: reset.UTC().Format(time.RFC3339Nano), SourceStatus: w.Status})
	}
	if len(obs.Windows) == 0 {
		obs.QueryStatus = "parse_error"
	}
	freshWindows(&obs)
	return obs
}
