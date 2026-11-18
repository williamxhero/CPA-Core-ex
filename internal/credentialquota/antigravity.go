package credentialquota

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const AntigravityProtocol = "antigravity-oauth-quota-summary"

var antigravityQuotaEndpoints = []string{
	"https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
	"https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary",
	"https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
}

// Antigravity reads quota only for the selected OAuth project. It never exports
// credentials, refreshes tokens, follows redirects, or uses an arbitrary origin.
func Antigravity(ctx context.Context, binding resource.Binding, metadata map[string]any, network NetworkOptions) resource.QuotaObservation {
	obs := resource.QuotaObservation{Binding: binding, Protocol: AntigravityProtocol, ProtocolVersion: 1, AccountProvenance: "selected_oauth_project", TimestampProvenance: "core_attempt_time", ObservedAtMS: time.Now().UnixMilli()}
	token, _ := metadata["access_token"].(string)
	project, _ := metadata["project_id"].(string)
	if strings.TrimSpace(token) == "" || strings.TrimSpace(project) == "" {
		obs.QueryStatus = "needs_configuration"
		obs.ErrorCode = "ANTIGRAVITY_OAUTH_PROJECT_REQUIRED"
		return obs
	}
	body, err := json.Marshal(map[string]string{"project": project})
	if err != nil {
		obs.QueryStatus = "parse_error"
		return obs
	}
	for _, endpoint := range antigravityQuotaEndpoints {
		data, status, date := readAntigravityQuota(ctx, endpoint, token, body, network)
		obs.QueryStatus = status
		if status == "success" {
			candidate := antigravityQuotaWindows(obs, data)
			if candidate.QueryStatus == "success" {
				candidate.ObservedAtMS = date.UnixMilli()
				candidate.ReceivedAtMS = time.Now().UnixMilli()
				candidate.TimestampProvenance = "upstream_http_date"
				return candidate
			}
			obs.QueryStatus = "parse_error"
		}
		if status == "auth_error" || status == "rate_limited" || ctx.Err() != nil {
			break
		}
	}
	obs.ErrorCode = "QUOTA_" + strings.ToUpper(obs.QueryStatus)
	obs.ReceivedAtMS = time.Now().UnixMilli()
	return obs
}

func readAntigravityQuota(ctx context.Context, endpoint, token string, body []byte, network NetworkOptions) ([]byte, string, time.Time) {
	// Separate from AllowedEndpoint: plugin GET access must not acquire this
	// native OAuth-only POST capability by sharing the general allowlist.
	allowed := false
	for _, candidate := range antigravityQuotaEndpoints {
		allowed = allowed || endpoint == candidate
	}
	if !allowed {
		return nil, "needs_configuration", time.Time{}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "network_error", time.Time{}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", misc.AntigravityUserAgent())
	response, err := secureClient(QueryTarget{EndpointURL: endpoint}, network).Do(req)
	if err != nil {
		return nil, "network_error", time.Time{}
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, "auth_error", time.Time{}
	case http.StatusTooManyRequests:
		return nil, "rate_limited", time.Time{}
	case http.StatusOK:
	default:
		return nil, "network_error", time.Time{}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return nil, "network_error", time.Time{}
	}
	date, errDate := http.ParseTime(response.Header.Get("Date"))
	if len(data) > 2<<20 || errDate != nil || time.Since(date) > 5*time.Minute || time.Until(date) > time.Minute {
		return nil, "parse_error", time.Time{}
	}
	return data, "success", date
}

func antigravityQuotaWindows(obs resource.QuotaObservation, data []byte) resource.QuotaObservation {
	var payload struct {
		Groups []struct {
			Name    string `json:"displayName"`
			Buckets []struct {
				ID        string   `json:"bucketId"`
				Window    string   `json:"window"`
				Remaining *float64 `json:"remainingFraction"`
				Reset     string   `json:"resetTime"`
			} `json:"buckets"`
		} `json:"groups"`
	}
	obs.QueryStatus = "parse_error"
	obs.Windows = nil
	// Summary groups are display evidence, not a complete model-to-quota
	// coverage receipt. Never use them to automatically pause or resume inference.
	obs.Complete = false
	obs.RecoveryEligible = false
	if json.Unmarshal(data, &payload) != nil || len(payload.Groups) == 0 {
		return obs
	}
	seen := map[string]bool{}
	for _, group := range payload.Groups {
		for _, bucket := range group.Buckets {
			name := bucket.Window
			seconds := int64(0)
			switch name {
			case "5h", "five-hour", "five_hour":
				name, seconds = "rolling", 18000
			case "week", "weekly":
				name, seconds = "weekly", 604800
			default:
				name = bucket.ID
			}
			key := group.Name + "\x00" + name
			reset, err := time.Parse(time.RFC3339Nano, bucket.Reset)
			if name == "" || len(name) > 128 || group.Name == "" || len(group.Name) > 128 || bucket.Remaining == nil || !finitePercent(*bucket.Remaining*100) || err != nil || seen[key] || len(obs.Windows) >= 128 {
				obs.Windows = nil
				return obs
			}
			seen[key] = true
			status := "allowed"
			if *bucket.Remaining == 0 {
				status = "rate-limited"
			}
			obs.Windows = append(obs.Windows, resource.QuotaWindow{Name: name, Model: group.Name, UsedPercent: (1 - *bucket.Remaining) * 100, RemainingFraction: *bucket.Remaining, ResetAt: reset.UTC().Format(time.RFC3339Nano), SourceStatus: status, LimitWindowSeconds: seconds})
		}
	}
	if len(obs.Windows) > 0 {
		obs.QueryStatus = "success"
	}
	return obs
}
