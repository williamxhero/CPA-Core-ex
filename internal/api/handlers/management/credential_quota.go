package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// SetQuotaNetwork installs external network dependencies for isolated host tests.
// It is not a remote management setting and never changes inference transport.
func (h *Handler) SetQuotaNetwork(n credentialquota.NetworkOptions) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.quotaNetwork = n
}

func (h *Handler) quotaSource(ctx context.Context, a *coreauth.Auth) resource.QuotaSource {
	s := resource.QuotaSource{Binding: *a.ResourceIdentity, SourceID: a.ID, SubjectID: a.ResourceIdentity.Targets[0].ResourceID, AuthIndex: a.Index, State: "unsupported", Reason: "quota_protocol_unverified", AccountProvenance: "unverified", Protocol: "unavailable", ManualDisabled: a.Disabled}
	switch {
	case a.SourcePluginID == "qwen-cliproxyapi":
		s.Protocol = "qwen-coding-plan-cli"
		s.Reason = "account_authority_unverified"
		if h.qwenCLIConfigured(ctx, a) {
			s.State = "ready"
			s.Reason = "configured_cli_source"
			s.AccountProvenance = "configured_cli_profile"
		} else {
			s.State = "needs_configuration"
		}
	case a.SourcePluginID == "opencode-go-cliproxyapi":
		s.Protocol = "opencode-go-usage"
		s.State = "ready"
		s.Reason = "selected_native_plugin"
		s.AccountProvenance = "selected_key_subscription"
		h.mu.Lock()
		host := h.pluginHost
		h.mu.Unlock()
		if host == nil || !host.HasQuotaProviderForPlugin(a.SourcePluginID) {
			s.State = "unsupported"
			s.Reason = "native_plugin_unavailable"
		} else if desc, handled, err := host.DescribeQuota(ctx, a.SourcePluginID); err != nil || !handled || !desc.ScopedHTTP {
			s.State = "unsupported"
			s.Reason = "quota_operation_context_unavailable"
			s.AccountProvenance = "unverified"
		}
		if s.State == "ready" && !credentialquota.AllowedEndpoint(h.quotaPluginEndpoint(ctx, a)+"/usage") {
			s.State = "needs_configuration"
			s.Reason = "plugin_origin_unverified"
			s.AccountProvenance = "unverified"
		}
		if s.State == "ready" && len(s.Targets) > 1 && h.quotaPluginEndpoint(ctx, a) != h.quotaPluginConfigEndpoint(ctx, a) {
			s.State = "needs_configuration"
			s.Reason = "projection_endpoint_mismatch"
			s.AccountProvenance = "unverified"
		}
	case a.SourcePluginID != "":
		s.Reason = "plugin_protocol_unverified"
	case a.Provider == "codex":
		metadataKey, _ := a.Metadata["api_key"].(string)
		metadataBase, _ := a.Metadata["base_url"].(string)
		if strings.TrimSpace(a.Attributes["api_key"]) != "" || strings.TrimSpace(metadataKey) != "" {
			s.Reason = "api_key_protocol_unverified"
			s.State = "needs_configuration"
			break
		}
		token, _ := a.Metadata["access_token"].(string)
		if token != "" && a.Attributes["base_url"] == "" && strings.TrimSpace(metadataBase) == "" {
			s.Protocol = "codex-oauth-wham"
			s.State = "ready"
			s.Reason = "selected_oauth"
			if account, _ := a.Metadata["account_id"].(string); account != "" {
				s.AccountProvenance = "selected_oauth_account"
			}
		} else {
			s.State = "needs_configuration"
			s.Reason = "native_oauth_required"
		}
	}
	// A SECRET-FREE query-source revision, never identity or a credential digest.
	endpoint := "https://chatgpt.com/backend-api/wham/usage"
	if s.Protocol == "opencode-go-usage" {
		endpoint = h.quotaPluginEndpoint(ctx, a) + "/usage"
	}
	if s.Protocol == "qwen-coding-plan-cli" {
		endpoint = ""
	}
	if s.State != "ready" {
		endpoint = ""
	}
	configRevision := ""
	if s.Protocol == "qwen-coding-plan-cli" {
		configRevision = h.qwenCLIRevision(ctx, a)
	}
	revision, _ := json.Marshal([]string{s.Protocol, s.State, s.Reason, s.AccountProvenance, endpoint, configRevision})
	digest := sha256.Sum256(revision)
	s.SourceVersion = hex.EncodeToString(digest[:])
	return s
}

func (h *Handler) qwenCLIRevision(ctx context.Context, a *coreauth.Auth) string {
	if a == nil {
		return ""
	}
	h.mu.Lock()
	cfg := h.cfg.Plugins.Configs[a.SourcePluginID]
	var raw map[string]any
	_ = cfg.Raw.Decode(&raw)
	h.mu.Unlock()
	// Hash only the selected source configuration; the digest is secret-free and
	// changes when the executable/profile/cache enrollment changes.
	command := fmt.Sprint(raw["command"])
	blPath := ""
	if args, ok := raw["command-args"].([]any); ok {
		for i := 0; i < len(args); i++ {
			arg := strings.TrimSpace(fmt.Sprint(args[i]))
			if !strings.HasPrefix(arg, "--") {
				continue
			}
			name, value, has := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			if !has && i+1 < len(args) && !strings.HasPrefix(strings.TrimSpace(fmt.Sprint(args[i+1])), "--") {
				value = strings.TrimSpace(fmt.Sprint(args[i+1]))
				i++
			}
			if name == "bl-path" {
				blPath = value
			}
		}
	}
	fileHash := func(path string) string {
		body, err := os.ReadFile(path)
		if err != nil {
			return "missing"
		}
		digest := sha256.Sum256(body)
		return hex.EncodeToString(digest[:])
	}
	var targets []resource.Target
	if a.ResourceIdentity != nil {
		targets = append(targets, a.ResourceIdentity.Targets...)
	}
	body, _ := json.Marshal([]any{raw["quota-source"], command, raw["command-args"], raw["command-timeout"], raw["quota-resource-bindings"], targets, fileHash(command), fileHash(blPath)})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// qwenCLIConfigured is deliberately narrow: the host accepts only the
// administrator-configured Coding Plan CLI/cache lane, never a default profile
// or an arbitrary plugin claim. The values are folded into SourceVersion below
// through the protocol/state projection and the selected resource binding.
func (h *Handler) qwenCLIConfigured(ctx context.Context, a *coreauth.Auth) bool {
	if a == nil || a.SourcePluginID != "qwen-cliproxyapi" || a.Provider != "qwen" {
		return false
	}
	h.mu.Lock()
	cfg := h.cfg.Plugins.Configs[a.SourcePluginID]
	var raw map[string]any
	_ = cfg.Raw.Decode(&raw)
	h.mu.Unlock()
	if strings.TrimSpace(fmt.Sprint(raw["quota-source"])) != "command" || strings.TrimSpace(fmt.Sprint(raw["command"])) == "" {
		return false
	}
	if a.ResourceIdentity == nil || len(a.ResourceIdentity.Targets) == 0 || !qwenTargetEnrolled(raw["quota-resource-bindings"], a.ResourceIdentity.Targets) {
		return false
	}
	args, ok := raw["command-args"].([]any)
	if !ok || len(args) == 0 {
		return false
	}
	seen := map[string]string{}
	cacheOnlyPresent := false
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(fmt.Sprint(args[i]))
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		name, value, has := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !has && i+1 < len(args) && !strings.HasPrefix(strings.TrimSpace(fmt.Sprint(args[i+1])), "--") {
			value = strings.TrimSpace(fmt.Sprint(args[i+1]))
			i++
		}
		seen[name] = value
		if name == "cache-only" {
			cacheOnlyPresent = true
		}
	}
	if seen["source"] != "coding-plan" || seen["protocol"] != "qwen-coding-plan-v1" {
		return false
	}
	if seen["token-file"] != "" || seen["console-site"] != "" || seen["console-region"] != "" {
		return false
	}
	if cacheOnlyPresent {
		value := strings.TrimSpace(strings.ToLower(seen["cache-only"]))
		if value == "" || value == "true" {
			return strings.TrimSpace(seen["cache-file"]) != "" && strings.TrimSpace(seen["max-age"]) != ""
		}
	}
	return strings.TrimSpace(seen["bl-path"]) != "" && strings.TrimSpace(seen["cache-file"]) != ""
}

func qwenTargetEnrolled(raw any, targets []resource.Target) bool {
	if len(targets) == 0 {
		return false
	}
	body, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	var enrolled []qwenResourceBinding
	if json.Unmarshal(body, &enrolled) != nil || len(enrolled) == 0 {
		return false
	}
	for _, target := range targets {
		matched := false
		for _, candidate := range enrolled {
			if candidate.ResourceID == target.ResourceID && candidate.IdentityVersion == target.IdentityVersion && candidate.CredentialVersion == target.CredentialVersion && candidate.ConfigVersion == target.ConfigVersion && candidate.MembershipVersion == target.MembershipVersion {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

type qwenResourceBinding struct {
	ResourceID        string `json:"resource-id"`
	IdentityVersion   uint64 `json:"identity-version"`
	CredentialVersion uint64 `json:"credential-version"`
	ConfigVersion     uint64 `json:"config-version"`
	MembershipVersion uint64 `json:"membership-version"`
}

// Resolve the SAME effective endpoint as the known plugin: explicit auth first,
// current instance config second, documented native default last. Never labels.
func (h *Handler) quotaPluginEndpoint(ctx context.Context, a *coreauth.Auth) string {
	endpoint := strings.TrimSpace(a.Attributes["base_url"])
	if endpoint == "" {
		return h.quotaPluginConfigEndpoint(ctx, a)
	}
	return strings.TrimRight(endpoint, "/")
}
func (h *Handler) quotaPluginConfigEndpoint(ctx context.Context, a *coreauth.Auth) string {
	var endpoint string
	h.mu.Lock()
	cfg := h.cfg.Plugins.Configs[a.SourcePluginID]
	var raw map[string]any
	_ = cfg.Raw.Decode(&raw)
	endpoint, _ = raw["base-url"].(string)
	h.mu.Unlock()
	if strings.TrimSpace(endpoint) == "" {
		h.mu.Lock()
		host := h.pluginHost
		h.mu.Unlock()
		if host != nil {
			if desc, handled, err := host.DescribeQuota(ctx, a.SourcePluginID); err == nil && handled && desc.ScopedHTTP {
				endpoint = desc.DefaultQuotaBaseURL
			}
		}
	}
	return strings.TrimRight(strings.TrimSpace(endpoint), "/")
}

// quotaSources preserves the private legacy source-only interface. The public
// view and this wrapper share one builder and the same validation boundaries.
func (h *Handler) quotaSources(ctx context.Context) ([]resource.QuotaSource, bool) {
	view, ok := h.quotaSourceBindingsView(ctx)
	return view.Sources, ok
}

func (h *Handler) CredentialQuotaSources(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	view, ok := h.quotaSourceBindingsView(ctx)
	if !ok {
		c.JSON(503, gin.H{"error": "resource_inventory_unavailable"})
		return
	}
	c.JSON(200, view)
}

func (h *Handler) selectedQuota(q resource.QuotaQuery) (*coreauth.Auth, bool) {
	if h.resourceCatalog == nil || h.resourceModeReason() != "" || q.AuthIndex == "" || len(q.Targets) == 0 || len(q.Targets) > 64 {
		return nil, false
	}
	a := h.currentRuntimeSource(h.authByIndex(q.AuthIndex))
	if a == nil || !reflect.DeepEqual(*a.ResourceIdentity, q.Binding) {
		return nil, false
	}
	return a, true
}

func (h *Handler) QueryCredentialQuota(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var q resource.QuotaQuery
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || q.TimeoutMS < 0 || q.TimeoutMS > 60000 {
		c.JSON(400, gin.H{"error": "invalid_query"})
		return
	}
	budget := time.Duration(q.TimeoutMS) * time.Millisecond
	if budget == 0 {
		budget = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), budget)
	defer cancel()
	a, ok := h.selectedQuota(q)
	if !ok {
		c.JSON(409, gin.H{"error": "identity_changed"})
		return
	}
	h.mu.Lock()
	if h.quotaSlots == nil {
		h.quotaSlots = make(chan struct{}, 4)
	}
	slots := h.quotaSlots
	n := h.quotaNetwork
	host := h.pluginHost
	h.mu.Unlock()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		c.JSON(429, gin.H{"error": "query_busy"})
		return
	}
	source := h.quotaSource(ctx, a)
	if q.SourceID == "" || q.SubjectID == "" || q.SourceID != source.SourceID || q.SubjectID != source.SubjectID || q.SourceVersion == "" || source.SourceVersion != q.SourceVersion {
		c.JSON(409, gin.H{"error": "source_changed"})
		return
	}
	obs := resource.QuotaObservation{Binding: q.Binding, Protocol: source.Protocol, QueryStatus: source.State, ErrorCode: source.Reason, ObservedAtMS: time.Now().UnixMilli(), AccountProvenance: source.AccountProvenance}
	if source.State == "ready" {
		if source.Protocol == "codex-oauth-wham" {
			obs = credentialquota.Codex(ctx, q.Binding, a.Metadata, n)
		} else if source.Protocol == "qwen-coding-plan-cli" {
			response, handled, err := host.FetchQuotaByPlugin(ctx, a.SourcePluginID, pluginapi.QuotaFetchRequest{AuthIndex: a.Index, AuthID: a.ID, Provider: a.Provider, Metadata: a.Metadata, Attributes: a.Attributes})
			if handled && err == nil && !h.qwenCLIReceiptValid(a, response) {
				response = pluginapi.QuotaFetchResponse{}
				err = fmt.Errorf("qwen CLI cache receipt is not current")
			}
			obs = qwenCLIObservation(q.Binding, source, response, handled, err)
		} else {
			// Both in-process and compiled plugins use this invocation-scoped bridge.
			// It records only this selected quota request, with no generic HTTP fallback.
			endpoint := h.quotaPluginEndpoint(ctx, a)
			bridge := credentialquota.NewPluginRead(strings.TrimRight(endpoint, "/")+"/usage", a.Attributes["api_key"], n)
			scoped := pluginhost.WithQuotaHTTPClient(ctx, bridge)
			_, handled, err := host.FetchQuotaByPlugin(scoped, a.SourcePluginID, pluginapi.QuotaFetchRequest{AuthIndex: a.Index, AuthID: a.ID, Provider: a.Provider, Metadata: a.Metadata, Attributes: a.Attributes, HTTPClient: bridge})
			obs = bridge.Observation(q.Binding)
			if !handled {
				obs.QueryStatus = "unsupported"
				obs.ErrorCode = "native_plugin_unavailable"
			} else if err != nil && obs.QueryStatus == "success" {
				obs.QueryStatus = "parse_error"
				obs.RecoveryEligible = false
				obs.ErrorCode = "native_plugin_rejected"
			}
		}
	}
	current, valid := h.selectedQuota(q)
	if !valid || h.quotaSource(ctx, current).SourceVersion != q.SourceVersion {
		c.JSON(409, gin.H{"error": "identity_changed"})
		return
	}
	obs.SourceVersion = source.SourceVersion
	if obs.ProtocolVersion == 0 {
		obs.ProtocolVersion = 1
		obs.ReceivedAtMS = time.Now().UnixMilli()
		obs.TimestampProvenance = "core_attempt_time"
	}
	c.JSON(200, obs)
}

func qwenCLIObservation(binding resource.Binding, source resource.QuotaSource, response pluginapi.QuotaFetchResponse, handled bool, fetchErr error) resource.QuotaObservation {
	now := time.Now()
	obs := resource.QuotaObservation{Binding: binding, Protocol: source.Protocol, ProtocolVersion: 1, TimestampProvenance: "local_cli_acquisition_time", ReceivedAtMS: now.UnixMilli(), QueryStatus: "network_error", ErrorCode: "qwen_cli_quota_failed", ObservedAtMS: now.UnixMilli(), AccountProvenance: source.AccountProvenance}
	if !handled || fetchErr != nil || response.Protocol != "qwen-coding-plan-v1" || response.AccountProvenance != "configured_cli_profile" || response.TimestampProvenance != "local_cli_acquisition_time" || response.ObservedAtMS <= 0 || response.ObservedAtMS > now.Add(time.Minute).UnixMilli() || now.Sub(time.UnixMilli(response.ObservedAtMS)) > 5*time.Minute || len(response.Groups) != 1 || len(response.Groups[0].Buckets) != 3 {
		return obs
	}
	seen := map[string]bool{}
	obs.QueryStatus = "success"
	obs.ErrorCode = ""
	obs.TimestampProvenance = response.TimestampProvenance
	obs.ReceivedAtMS = now.UnixMilli()
	obs.ObservedAtMS = response.ObservedAtMS
	obs.Complete = true
	obs.RecoveryEligible = true
	for _, bucket := range response.Groups[0].Buckets {
		if bucket.Window == "" || seen[bucket.Window] || bucket.RemainingFraction < 0 || bucket.RemainingFraction > 1 || math.IsNaN(bucket.RemainingFraction) || math.IsInf(bucket.RemainingFraction, 0) {
			obs.QueryStatus = "parse_error"
			obs.ErrorCode = "INVALID_QWEN_QUOTA_WINDOWS"
			obs.Windows = nil
			obs.Complete = false
			obs.RecoveryEligible = false
			return obs
		}
		reset, err := time.Parse(time.RFC3339Nano, bucket.ResetTime)
		if err != nil || !reset.After(now) {
			obs.QueryStatus = "parse_error"
			obs.ErrorCode = "INVALID_QWEN_QUOTA_WINDOWS"
			obs.Windows = nil
			obs.Complete = false
			obs.RecoveryEligible = false
			return obs
		}
		seen[bucket.Window] = true
		status := "allowed"
		if bucket.RemainingFraction == 0 {
			status = "rate-limited"
			obs.RecoveryEligible = false
		}
		name := map[string]string{"5h": "rolling", "week": "weekly", "billing_month": "monthly"}[bucket.Window]
		if name == "" {
			obs.QueryStatus = "parse_error"
			obs.ErrorCode = "INVALID_QWEN_QUOTA_WINDOWS"
			obs.Windows = nil
			obs.Complete = false
			obs.RecoveryEligible = false
			return obs
		}
		obs.Windows = append(obs.Windows, resource.QuotaWindow{Name: name, UsedPercent: (1 - bucket.RemainingFraction) * 100, RemainingFraction: bucket.RemainingFraction, ResetAt: bucket.ResetTime, SourceStatus: status})
	}
	if !seen["5h"] || !seen["week"] || !seen["billing_month"] {
		obs.QueryStatus = "parse_error"
		obs.ErrorCode = "INVALID_QWEN_QUOTA_WINDOWS"
		obs.Windows = nil
		obs.Complete = false
		obs.RecoveryEligible = false
	}
	return obs
}

type qwenCLIAttemptReceipt struct {
	Version     int    `json:"version"`
	State       string `json:"state"`
	ObservedAt  string `json:"observedAt"`
	CacheSHA256 string `json:"cacheSHA256"`
}

// qwenCLIReceiptValid is the host-owned enrollment fence for the existing CLI
// lane. A successful plugin response is policy-capable only when it matches the
// configured cache, its atomic latest-attempt receipt, and the selected source.
func (h *Handler) qwenCLIReceiptValid(a *coreauth.Auth, response pluginapi.QuotaFetchResponse) bool {
	cacheFile, ok := h.qwenCLICacheFile(a)
	if !ok || response.ObservedAtMS <= 0 {
		return false
	}
	cache, err := os.ReadFile(cacheFile)
	if err != nil || len(cache) == 0 {
		return false
	}
	receiptBody, err := os.ReadFile(cacheFile + ".attempt.json")
	if err != nil || len(receiptBody) > 16<<10 {
		return false
	}
	var receipt qwenCLIAttemptReceipt
	if json.Unmarshal(receiptBody, &receipt) != nil || receipt.Version != 1 || receipt.State != "success" || len(receipt.CacheSHA256) != 64 {
		return false
	}
	hash := sha256.Sum256(cache)
	if !strings.EqualFold(hex.EncodeToString(hash[:]), receipt.CacheSHA256) {
		return false
	}
	observed, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
	return err == nil && observed.UnixMilli() == response.ObservedAtMS && response.TimestampProvenance == "local_cli_acquisition_time" && response.Protocol == "qwen-coding-plan-v1" && response.AccountProvenance == "configured_cli_profile" && qwenCacheMatchesResponse(cache, response)
}

func qwenCacheMatchesResponse(cache []byte, response pluginapi.QuotaFetchResponse) bool {
	var saved struct {
		Protocol    string `json:"protocol"`
		Product     string `json:"product"`
		QueryStatus string `json:"queryStatus"`
		Windows     []struct {
			Window    string `json:"window"`
			Used      string `json:"used"`
			Total     string `json:"total"`
			ResetTime string `json:"resetTime"`
		} `json:"windows"`
	}
	if json.Unmarshal(cache, &saved) != nil || saved.Protocol != "qwen-coding-plan-v1" || saved.Product != "coding-plan" || saved.QueryStatus != "success" || len(saved.Windows) != 3 || len(response.Groups) != 1 || len(response.Groups[0].Buckets) != 3 {
		return false
	}
	for _, savedWindow := range saved.Windows {
		used, okUsed := new(big.Int).SetString(savedWindow.Used, 10)
		total, okTotal := new(big.Int).SetString(savedWindow.Total, 10)
		if !okUsed || !okTotal || total.Sign() <= 0 || used.Cmp(total) > 0 {
			return false
		}
		difference := new(big.Int).Sub(new(big.Int).Set(total), used)
		want, _ := new(big.Float).SetPrec(256).SetRat(new(big.Rat).SetFrac(difference, total)).Float64()
		matched := false
		for _, bucket := range response.Groups[0].Buckets {
			if bucket.Window == savedWindow.Window && bucket.ResetTime == savedWindow.ResetTime && bucket.RemainingFraction == want {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func (h *Handler) qwenCLICacheFile(a *coreauth.Auth) (string, bool) {
	if a == nil {
		return "", false
	}
	h.mu.Lock()
	cfg := h.cfg.Plugins.Configs[a.SourcePluginID]
	var raw map[string]any
	_ = cfg.Raw.Decode(&raw)
	h.mu.Unlock()
	args, ok := raw["command-args"].([]any)
	if !ok {
		return "", false
	}
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(fmt.Sprint(args[i]))
		if !strings.HasPrefix(arg, "--") {
			continue
		}
		name, value, has := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if !has && i+1 < len(args) && !strings.HasPrefix(strings.TrimSpace(fmt.Sprint(args[i+1])), "--") {
			value = strings.TrimSpace(fmt.Sprint(args[i+1]))
			i++
		}
		if name == "cache-file" && value != "" {
			return value, true
		}
	}
	return "", false
}
