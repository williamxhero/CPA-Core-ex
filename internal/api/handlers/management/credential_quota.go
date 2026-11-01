package management

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	s := resource.QuotaSource{Binding: *a.ResourceIdentity, AuthIndex: a.Index, State: "unsupported", Reason: "quota_protocol_unverified", AccountProvenance: "unverified", Protocol: "unavailable", ManualDisabled: a.Disabled}
	switch {
	case a.SourcePluginID == "qwen-cliproxyapi":
		s.State = "needs_configuration"
		s.Reason = "account_authority_unverified"
		s.Protocol = "qwen-console"
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
		if !credentialquota.AllowedEndpoint(h.quotaPluginEndpoint(a) + "/usage") {
			s.State = "needs_configuration"
			s.Reason = "plugin_origin_unverified"
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
	return s
}

// Resolve the SAME effective endpoint as the known plugin: explicit auth first,
// current instance config second, documented native default last. Never labels.
func (h *Handler) quotaPluginEndpoint(a *coreauth.Auth) string {
	endpoint := strings.TrimSpace(a.Attributes["base_url"])
	if endpoint == "" {
		h.mu.Lock()
		cfg := h.cfg.Plugins.Configs[a.SourcePluginID]
		var raw map[string]any
		_ = cfg.Raw.Decode(&raw)
		endpoint, _ = raw["base-url"].(string)
		h.mu.Unlock()
	}
	if strings.TrimSpace(endpoint) == "" {
		endpoint = "https://opencode.ai/zen/go/v1"
	}
	return strings.TrimRight(strings.TrimSpace(endpoint), "/")
}

func (h *Handler) quotaSources(ctx context.Context) ([]resource.QuotaSource, bool) {
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		return nil, false
	}
	snapshot, err := h.resourceCatalog.Snapshot()
	if err != nil {
		return nil, false
	}
	out := []resource.QuotaSource{}
	bound := map[string]bool{}
	for _, a := range h.authManager.List() {
		if h.resourceCatalog.BindingCurrent(a.ResourceIdentity) {
			out = append(out, h.quotaSource(ctx, a))
			for _, t := range a.ResourceIdentity.Targets {
				bound[t.ResourceID] = true
			}
		}
	}
	for _, r := range snapshot.Resources {
		if (r.Kind == "credential" || r.Kind == "provider" && len(r.Members) == 0) && !bound[r.ResourceID] {
			out = append(out, resource.QuotaSource{Binding: resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{r.Target}}, Protocol: "unavailable", State: "unsupported", Reason: "runtime_binding_unavailable", AccountProvenance: "unverified", ManualDisabled: r.Manual.Disabled})
		}
	}
	return out, true
}

func (h *Handler) CredentialQuotaSources(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()
	sources, ok := h.quotaSources(ctx)
	if !ok {
		c.JSON(503, gin.H{"error": "resource_inventory_unavailable"})
		return
	}
	c.JSON(200, gin.H{"version": 1, "sources": sources})
}

func (h *Handler) selectedQuota(q resource.QuotaQuery) (*coreauth.Auth, bool) {
	if h.resourceCatalog == nil || h.resourceModeReason() != "" || q.AuthIndex == "" || len(q.Targets) == 0 || len(q.Targets) > 64 {
		return nil, false
	}
	a := h.authByIndex(q.AuthIndex)
	if a == nil || !h.resourceCatalog.BindingCurrent(a.ResourceIdentity) || !reflect.DeepEqual(*a.ResourceIdentity, q.Binding) {
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
	obs := resource.QuotaObservation{Binding: q.Binding, Protocol: source.Protocol, QueryStatus: source.State, ErrorCode: source.Reason, ObservedAtMS: time.Now().UnixMilli(), AccountProvenance: source.AccountProvenance}
	if source.State == "ready" {
		if source.Protocol == "codex-oauth-wham" {
			obs = credentialquota.Codex(ctx, q.Binding, a.Metadata, n)
		} else {
			// Both in-process and compiled plugins use this invocation-scoped bridge.
			// It records only this selected quota request, with no generic HTTP fallback.
			endpoint := h.quotaPluginEndpoint(a)
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
	if _, ok = h.selectedQuota(q); !ok {
		c.JSON(409, gin.H{"error": "identity_changed"})
		return
	}
	if obs.ProtocolVersion == 0 {
		obs.ProtocolVersion = 1
		obs.ReceivedAtMS = time.Now().UnixMilli()
		obs.TimestampProvenance = "core_attempt_time"
	}
	c.JSON(200, obs)
}
