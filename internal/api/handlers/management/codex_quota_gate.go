package management

import (
	"context"
	"reflect"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialquota"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	log "github.com/sirupsen/logrus"
)

func (h *Handler) observeCodexQuotaRejection(ctx context.Context, dispatched *coreauth.Auth, start time.Time, evidence resource.CodexQuotaRejection) bool {
	if h.resourceCatalog == nil || dispatched.ResourceIdentity == nil {
		return false
	}
	current := h.currentRuntimeSource(dispatched)
	if current == nil || !reflect.DeepEqual(dispatched.ResourceIdentity.Targets, current.ResourceIdentity.Targets) {
		return false
	}
	source := h.quotaSource(ctx, current)
	if source.Protocol != "codex-oauth-wham" || source.State != "ready" || source.AccountProvenance != "selected_oauth_account" {
		return false
	}
	if evidence.Model == "" && !h.confirmWholeCodexQuota(ctx, current, source, evidence) {
		return false
	}
	handled, err := h.resourceCatalog.ObserveCodexQuotaRejection(source.Binding, source.AuthIndex, source.SourceVersion, start, evidence)
	if err != nil {
		log.Warn("native scoped quota rejection could not publish")
	}
	return handled
}

// The standard Codex bucket may coexist with separate model limits or
// spendable credits. Use the selected account's read-only quota operation to
// establish a provider-wide rejection, under the same bounded query slots.
func (h *Handler) confirmWholeCodexQuota(ctx context.Context, a *coreauth.Auth, source resource.QuotaSource, evidence resource.CodexQuotaRejection) bool {
	h.mu.Lock()
	if h.quotaSlots == nil {
		h.quotaSlots = make(chan struct{}, 4)
	}
	slots, network := h.quotaSlots, h.quotaNetwork
	h.mu.Unlock()
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		return false
	}
	queryCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	obs := credentialquota.Codex(queryCtx, source.Binding, a.Metadata, network)
	if obs.QueryStatus != "success" || !obs.Complete || !obs.StandardOnlyNoCredits ||
		obs.TimestampProvenance != "upstream_http_date" || obs.AccountProvenance != source.AccountProvenance ||
		obs.ObservedAtMS < evidence.ObservedAtMS || len(obs.Windows) != 2 {
		return false
	}
	seen := map[string]bool{}
	confirmed := false
	for _, window := range obs.Windows {
		reset, err := time.Parse(time.RFC3339, window.ResetAt)
		if window.Model != "" || window.SourceStatus != "rate-limited" || seen[window.Name] || err != nil || !reset.After(time.Now()) {
			return false
		}
		seen[window.Name] = true
		if window.Name == evidence.Window && window.LimitWindowSeconds == evidence.WindowSeconds && window.UsedPercent == 100 && reset.UnixMilli() == evidence.ResetAtMS {
			confirmed = true
		}
	}
	if !confirmed || !seen["primary"] || !seen["secondary"] {
		return false
	}
	current := h.currentRuntimeSource(a)
	return current != nil && reflect.DeepEqual(*current.ResourceIdentity, source.Binding) &&
		h.quotaSource(ctx, current).SourceVersion == source.SourceVersion
}

func quotaGateState(state resource.GateState) any {
	type gateView struct {
		resource.Gate
		Quota   *resource.QuotaGateEvidence   `json:"quota,omitempty"`
		Funding *resource.FundingGateEvidence `json:"funding,omitempty"`
	}
	var gates []gateView
	if state.Gates != nil {
		gates = make([]gateView, 0, len(state.Gates))
	}
	for _, gate := range state.Gates {
		facts, _ := resourcecatalog.QuotaGateDetails(gate.Owner, gate.EvidenceID)
		gates = append(gates, gateView{Gate: gate, Quota: facts, Funding: resourcecatalog.FundingGateDetails(gate.Owner, gate.EvidenceID)})
	}
	return struct {
		resource.GateState
		Gates []gateView `json:"gates"`
	}{state, gates}
}
