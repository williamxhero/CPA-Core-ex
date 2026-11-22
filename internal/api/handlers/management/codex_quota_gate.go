package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
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
		log.WithFields(log.Fields{
			"component": "credential_quota", "provider": "codex", "window": evidence.Window, "model": evidence.Model,
		}).Warn("Native scoped quota rejection could not publish")
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
	// The original inference response has already been read. This budget
	// applies only to the separate credential-authority acquisition GET.
	// A real WHAM read takes roughly one to two seconds on this host; the old
	// 200ms ceiling made every confirmation fail, so the first structured 429
	// never acquired its durable pause. Keep the read inside the request's
	// documented three-second active-wait budget.
	queryCtx, cancel := context.WithTimeout(ctx, codexWholeQuotaConfirmTimeout)
	defer cancel()
	obs := credentialquota.Codex(queryCtx, source.Binding, a.Metadata, network)
	if obs.AccountProvenance != source.AccountProvenance || !codexQuotaConfirmsWholeAccount(obs, evidence, time.Now()) {
		return false
	}
	current := h.currentRuntimeSource(a)
	return current != nil && reflect.DeepEqual(*current.ResourceIdentity, source.Binding) &&
		h.quotaSource(ctx, current).SourceVersion == source.SourceVersion
}

const codexWholeQuotaConfirmTimeout = 3 * time.Second

// codexQuotaConfirmsWholeAccount accepts the same exhausted standard window as
// the upstream rejection. Another standard window may still be below its own
// limit: the weekly cap still blocks the account until it resets, so requiring
// every window to be rate-limited kept plus/prolite weekly exhaustion from ever
// becoming a durable pause. Independent model limits and usable credits still
// forbid a whole-account decision.
func codexQuotaConfirmsWholeAccount(obs resource.QuotaObservation, evidence resource.CodexQuotaRejection, now time.Time) bool {
	if obs.QueryStatus != "success" || !obs.Complete || !obs.StandardOnlyNoCredits ||
		obs.TimestampProvenance != "upstream_http_date" || obs.ObservedAtMS < evidence.ObservedAtMS ||
		(len(obs.Windows) != 2 && len(obs.Windows) != 1) {
		return false
	}
	seen := map[string]bool{}
	confirmed := false
	for _, window := range obs.Windows {
		reset, err := time.Parse(time.RFC3339, window.ResetAt)
		if window.Model != "" || window.LimitName != "" || seen[window.Name] || err != nil || !reset.After(now) ||
			(window.SourceStatus != "rate-limited" && window.SourceStatus != "allowed") {
			return false
		}
		seen[window.Name] = true
		if window.Name == evidence.Window && window.LimitWindowSeconds == evidence.WindowSeconds &&
			window.CodexUsage == resource.CodexWindowUsageAtLimit &&
			reset.Sub(time.UnixMilli(evidence.ResetAtMS)).Abs() <= time.Minute {
			confirmed = true
		}
	}
	if !confirmed || !seen["primary"] || (!seen["secondary"] && evidence.WindowSeconds != 604800) {
		return false
	}
	return true
}

type codexQuotaRecheck struct {
	resource.Binding
	AuthIndex     string `json:"auth_index"`
	SourceID      string `json:"sourceId"`
	SubjectID     string `json:"subjectId"`
	SourceVersion string `json:"sourceVersion"`
	ObservedAtMS  int64  `json:"observedAtMs"`
	PublishedAtMS int64  `json:"publishedAtMs"`
	RecheckAtMS   int64  `json:"recheckAtMs"`
	ResetID       string `json:"resetId"`
}

// This read projects only current query authority. It cannot clear an
// existing pause or create a refresh; Manager still validates the live lease.
func (h *Handler) codexQuotaRechecks(ctx context.Context, state resource.GateState) []codexQuotaRecheck {
	if !state.Ready || h.authManager == nil {
		return nil
	}
	type pending struct {
		gate   resource.Gate
		due    *resource.QuotaGateEvidence
		intake int64
	}
	var due []pending
	for _, gate := range state.Gates {
		if gate.Applicability != "current" || len(gate.Targets) == 0 || gate.Subject == "provider" {
			continue
		}
		details, intake := resourcecatalog.QuotaGateDetails(gate.Owner, gate.EvidenceID)
		if details != nil && details.RecheckAtMS > 0 {
			due = append(due, pending{gate, details, intake})
		}
	}
	if len(due) == 0 {
		return nil
	}
	slices.SortFunc(due, func(a, b pending) int {
		if a.due.RecheckAtMS < b.due.RecheckAtMS {
			return -1
		}
		if a.due.RecheckAtMS > b.due.RecheckAtMS {
			return 1
		}
		return strings.Compare(a.gate.EvidenceID, b.gate.EvidenceID)
	})
	candidates := make(map[string]*coreauth.Auth)
	for _, a := range h.authManager.List() {
		if a != nil && ((a.Provider == "codex" && a.SourcePluginID == "") || a.SourcePluginID == "cpa-credential-opencode" || a.SourcePluginID == "cpa-credential-qwen") && a.ResourceIdentity != nil && len(a.ResourceIdentity.Targets) > 0 {
			id := a.ResourceIdentity.Targets[0].ResourceID
			if _, exists := candidates[id]; exists {
				candidates[id] = nil
			} else {
				candidates[id] = a
			}
		}
	}
	var out []codexQuotaRecheck
	leases := make(map[string]resource.QuotaSource)
	for _, item := range due {
		if ctx.Err() != nil {
			break
		}
		id := item.gate.Targets[0].ResourceID
		source, known := leases[id]
		if !known {
			if a := h.currentRuntimeSource(candidates[id]); a != nil && a.ResourceIdentity.Scope == state.Scope {
				source = h.quotaSource(ctx, a)
			}
			leases[id] = source
		}
		if (source.Protocol != "codex-oauth-wham" && source.Protocol != "opencode-go-usage" && source.Protocol != "qwen-coding-plan-cli") || source.State != "ready" || source.SourceVersion != item.gate.SourceVersion ||
			!h.resourceCatalog.CodexQuotaRecheckCurrent(state.Revision, item.gate, source.Binding) {
			continue
		}
		digest := sha256.Sum256([]byte(item.gate.EvidenceID))
		out = append(out, codexQuotaRecheck{
			Binding: source.Binding, AuthIndex: source.AuthIndex, SourceID: source.SourceID,
			SubjectID: source.SubjectID, SourceVersion: source.SourceVersion,
			ObservedAtMS: item.due.ObservedAtMS, PublishedAtMS: (item.intake-1)/int64(time.Millisecond) + 1, RecheckAtMS: item.due.RecheckAtMS,
			ResetID: hex.EncodeToString(digest[:]),
		})
	}
	return out
}

func quotaGateState(state resource.GateState, rechecks []codexQuotaRecheck) any {
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
		Gates         []gateView          `json:"gates"`
		QuotaRechecks []codexQuotaRecheck `json:"quotaRechecks,omitempty"`
	}{state, gates, rechecks}
}
