package auth

import (
	"context"
	"slices"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

type schedulingInventoryReader struct {
	snapshot func() (resource.Snapshot, error)
}

// SetSchedulingInventory shares the existing catalog's read view for diagnostics.
// Catalog rows do not participate in dispatch or create runtime auths.
func (m *Manager) SetSchedulingInventory(snapshot func() (resource.Snapshot, error)) {
	if snapshot == nil {
		m.schedulingInventory.Store(nil)
	} else {
		m.schedulingInventory.Store(&schedulingInventoryReader{snapshot})
	}
}

type schedulingInventoryClaim struct {
	id, owner, family string
	priority          int
	reason            string
}

func configuredSchedulingModelMatches(model, prefix string, forcePrefix bool, entries []modelAliasEntry) bool {
	for _, entry := range entries {
		id := strings.TrimSpace(entry.GetAlias())
		if id == "" {
			id = strings.TrimSpace(entry.GetName())
		}
		if id == "" {
			continue
		}
		if (prefix == "" || !forcePrefix || prefix == id) && sameCanonicalModelKey(id, model) {
			return true
		}
		if prefix != "" && sameCanonicalModelKey(prefix+"/"+id, model) {
			return true
		}
	}
	return false
}

func configuredSchedulingClaims(cfg *internalconfig.Config, model string) []schedulingInventoryClaim {
	var claims []schedulingInventoryClaim
	add := func(id, owner, family, prefix string, priority int, models []modelAliasEntry, disabled, held bool) {
		if !configuredSchedulingModelMatches(model, prefix, cfg.ForceModelPrefix, models) {
			return
		}
		reason := ""
		if disabled {
			reason = "manual_disabled"
		} else if held {
			reason = "inference_admission_blocked"
		}
		claims = append(claims, schedulingInventoryClaim{id, owner, family, priority, reason})
	}
	for _, group := range cfg.OpenAICompatibility {
		owner := util.OpenAICompatibleProviderKey(group.Name)
		if len(group.APIKeyEntries) == 0 {
			add(group.ResourceID, owner, "openai-compatible", group.Prefix, group.Priority, asModelAliasEntries(group.Models), group.Disabled, group.AutoHeld)
			continue
		}
		for _, entry := range group.APIKeyEntries {
			add(entry.ResourceID, owner, "openai-compatible", group.Prefix, group.Priority, asModelAliasEntries(group.Models), group.Disabled, group.AutoHeld)
		}
	}
	for _, entry := range cfg.CodexKey {
		add(entry.ResourceID, "codex", "codex", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	for _, entry := range cfg.ClaudeKey {
		add(entry.ResourceID, "claude", "claude", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	for _, entry := range cfg.GeminiKey {
		add(entry.ResourceID, "gemini", "gemini", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	for _, entry := range cfg.InteractionsKey {
		add(entry.ResourceID, "interactions", "interactions", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	for _, entry := range cfg.XAIKey {
		add(entry.ResourceID, "xai", "xai", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	for _, entry := range cfg.MetaKey {
		add(entry.ResourceID, "meta", "meta", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	for _, entry := range cfg.VertexCompatAPIKey {
		add(entry.ResourceID, "vertex", "vertex", entry.Prefix, entry.Priority, asModelAliasEntries(entry.Models), false, entry.AutoHeld)
	}
	return claims
}

// KnownScheduledProviders distinguishes explicitly configured but currently
// unregistered models from unknown models. Registration remains mandatory to
// dispatch any configured model.
func (m *Manager) KnownScheduledProviders(ctx context.Context, model string) []string {
	if !m.ProviderSchedulingEnforced(ctx, model) {
		return nil
	}
	var out []string
	for _, claim := range configuredSchedulingClaims(m.runtimeConfigSnapshot(), model) {
		if !slices.Contains(out, claim.owner) {
			out = append(out, claim.owner)
		}
	}
	return out
}

func (m *Manager) appendSchedulingInventory(view *SchedulingDecision) {
	claims := configuredSchedulingClaims(m.runtimeConfigSnapshot(), view.Model)
	reader := m.schedulingInventory.Load()
	if reader == nil {
		return
	}
	snapshot, err := reader.snapshot()
	if err != nil || !snapshot.Complete {
		return
	}
	claimed := make(map[string]schedulingInventoryClaim, len(claims))
	for _, c := range claims {
		if c.id != "" {
			claimed[c.id] = c
		}
	}
	present := make(map[string]struct{}, len(view.Candidates))
	for _, c := range view.Candidates {
		if c.ResourceID != "" {
			present[c.ResourceID] = struct{}{}
		}
	}
	for _, row := range snapshot.Resources {
		if row.Kind != "credential" && row.Kind != "provider" {
			continue
		}
		if _, exists := present[row.ResourceID]; exists {
			continue
		}
		c, matched := claimed[row.ResourceID]
		if !matched {
			// Only show a route when a configured model claim exists; the
			// catalog inventory alone does not advertise model membership.
			continue
		}
		reasons := []string{"model_not_registered"}
		if row.Manual.Disabled {
			reasons = append(reasons, "manual_disabled")
		} else if c.reason != "" {
			reasons = append(reasons, c.reason)
		}
		view.Candidates = append(view.Candidates, SchedulingCandidateDecision{
			ResourceID: row.ResourceID, Family: c.family, Priority: c.priority, Reasons: reasons,
			Refresh: schedulingKnownTime(time.Time{}), Recheck: schedulingKnownTime(time.Time{}),
		})
	}
}
