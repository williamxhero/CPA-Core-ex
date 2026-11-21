package auth

import (
	"context"
	"slices"
	"sort"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SchedulingCandidateDecision contains only allowlisted scheduling facts. A
// missing resource ID means the runtime row has no catalog binding.
type SchedulingCandidateDecision struct {
	ResourceID string   `json:"resource_id,omitempty"`
	Family     string   `json:"family"`
	Priority   int      `json:"priority"`
	Registered bool     `json:"registered"`
	Eligible   bool     `json:"eligible"`
	Available  bool     `json:"available"`
	Reasons    []string `json:"reasons,omitempty"`
}

// SchedulingDecision is one redacted route evaluation for an authenticated request.
type SchedulingDecision struct {
	Mode               string                        `json:"mode"`
	Model              string                        `json:"model"`
	SelectedResourceID string                        `json:"selected_resource_id,omitempty"`
	Candidates         []SchedulingCandidateDecision `json:"candidates"`
}

type schedulingDecisionKey struct{}

// WithSchedulingDecisionObserver attaches a request-local sink for read-only
// snapshots; it is not invoked under the manager, selector or reservation locks.
func WithSchedulingDecisionObserver(ctx context.Context, observer func(SchedulingDecision)) context.Context {
	if observer == nil {
		return ctx
	}
	return context.WithValue(ctx, schedulingDecisionKey{}, observer)
}

func schedulingDecisionObserver(ctx context.Context) func(SchedulingDecision) {
	fn, _ := ctx.Value(schedulingDecisionKey{}).(func(SchedulingDecision))
	return fn
}

func schedulingDiagnosticFamily(a *Auth) string {
	if isConfiguredOpenAICompatAuth(a) {
		return "openai-compatible"
	}
	switch a.Provider {
	case "antigravity", "claude", "codex", "gemini", "gemini-cli", "gemini-vertex", "vertex", "xai", "kimi", "meta", "aistudio", "devin", "interactions":
		return a.Provider
	default:
		return "other"
	}
}

func (m *Manager) schedulingView(mode, model string, candidates []scheduledCandidate, selected *Auth) SchedulingDecision {
	d := SchedulingDecision{Mode: mode, Model: model, Candidates: make([]SchedulingCandidateDecision, 0, len(candidates))}
	d.SelectedResourceID, _ = schedulingResource(selected)
	for _, candidate := range candidates {
		id, _ := schedulingResource(candidate.auth)
		row := SchedulingCandidateDecision{ResourceID: id, Family: schedulingDiagnosticFamily(candidate.auth), Priority: authPriority(candidate.auth), Registered: !slices.Contains(candidate.reasons, "model_not_registered"), Eligible: true, Available: len(candidate.reasons) == 0, Reasons: slices.Clone(candidate.reasons)}
		for _, reason := range candidate.reasons {
			switch reason {
			case "model_not_registered", "provider_out_of_scope", "protocol_incompatible", "streaming_incompatible", "tools_incompatible", "image_incompatible", "reasoning_incompatible", "hard_binding", "caller_ineligible", "funding_ineligible":
				row.Eligible = false
			}
		}
		d.Candidates = append(d.Candidates, row)
	}
	m.appendSchedulingInventory(&d)
	sort.SliceStable(d.Candidates, func(i, j int) bool {
		left, right := d.Candidates[i], d.Candidates[j]
		if left.Family != right.Family {
			return left.Family < right.Family
		}
		if left.ResourceID != right.ResourceID {
			return left.ResourceID < right.ResourceID
		}
		return left.Priority > right.Priority
	})
	return d
}

// SchedulingCandidateSnapshot runs the pure candidate pass against the current
// registry, policy and capacity. It never rotates aliases, picks or reserves.
func (m *Manager) SchedulingCandidateSnapshot(ctx context.Context, providers []string, model string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) SchedulingDecision {
	return m.schedulingSnapshot(ctx, providers, model, m.scheduleRequestOptions(req, opts), nil)
}

func (m *Manager) schedulingSnapshot(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) SchedulingDecision {
	candidates, _ := m.scheduledCandidates(ctx, providers, model, opts, tried, m.getContinuityClock().Now())
	m.providerSchedulingUse.mu.Lock()
	m.scheduledAvailable(candidates, model)
	m.providerSchedulingUse.mu.Unlock()
	return m.schedulingView(m.providerSchedulingMode(ctx, model), model, candidates, nil)
}
