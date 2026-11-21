package auth

import (
	"context"
	"slices"
	"sort"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// SchedulingCandidateDecision contains only allowlisted scheduling facts. A
// missing resource ID means the runtime row has no catalog binding.
type SchedulingCandidateDecision struct {
	ResourceID string         `json:"resource_id,omitempty"`
	Family     string         `json:"family"`
	Priority   int            `json:"priority"`
	Registered bool           `json:"registered"`
	Eligible   bool           `json:"eligible"`
	Available  bool           `json:"available"`
	Reasons    []string       `json:"reasons,omitempty"`
	Refresh    SchedulingTime `json:"refresh"`
	Recheck    SchedulingTime `json:"recheck"`
}

type SchedulingTime struct {
	State string     `json:"state"`
	At    *time.Time `json:"at,omitempty"`
}

type SchedulingCounts struct {
	Inventory  int `json:"inventory"`
	Registered int `json:"registered"`
	Eligible   int `json:"eligible"`
	Available  int `json:"available"`
	Reserved   int `json:"reserved"`
	Excluded   int `json:"excluded"`
	Selected   int `json:"selected"`
}

// SchedulingDecision is one redacted route evaluation for an authenticated request.
type SchedulingDecision struct {
	Source              string                        `json:"source,omitempty"`
	Coverage            string                        `json:"coverage,omitempty"`
	Reason              string                        `json:"reason,omitempty"`
	TransportVisibility string                        `json:"transport_visibility,omitempty"`
	Mode                string                        `json:"mode"`
	Model               string                        `json:"model"`
	SelectedResourceID  string                        `json:"selected_resource_id,omitempty"`
	Candidates          []SchedulingCandidateDecision `json:"candidates"`
	Counts              SchedulingCounts              `json:"counts"`
	OmittedCandidates   int                           `json:"omitted_candidates,omitempty"`
	ActualResourceID    string                        `json:"actual_resource_id,omitempty"`
	ProposedResourceID  string                        `json:"proposed_resource_id,omitempty"`
	Proposal            string                        `json:"proposal,omitempty"`
	Comparison          string                        `json:"comparison,omitempty"`
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

func wantsSchedulingDecision(ctx context.Context) bool {
	return routingTraceCollects(ctx) || schedulingDecisionObserver(ctx) != nil
}

func publishSchedulingDecision(ctx context.Context, decision SchedulingDecision) {
	recordRoutingStage(ctx, decision)
	if sink := schedulingDecisionObserver(ctx); sink != nil {
		sink(decision)
	}
}

func schedulingKnownTime(t time.Time) SchedulingTime {
	if t.IsZero() {
		return SchedulingTime{State: "unknown"}
	}
	at := t.UTC()
	return SchedulingTime{State: "known", At: &at}
}

func cloneSchedulingRows(rows []SchedulingCandidateDecision) []SchedulingCandidateDecision {
	out := append([]SchedulingCandidateDecision{}, rows...)
	for i := range out {
		row := &out[i]
		row.ResourceID = catalogRoutingID(row.ResourceID)
		row.Reasons = slices.Clone(row.Reasons)
		if row.Refresh.At != nil {
			at := *row.Refresh.At
			row.Refresh.At = &at
		}
		if row.Recheck.At != nil {
			at := *row.Recheck.At
			row.Recheck.At = &at
		}
	}
	return out
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

func (m *Manager) schedulingView(mode, model string, candidates []scheduledCandidate, selected *Auth, bound string) SchedulingDecision {
	d := SchedulingDecision{Mode: mode, Model: model, Candidates: make([]SchedulingCandidateDecision, 0, len(candidates))}
	d.SelectedResourceID, _ = schedulingResource(selected)
	for _, candidate := range candidates {
		id, _ := schedulingResource(candidate.auth)
		row := SchedulingCandidateDecision{ResourceID: id, Family: schedulingDiagnosticFamily(candidate.auth), Priority: authPriority(candidate.auth), Registered: !slices.Contains(candidate.reasons, "model_not_registered"), Eligible: true, Available: len(candidate.reasons) == 0, Reasons: slices.Clone(candidate.reasons)}
		if bound != "" && candidate.auth.ID != bound {
			row.Reasons = appendSchedulingReason(row.Reasons, "hard_binding")
			row.Available = false
		}
		if candidate.diagnosticExpired {
			row.Reasons = appendSchedulingReason(row.Reasons, "access_token_expired")
		}
		if candidate.diagnosticQuota {
			row.Reasons = appendSchedulingReason(row.Reasons, "credential_quota")
		}
		last, _ := authLastRefreshTimestamp(candidate.auth)
		if candidate.auth.LastRefreshedAt.After(last) {
			last = candidate.auth.LastRefreshedAt
		}
		row.Refresh = schedulingKnownTime(last)
		recheck := candidate.diagnosticQuotaAt
		if recheck.IsZero() {
			recheck = candidate.retryAt
		}
		row.Recheck = schedulingKnownTime(recheck)
		for _, reason := range row.Reasons {
			switch reason {
			case "model_not_registered", "provider_out_of_scope", "protocol_incompatible", "streaming_incompatible", "tools_incompatible", "image_incompatible", "reasoning_incompatible", "hard_binding", "caller_ineligible", "funding_ineligible":
				row.Eligible = false
			}
		}
		d.Candidates = append(d.Candidates, row)
	}
	m.appendSchedulingInventory(&d)
	d.Counts.Inventory = len(d.Candidates)
	for _, row := range d.Candidates {
		if row.Registered {
			d.Counts.Registered++
		}
		if row.Eligible {
			d.Counts.Eligible++
		}
		if row.Available {
			d.Counts.Available++
		}
		if slices.Contains(row.Reasons, "request_excluded") {
			d.Counts.Excluded++
		}
	}
	if selected != nil {
		d.Counts.Selected = 1
		if len(schedulingLimits(m.runtimeConfigSnapshot().Routing.ProviderScheduling, selected)) > 0 {
			d.Counts.Reserved = 1
		}
	}
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
	candidates, selector := m.scheduledCandidates(ctx, providers, model, opts, tried, m.getContinuityClock().Now())
	bound := scheduledHardAffinity(selector, model, opts)
	m.providerSchedulingUse.mu.Lock()
	available, _ := m.scheduledAvailable(candidates, model)
	m.providerSchedulingUse.mu.Unlock()
	view := m.schedulingView(m.providerSchedulingMode(ctx, model), model, candidates, nil, bound)
	if bound != "" {
		available = slices.DeleteFunc(available, func(a *Auth) bool { return a.ID != bound })
	} else {
		available = highestPriorityAuths(available)
	}
	if len(available) > 1 {
		if affinity, ok := selector.(*SessionAffinitySelector); ok {
			pinned, _ := affinity.resolveBoundAuth(nil, selectionArgForSelector(selector, model), opts, true)
			idx := slices.IndexFunc(available, func(a *Auth) bool { return a.ID == pinned })
			if idx >= 0 {
				available = available[idx : idx+1]
			}
			selector = affinity.fallback
		}
	}
	if _, fill := selector.(*FillFirstSelector); fill && len(available) > 1 {
		available = available[:1]
	}
	switch len(available) {
	case 0:
		view.Proposal = "no_available_route"
	case 1:
		id, _ := schedulingResource(available[0])
		view.ProposedResourceID = catalogRoutingID(id)
		view.Proposal = "available"
	default:
		view.Proposal = "equally_ranked"
	}
	return view
}
