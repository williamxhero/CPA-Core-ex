package resourcecatalog

import (
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// Auto-stop projection states. They describe the durable gate ledger only: a
// manual `disabled` or `auto-held` intent is never an automatic pause and is
// deliberately absent from this projection.
const (
	AutoStopStateAvailable         = "available"
	AutoStopStatePaused            = "auto_paused"
	AutoStopStatePartiallyPaused   = "partially_auto_paused"
	autoStopMemberStatePaused      = "paused"
	autoStopMemberStateAvailable   = "available"
	autoStopProjectionContractVers = 1
)

// AutoStopReason attributes a pause to the owned gate that published it. The
// observation time is the sealed evidence timestamp, or zero for owners whose
// evidence carries no clock, so callers can tell "unknown" from "now".
type AutoStopReason struct {
	Owner        string `json:"owner"`
	Reason       string `json:"reason"`
	ObservedAtMS int64  `json:"observedAtMs"`
	ResourceID   string `json:"resourceId"`
}

// AutoStopMember is one credential-level member of a provider group.
type AutoStopMember struct {
	ResourceID string           `json:"resourceId"`
	State      string           `json:"state"`
	Reasons    []AutoStopReason `json:"reasons"`
}

// AutoStopProvider is one access point (provider group) with its members. Its
// reasons are the union of the member reasons, so a partial pause names the
// affected credential.
type AutoStopProvider struct {
	ResourceID  string           `json:"resourceId"`
	State       string           `json:"state"`
	MemberCount int              `json:"memberCount"`
	PausedCount int              `json:"pausedCount"`
	Reasons     []AutoStopReason `json:"reasons"`
	Members     []AutoStopMember `json:"members"`
}

// AutoStopProjection is the read-only management view of automatic pauses.
type AutoStopProjection struct {
	Version   int                `json:"version"`
	Ready     bool               `json:"ready"`
	Revision  uint64             `json:"revision"`
	Providers []AutoStopProvider `json:"providers"`
}

// gateObservedAtMS returns the sealed observation time of one gate. Only the
// owners whose evidence encodes a timestamp report one; everything else is 0
// rather than a fabricated clock.
func gateObservedAtMS(g resource.Gate) int64 {
	if stamp := BalanceGateObservedAtMS(g.Owner, g.EvidenceID); stamp > 0 {
		return stamp
	}
	if facts, _ := QuotaGateDetails(g.Owner, g.EvidenceID); facts != nil && facts.ObservedAtMS > 0 {
		return facts.ObservedAtMS
	}
	if facts := FundingGateDetails(g.Owner, g.EvidenceID); facts != nil && facts.ObservedAtMS > 0 {
		return facts.ObservedAtMS
	}
	return 0
}

// autoStopGatePauses reports whether one current gate pauses this member. A
// provider-subject gate covers the whole group; a credential-subject gate only
// covers the member whose lifecycle it was published against. Both checks are
// the same identity test routing uses, so a drifted incarnation is not paused.
func autoStopGatePauses(g resource.Gate, group, member resource.Row) bool {
	if g.Subject == "provider" {
		return len(g.Targets) > 0 && sameGateLifecycle(g.Targets[0], group.Target)
	}
	for _, t := range g.Targets {
		if sameGateLifecycle(t, member.Target) {
			return true
		}
	}
	return false
}

// AutoStopProjection publishes the current automatic pauses per provider group.
// It mutates nothing: an unavailable or unreadable ledger is an error, never an
// empty "everything is available" answer.
func (c *Catalog) AutoStopProjection() (AutoStopProjection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := c.gateStateLocked()
	if err != nil {
		return AutoStopProjection{}, err
	}
	return c.autoStopProjectionLocked(state), nil
}

func (c *Catalog) autoStopProjectionLocked(state resource.GateState) AutoStopProjection {
	projection := AutoStopProjection{Version: autoStopProjectionContractVers, Ready: state.Ready, Revision: state.Revision, Providers: []AutoStopProvider{}}
	if !state.Ready {
		return projection
	}
	groups := make([]resource.Row, 0, len(c.snapshot.Resources))
	members := map[string][]resource.Row{}
	for _, row := range c.snapshot.Resources {
		if row.Kind == "provider" && row.ParentID == "" {
			groups = append(groups, row)
			continue
		}
		if row.Kind == "credential" && row.ParentID != "" {
			members[row.ParentID] = append(members[row.ParentID], row)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ResourceID < groups[j].ResourceID })
	for _, group := range groups {
		owned := members[group.ResourceID]
		sort.Slice(owned, func(i, j int) bool { return owned[i].ResourceID < owned[j].ResourceID })
		view := AutoStopProvider{ResourceID: group.ResourceID, MemberCount: len(owned), Reasons: []AutoStopReason{}, Members: make([]AutoStopMember, 0, len(owned))}
		for _, member := range owned {
			entry := AutoStopMember{ResourceID: member.ResourceID, State: autoStopMemberStateAvailable, Reasons: []AutoStopReason{}}
			for _, gate := range state.Gates {
				if gate.Applicability != "current" || !autoStopGatePauses(gate, group, member) {
					continue
				}
				entry.Reasons = append(entry.Reasons, AutoStopReason{Owner: gate.Owner, Reason: gate.Reason, ObservedAtMS: gateObservedAtMS(gate), ResourceID: member.ResourceID})
			}
			if len(entry.Reasons) > 0 {
				entry.State = autoStopMemberStatePaused
				view.PausedCount++
				view.Reasons = append(view.Reasons, entry.Reasons...)
			}
			view.Members = append(view.Members, entry)
		}
		view.State = AutoStopStateAvailable
		if view.MemberCount > 0 && view.PausedCount == view.MemberCount {
			view.State = AutoStopStatePaused
		} else if view.PausedCount > 0 {
			view.State = AutoStopStatePartiallyPaused
		}
		projection.Providers = append(projection.Providers, view)
	}
	return projection
}
