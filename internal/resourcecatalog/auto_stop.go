package resourcecatalog

import (
	"sort"
	"strconv"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// Auto-stop projection states. They describe the durable gate ledger only.
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

// autoStopGateRef is one current gate with its observation time resolved once,
// so a wide ledger is not re-decoded per member.
type autoStopGateRef struct {
	gate       resource.Gate
	observedMS int64
}

// autoStopTargetKey buckets gates by the lifecycle identity that decides
// coverage — the one sameGateLifecycle compares — so a member only walks the
// gates that can reach it.
func autoStopTargetKey(t resource.Target) string {
	return t.ResourceID + "\x00" + t.Incarnation + "\x00" + strconv.FormatUint(t.IdentityVersion, 10) + "\x00" +
		strconv.FormatUint(t.CredentialVersion, 10) + "\x00" + strconv.FormatUint(t.MembershipVersion, 10)
}

// autoStopMemberGateIndexes merges the provider and credential buckets of one
// member back into ledger order, which is the order reasons have always kept.
func autoStopMemberGateIndexes(provider, credential []int) []int {
	if len(provider) == 0 {
		return credential
	}
	if len(credential) == 0 {
		return provider
	}
	merged := make([]int, 0, len(provider)+len(credential))
	i, j := 0, 0
	for i < len(provider) && j < len(credential) {
		if provider[i] <= credential[j] {
			merged = append(merged, provider[i])
			i++
			continue
		}
		merged = append(merged, credential[j])
		j++
	}
	merged = append(merged, provider[i:]...)
	return append(merged, credential[j:]...)
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
	refs := make([]autoStopGateRef, 0, len(state.Gates))
	byProviderTarget := map[string][]int{}
	byCredentialTarget := map[string][]int{}
	for _, gate := range state.Gates {
		if gate.Applicability != "current" {
			continue
		}
		// A model-scoped pause leaves the rest of the member routable, so it
		// must not colour the whole access point as stopped.
		if gate.Model != "" {
			continue
		}
		index := len(refs)
		refs = append(refs, autoStopGateRef{gate: gate, observedMS: gateObservedAtMS(gate)})
		if gate.Subject == "provider" {
			if len(gate.Targets) > 0 {
				key := autoStopTargetKey(gate.Targets[0])
				byProviderTarget[key] = append(byProviderTarget[key], index)
			}
			continue
		}
		// A gate naming the same lifecycle twice still pauses the member once.
		seen := make(map[string]struct{}, len(gate.Targets))
		for _, target := range gate.Targets {
			key := autoStopTargetKey(target)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			byCredentialTarget[key] = append(byCredentialTarget[key], index)
		}
	}
	for _, group := range groups {
		owned := members[group.ResourceID]
		sort.Slice(owned, func(i, j int) bool { return owned[i].ResourceID < owned[j].ResourceID })
		providerGates := byProviderTarget[autoStopTargetKey(group.Target)]
		view := AutoStopProvider{ResourceID: group.ResourceID, MemberCount: len(owned), Reasons: []AutoStopReason{}, Members: make([]AutoStopMember, 0, len(owned))}
		for _, member := range owned {
			entry := AutoStopMember{ResourceID: member.ResourceID, State: autoStopMemberStateAvailable, Reasons: []AutoStopReason{}}
			for _, index := range autoStopMemberGateIndexes(providerGates, byCredentialTarget[autoStopTargetKey(member.Target)]) {
				ref := refs[index]
				entry.Reasons = append(entry.Reasons, AutoStopReason{Owner: ref.gate.Owner, Reason: ref.gate.Reason, ObservedAtMS: ref.observedMS, ResourceID: member.ResourceID})
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
