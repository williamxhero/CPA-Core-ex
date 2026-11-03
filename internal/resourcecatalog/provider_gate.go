package resourcecatalog

import (
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// ProviderGateBinding validates the complete issued provider/member closure.
// It proves catalog identity only, not runtime route coverage or funding.
func (c *Catalog) ProviderGateBinding(b resource.Binding) (resource.Binding, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.Binding{}, ErrUnavailable
	}
	return c.providerGateBindingLocked(b)
}

func (c *Catalog) providerGateBindingLocked(b resource.Binding) (resource.Binding, error) {
	if !c.snapshot.Complete || b.Scope != c.versionLocked() || len(b.Targets) < 2 || len(b.Targets) > 64 {
		return resource.Binding{}, ErrConflict
	}
	provided := make(map[string]resource.Target, len(b.Targets))
	parentID := ""
	for _, t := range b.Targets {
		if _, duplicate := provided[t.ResourceID]; duplicate {
			return resource.Binding{}, ErrConflict
		}
		r, ok := c.gateRowLocked(t.ResourceID)
		if !ok || r.Target != t {
			return resource.Binding{}, ErrConflict
		}
		provided[t.ResourceID] = t
		if r.Kind == "provider" {
			if parentID != "" {
				return resource.Binding{}, ErrConflict
			}
			parentID = r.ResourceID
		}
	}
	group, err := c.providerGroupLocked(parentID)
	if err != nil || len(group.Targets) != len(provided) {
		return resource.Binding{}, ErrConflict
	}
	for _, t := range group.Targets {
		if supplied, ok := provided[t.ResourceID]; !ok || supplied != t {
			return resource.Binding{}, ErrConflict
		}
	}
	return group, nil
}

// gateRowLocked rejects duplicate identities even if one duplicate looks ready.
func (c *Catalog) gateRowLocked(id string) (resource.Row, bool) {
	var row resource.Row
	count := 0
	for _, candidate := range c.snapshot.Resources {
		if candidate.ResourceID == id {
			row = candidate
			count++
		}
	}
	r := c.state.Records[id]
	return row, count == 1 && r != nil && !r.Deleted && !r.Blocked && r.Target == row.Target && row.Identity == "valid" && row.Readiness == "ready"
}

func (c *Catalog) providerGroupLocked(id string) (resource.Binding, error) {
	p, ok := c.gateRowLocked(id)
	if !ok || p.Kind != "provider" || p.ParentID != "" || len(p.SourceBindings) != 0 || len(p.Members) == 0 {
		return resource.Binding{}, ErrConflict
	}
	members := make(map[string]bool, len(p.Members))
	children := make([]resource.Target, 0, len(p.Members))
	for _, memberID := range p.Members {
		child, ready := c.gateRowLocked(memberID)
		if members[memberID] || !ready || child.Kind != "credential" || child.ParentID != id || child.Family != p.Family || len(child.Members) != 0 || !c.providerProjectionLocked(child) {
			return resource.Binding{}, ErrConflict
		}
		members[memberID] = true
		children = append(children, child.Target)
	}
	// Members must also cover every current child claiming this parent.
	for _, child := range c.snapshot.Resources {
		if child.ParentID == id && !members[child.ResourceID] {
			return resource.Binding{}, ErrConflict
		}
	}
	sort.Slice(children, func(i, j int) bool { return children[i].ResourceID < children[j].ResourceID })
	return resource.Binding{Scope: c.versionLocked(), Targets: append([]resource.Target{p.Target}, children...)}, nil
}

// Only an exact reciprocal, same-family materialized projection is proven by
// the current catalog contract. Multi-hop and cross-provider shapes fail closed.
func (c *Catalog) providerProjectionLocked(member resource.Row) bool {
	if len(member.SourceBindings) == 0 {
		return member.BindingState == "" || member.BindingState == "unmaterialized" || member.BindingState == "standalone"
	}
	if len(member.SourceBindings) != 1 || member.BindingState != "verified_projection" {
		return false
	}
	projection, ok := c.gateRowLocked(member.SourceBindings[0].ResourceID)
	return ok && projection.Target == member.SourceBindings[0] && projection.Kind == "credential" && projection.ParentID == "" && projection.Family == member.Family && len(projection.Members) == 0 && projection.BindingState == "verified_projection" && len(projection.SourceBindings) == 1 && projection.SourceBindings[0] == member.Target
}

// Catalog issuance advances identity and membership together on a roster edit.
// Equal incarnation plus exactly that version delta proves the same stable
// parent lineage, without accepting an independent identity replacement.
func sameProviderLineage(a, b resource.Target) bool {
	return a.ResourceID == b.ResourceID && a.Incarnation == b.Incarnation && b.IdentityVersion >= a.IdentityVersion && b.MembershipVersion >= a.MembershipVersion && b.IdentityVersion-a.IdentityVersion == b.MembershipVersion-a.MembershipVersion
}

// Runtime credential bindings stay unchanged. Parent attribution is derived
// afresh for every credential and its already-proven projection targets.
func (c *Catalog) providerParentsLocked(b *resource.Binding) (map[string]resource.Binding, error) {
	parents := map[string]resource.Binding{}
	for _, target := range b.Targets {
		row, ok := c.gateRowLocked(target.ResourceID)
		if !ok || row.Kind != "credential" || row.Target != target {
			return nil, ErrUnavailable
		}
		if row.ParentID == "" {
			if len(row.SourceBindings) == 0 {
				// A standalone plugin file may be a detached old projection.
				// Without a current reciprocal link, its independence from a
				// same-family provider restriction cannot be proven.
				if row.BindingState == "standalone" {
					for _, g := range c.state.Gates.Gates {
						if g.Subject != "provider" || len(g.Targets) == 0 {
							continue
						}
						parent := c.state.Records[g.Targets[0].ResourceID]
						if parent == nil || parent.Family == row.Family {
							return nil, ErrUnavailable
						}
					}
				}
				continue
			}
			if len(row.SourceBindings) != 1 {
				return nil, ErrUnavailable
			}
			member, ready := c.gateRowLocked(row.SourceBindings[0].ResourceID)
			if !ready || member.ParentID == "" || !c.providerProjectionLocked(member) {
				return nil, ErrUnavailable
			}
			row = member
		}
		if _, found := parents[row.ParentID]; !found {
			group, err := c.providerGroupLocked(row.ParentID)
			if err != nil {
				return nil, ErrUnavailable
			}
			parents[row.ParentID] = group
		}
		found := false
		for _, member := range parents[row.ParentID].Targets[1:] {
			if member == row.Target {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrUnavailable
		}
	}
	return parents, nil
}

func (c *Catalog) providerGateAppliesLocked(g resource.Gate, parents map[string]resource.Binding, b *resource.Binding) (bool, error) {
	if len(g.Targets) < 2 {
		return false, ErrUnavailable
	}
	if _, found := parents[g.Targets[0].ResourceID]; found {
		if _, err := c.providerGateBindingLocked(resource.Binding{Scope: c.versionLocked(), Targets: g.Targets}); err != nil {
			return false, ErrUnavailable
		}
		return true, nil
	}
	// A formerly grouped credential cannot escape a stale relationship by
	// becoming unparented. Other proven providers remain source-scoped.
	for _, old := range g.Targets[1:] {
		for _, current := range b.Targets {
			if old.ResourceID == current.ResourceID {
				return false, ErrUnavailable
			}
		}
	}
	return false, nil
}
