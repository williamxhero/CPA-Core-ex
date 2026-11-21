package resourcecatalog

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// A v1 credential owner also works with the predecessor, which treats it as a
// regular hold. Only this Core may bypass it, and only with exact paid proof.
// The original YAML marker stays intact as an additional rollback guard.
const legacyFundingOwner = "core.funding.v1/legacy-auto-hold"
const legacyFundingEvidencePrefix = "legacy-funding/v1/"

type legacyFundingGroup struct {
	adapter    string
	binding    resource.Binding
	generation string
}

func (c *Catalog) nativeLegacyFundingGroup(p *config.OpenAICompatibility, adapter string) (legacyFundingGroup, bool) {
	if adapter == "" {
		return legacyFundingGroup{}, false
	}
	b, err := c.providerGroupLocked(p.ResourceID)
	if err != nil || len(b.Targets) != 1+len(p.APIKeyEntries) {
		return legacyFundingGroup{}, false
	}
	expected := map[string]bool{}
	for _, entry := range p.APIKeyEntries {
		expected[entry.ResourceID] = true
	}
	for _, target := range b.Targets[1:] {
		row, ok := c.gateRowLocked(target.ResourceID)
		if !ok || !expected[target.ResourceID] || len(row.SourceBindings) != 0 {
			return legacyFundingGroup{}, false
		}
	}
	// The raw flag elects the first migration. A current signed member also
	// elects the whole roster after a predecessor rewrote the legacy flag.
	if !p.AutoHeld {
		elected := false
		for _, gate := range c.state.Gates.Gates {
			if gate.Owner != legacyFundingOwner || len(gate.Targets) != 1 {
				continue
			}
			for _, target := range b.Targets[1:] {
				if sameGateLifecycle(gate.Targets[0], target) {
					elected = true
					break
				}
			}
			if elected {
				break
			}
		}
		if !elected {
			return legacyFundingGroup{}, false
		}
	}
	return legacyFundingGroup{adapter: adapter, binding: b, generation: sealValue(c.key, []any{adapter, b.Targets})}, true
}

// Publish the predecessor-compatible guard with the source's own reconciliation
// journal. A list reorder is harmless; a new roster or source gets a new epoch.
func (c *Catalog) materializeLegacyFundingGuards(state *diskState, snapshot resource.Snapshot, files []*sourceFile, rows []*sourceRow) (bool, error) {
	hasMarker := false
	for _, r := range rows {
		if r.file.path == c.configPath && r.row.Kind == "provider" && scalar(r.node, "auto-held") == "true" {
			hasMarker = true
			break
		}
	}
	if !hasMarker {
		for _, gate := range state.Gates.Gates {
			if gate.Owner == legacyFundingOwner {
				hasMarker = true
				break
			}
		}
		if !hasMarker {
			return false, nil
		}
	}
	var cfg *config.Config
	for _, f := range files {
		if f.path != c.configPath {
			continue
		}
		bytes := f.original
		if f.changed {
			var err error
			bytes, err = f.encode()
			if err != nil {
				return false, err
			}
		}
		var err error
		cfg, err = config.ParseConfigBytes(bytes)
		if err != nil {
			return false, ErrUnavailable
		}
		break
	}
	if cfg == nil {
		return false, ErrUnavailable
	}
	view := &Catalog{key: c.key, state: state, snapshot: snapshot, boot: c.boot}
	ledger := state.Gates
	changed := false
	for i := range cfg.OpenAICompatibility {
		prov := &cfg.OpenAICompatibility[i]
		group, ok := view.nativeLegacyFundingGroup(prov, cfg.NativeFundingAdapter(prov))
		if !ok {
			continue
		}
		for _, target := range group.binding.Targets[1:] {
			found := false
			pos := -1
			for i, g := range ledger.Gates {
				if g.Owner != legacyFundingOwner || len(g.Targets) != 1 || g.Targets[0].ResourceID != target.ResourceID {
					continue
				}
				pos = i
				found = g.Targets[0] == target && g.SourceVersion == group.generation
				break
			}
			if found {
				continue
			}
			if !advance(&ledger.Revision) {
				return false, ErrUnavailable
			}
			stamp := legacyFundingEvidencePrefix + strconv.FormatInt(time.Now().UnixMilli(), 10) + "/" + uuid.NewString()
			op := resource.GateOperation{Version: 1, OpID: uuid.NewString(), ExpectedRevision: ledger.Revision - 1, Binding: resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{target}}, AuthIndex: "catalog-legacy-hold", SourceVersion: group.generation, Subject: "credential", Owner: legacyFundingOwner, Action: "pause", Reason: "legacy_funding_unverified", EvidenceID: stamp}
			gate := resource.Gate{Targets: op.Targets, Owner: op.Owner, Reason: op.Reason, EvidenceID: op.EvidenceID, SourceVersion: op.SourceVersion, Revision: ledger.Revision}
			if pos >= 0 {
				ledger.Gates[pos] = gate
			} else {
				ledger.Gates = append(ledger.Gates, gate)
			}
			result := resource.GateResult{Version: 1, OpID: op.OpID, Status: "applied", Revision: ledger.Revision, DurableRevision: ledger.Revision, AppliedRevision: ledger.Revision, Durable: true, Applied: true}
			ledger.Operations[op.OpID] = gateReceipt{Operation: op, Result: result}
			changed = true
		}
	}
	if changed {
		state.GateSeal = sealValue(c.key, ledger)
	}
	return changed, nil
}

func legacyFundingObservedAfter(evidence string) int64 {
	if !strings.HasPrefix(evidence, legacyFundingEvidencePrefix) {
		return 0
	}
	stamp, id, ok := strings.Cut(strings.TrimPrefix(evidence, legacyFundingEvidencePrefix), "/")
	if !ok || !validID(id) {
		return 0
	}
	at, _ := strconv.ParseInt(stamp, 10, 64)
	return at
}

// The existing funding writer has already authenticated each observation and
// applied its freshness rule. A failed query never overwrites its receipt.
// Current scope, entire roster epoch, and a positive reading newer than the
// rollback guard are required; a receipt from a former roster cannot reopen it.
func (c *Catalog) legacyFundingReleasedLocked(group legacyFundingGroup) bool {
	scope := c.versionLocked()
	for _, target := range group.binding.Targets[1:] {
		var after int64
		for _, gate := range c.state.Gates.Gates {
			if gate.Owner == legacyFundingOwner && len(gate.Targets) == 1 && gate.Targets[0] == target && gate.SourceVersion == group.generation {
				after = legacyFundingObservedAfter(gate.EvidenceID)
				break
			}
		}
		if after <= 0 {
			return false
		}
		op := c.state.Gates.Operations[fundingStateSlot(group.adapter, target.ResourceID)].Operation
		fact := FundingGateDetails(op.Owner, op.EvidenceID)
		if fact == nil || fact.Source != group.adapter || fact.ObservedAtMS <= after || op.Action != "clear" || len(op.Targets) != 1 ||
			op.Targets[0] != target || op.Scope.InstanceID != scope.InstanceID || op.Scope.InstanceIncarnation != scope.InstanceIncarnation {
			return false
		}
	}
	return true
}

func (c *Catalog) legacyFundingAdmissionLocked(b *resource.Binding) (required, released bool, err error) {
	if _, err := c.configuredAuthsLocked(); err != nil {
		return false, false, err
	}
	for _, target := range b.Targets {
		p, known := c.configuredProjection.legacyFunding[target.ResourceID]
		if !known {
			continue
		}
		group, ok := c.nativeLegacyFundingGroup(&p.provider, p.adapter)
		if !ok && !p.provider.AutoHeld {
			continue
		}
		required = true
		if !ok || !c.legacyFundingReleasedLocked(group) {
			return true, false, nil
		}
		released = true
	}
	return
}
