package resourcecatalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// QuotaAutoStop is intent only. Existing owner gates survive an OFF update.
type QuotaAutoStop struct {
	Version int `json:"version"`
	resource.Binding
	AuthIndex     string `json:"auth_index"`
	SourceVersion string `json:"sourceVersion"`
	Subject       string `json:"subject"`
	Owner         string `json:"owner"`
	Generation    int64  `json:"generation"`
	Enabled       bool   `json:"enabled"`
}

type quotaAutoStopEntry struct {
	Policy        QuotaAutoStop `json:"policy"`
	LastFailureMS int64         `json:"lastFailureMs,omitempty"`
}

// Keep this signed file separate from the v1 gate ledger so binary rollback
// preserves the old ledger serialization and every already-applied restriction.
func (c *Catalog) loadQuotaAutoStops() error {
	raw, err := os.ReadFile(filepath.Join(c.stateDir, "quota-auto-stop-v1.json"))
	if os.IsNotExist(err) {
		return nil
	}
	var envelope journalEnvelope
	if err != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Seal != seal(c.key, envelope.Data) || json.Unmarshal(envelope.Data, &c.quotaAutoStops) != nil {
		return ErrUnavailable
	}
	return nil
}

func (c *Catalog) saveQuotaAutoStopsLocked(entries []quotaAutoStopEntry) error {
	raw, err := json.Marshal(entries)
	if err != nil {
		return ErrUnavailable
	}
	envelope, err := json.Marshal(journalEnvelope{Data: raw, Seal: seal(c.key, raw)})
	if err != nil || c.writeFile(filepath.Join(c.stateDir, "quota-auto-stop-v1.json"), envelope) != nil {
		c.failed = true
		return ErrUnavailable
	}
	c.quotaAutoStops = entries
	return nil
}

// quotaPolicyMatchesLocked accepts a full unchanged lifecycle or a certified
// native OAuth refresh chain. A filename or runtime auth index is never proof.
func (c *Catalog) quotaPolicyMatchesLocked(p QuotaAutoStop, b resource.Binding) bool {
	if p.Scope.InstanceID != b.Scope.InstanceID || p.Scope.InstanceIncarnation != b.Scope.InstanceIncarnation {
		return false
	}
	if reflect.DeepEqual(p.Targets, b.Targets) {
		return true
	}
	cursor := p.Targets
	for _, edge := range c.state.Gates.Refreshes {
		if edge.From.Scope.InstanceID == p.Scope.InstanceID && edge.From.Scope.InstanceIncarnation == p.Scope.InstanceIncarnation && gateRefreshConfigurationForward(cursor, edge.From.Targets) {
			cursor = edge.To
			if reflect.DeepEqual(cursor, b.Targets) {
				return true
			}
		}
	}
	return false
}

func (c *Catalog) SetQuotaAutoStop(p QuotaAutoStop) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if p.Version != 1 || p.Subject != "credential" || p.AuthIndex == "" || !validSeal(p.SourceVersion) || !gateReference.MatchString(p.Owner) || p.Generation < 1 || p.Generation >= 9007199254740991 || len(p.Targets) == 0 || len(p.Targets) > 64 {
		return ErrConflict
	}
	entries := append([]quotaAutoStopEntry(nil), c.quotaAutoStops...)
	index := -1
	for i, e := range entries {
		if e.Policy.Owner == p.Owner && c.quotaPolicyMatchesLocked(e.Policy, p.Binding) {
			index = i
			if e.Policy.Generation > p.Generation || e.Policy.Generation == p.Generation && e.Policy.Enabled != p.Enabled {
				return ErrConflict
			}
			break
		}
	}
	// Emergency OFF can use the last issued binding during a Core restart.
	if !c.bindingLocked(&p.Binding) && (p.Enabled || index < 0) {
		return ErrConflict
	}
	if index < 0 {
		entries = append(entries, quotaAutoStopEntry{Policy: p})
	} else {
		if reflect.DeepEqual(entries[index].Policy, p) {
			return nil
		}
		entries[index].Policy = p
	}
	return c.saveQuotaAutoStopsLocked(entries)
}

func (c *Catalog) QuotaAutoStopSynced(p QuotaAutoStop) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return false, ErrUnavailable
	}
	if !c.bindingLocked(&p.Binding) {
		return false, ErrConflict
	}
	for _, entry := range c.quotaAutoStops {
		if entry.Policy.Owner == p.Owner && entry.Policy.Generation == p.Generation && entry.Policy.Enabled == p.Enabled && c.quotaPolicyMatchesLocked(entry.Policy, p.Binding) {
			return true, nil
		}
	}
	return false, nil
}

// ObserveQuotaExhaustion publishes a durable owner pause before returning to
// the retry loop. Cooling flags and reset hints deliberately play no role.
func (c *Catalog) ObserveQuotaExhaustion(b resource.Binding, authIndex, sourceVersion string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if !c.bindingLocked(&b) {
		return ErrConflict
	}
	for i := range c.quotaAutoStops {
		entry := c.quotaAutoStops[i]
		p := entry.Policy
		if !p.Enabled || !c.quotaPolicyMatchesLocked(p, b) {
			continue
		}
		// Persist the failure fence before the gate. An interrupted publication
		// cannot let a pre-failure successful quota query clear a later pause.
		entries := append([]quotaAutoStopEntry(nil), c.quotaAutoStops...)
		entries[i].LastFailureMS = time.Now().UnixMilli()
		if err := c.saveQuotaAutoStopsLocked(entries); err != nil {
			return err
		}
		paused := false
		for _, gate := range c.state.Gates.Gates {
			if gate.Subject != "provider" && gate.Owner == p.Owner && gate.Model == "" && sameGateSubjects(gate.Targets, b.Targets) {
				paused = true
				break
			}
		}
		if paused {
			continue
		}
		id := uuid.NewString()
		op := resource.GateOperation{Version: 1, OpID: id, ExpectedRevision: c.state.Gates.Revision, Binding: b, AuthIndex: authIndex, SourceVersion: sourceVersion, Subject: "credential", Owner: p.Owner, Action: "pause", Reason: "quota_windows_exhausted", EvidenceID: "upstream-quota:" + id}
		if _, err := c.applyGateLocked(op); err != nil {
			return err
		}
	}
	return nil
}

// ApplyObservedGate rejects recovery evidence older than the latest upstream
// exhaustion. Authenticated manual resume remains an explicit override.
func (c *Catalog) ApplyObservedGate(op resource.GateOperation, observedAtMS int64, manual bool) (resource.GateResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.GateResult{}, ErrUnavailable
	}
	if _, exists := c.state.Gates.Operations[op.OpID]; !exists && op.Action == "clear" && !manual {
		for _, entry := range c.quotaAutoStops {
			if entry.Policy.Owner == op.Owner && c.quotaPolicyMatchesLocked(entry.Policy, op.Binding) && entry.LastFailureMS > 0 && observedAtMS <= entry.LastFailureMS {
				return resource.GateResult{}, ErrConflict
			}
		}
	}
	return c.applyGateLocked(op)
}
