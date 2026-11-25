package resourcecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const (
	UpstreamBalanceResumeReasonNoPause          = "no_pause"
	UpstreamBalanceResumeReasonNotPositive      = "not_positive"
	UpstreamBalanceResumeReasonStale            = "stale"
	UpstreamBalanceResumeReasonLifecycleChanged = "lifecycle_changed"

	upstreamBalancePositiveReadingOp = "upstream_balance_reading_positive"
	upstreamBalanceSourceRefPrefix   = "source/"
	maxUpstreamBalanceSourceID       = 128
	maxUpstreamBalanceAuthIndex      = 256
)

// UpstreamBalanceManualResumeReason is the only operator-supplied resume
// reason; any other request reason is refused.
const UpstreamBalanceManualResumeReason = "manual_resume"

// UpstreamBalanceReading is one operator-supplied balance observation. A reading
// by itself never pauses anything: only a positive reading strictly newer than
// the recorded pause retires it.
type UpstreamBalanceReading struct {
	ObservedAtMS int64
	Available    bool
	SourceID     string
}

// ValidUpstreamBalanceSourceID bounds the audit reference kept with a reading.
func ValidUpstreamBalanceSourceID(id string) bool {
	if id == "" || len(id) > maxUpstreamBalanceSourceID {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] == 0x7f {
			return false
		}
	}
	return true
}

// ResumeUpstreamBalance clears the automatic balance pause of one credential
// lifecycle on explicit operator request. The receipt and the ledger change
// commit together, so a retried opId replays the first answer and a reused opId
// with different content is refused.
func (c *Catalog) ResumeUpstreamBalance(opID string, b resource.Binding, authIndex, reason string, now time.Time) (resource.GateResult, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.GateResult{}, "", ErrUnavailable
	}
	if !c.upstreamBalanceRequestCurrentLocked(opID, b, authIndex) {
		return resource.GateResult{}, "", ErrConflict
	}
	if reason == "" {
		reason = UpstreamBalanceManualResumeReason
	}
	if reason != UpstreamBalanceManualResumeReason {
		return resource.GateResult{}, "", ErrConflict
	}
	observedMS := now.UnixMilli()
	if observedMS <= 0 {
		observedMS = 1
	}
	op := c.upstreamBalanceClearOperation(opID, b, authIndex, reason, upstreamBalanceEvidence(observedMS, b.Targets, reason))
	if saved, ok := c.state.Gates.Operations[opID]; ok {
		if !sameUpstreamBalanceOperation(saved.Operation, op) {
			return resource.GateResult{}, "", ErrOperationConflict
		}
		return saved.Result, "", nil
	}
	if _, blocked := c.upstreamBalancePauseLocked(b); blocked != "" {
		return c.upstreamBalanceUnchangedLocked(opID), blocked, nil
	}
	result, err := c.applyGateWithPrivateFenceLocked(op, c.upstreamBalanceFenceSlotLocked(b, observedMS), true, UpstreamBalanceManualResumeReason)
	if err != nil {
		return resource.GateResult{}, "", err
	}
	return result, "", nil
}

// ObserveUpstreamBalanceReading retires the pause only when the reading is
// positive, newer than every observation already recorded for the credential,
// and still describes the paused lifecycle.
func (c *Catalog) ObserveUpstreamBalanceReading(opID string, b resource.Binding, authIndex string, reading UpstreamBalanceReading, now time.Time) (resource.GateResult, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.GateResult{}, "", ErrUnavailable
	}
	if !c.upstreamBalanceRequestCurrentLocked(opID, b, authIndex) {
		return resource.GateResult{}, "", ErrConflict
	}
	if reading.ObservedAtMS <= 0 || reading.ObservedAtMS > now.UnixMilli() || !ValidUpstreamBalanceSourceID(reading.SourceID) {
		return resource.GateResult{}, "", ErrConflict
	}
	op := c.upstreamBalanceClearOperation(opID, b, authIndex, upstreamBalancePositiveReadingOp, upstreamBalanceEvidence(reading.ObservedAtMS, b.Targets, reading.SourceID))
	if saved, ok := c.state.Gates.Operations[opID]; ok {
		if !sameUpstreamBalanceOperation(saved.Operation, op) {
			return resource.GateResult{}, "", ErrOperationConflict
		}
		return saved.Result, "", nil
	}
	if !reading.Available {
		return c.upstreamBalanceUnchangedLocked(opID), UpstreamBalanceResumeReasonNotPositive, nil
	}
	gate, reason := c.upstreamBalancePauseLocked(b)
	if reason != "" {
		return c.upstreamBalanceUnchangedLocked(opID), reason, nil
	}
	slot := upstreamBalanceSlot(b)
	floor := BalanceGateObservedAtMS(gate.Owner, gate.EvidenceID)
	if fence := c.upstreamBalanceFenceLocked(slot); fence > floor {
		floor = fence
	}
	if reading.ObservedAtMS <= floor {
		return c.upstreamBalanceUnchangedLocked(opID), UpstreamBalanceResumeReasonStale, nil
	}
	// The reading advances the same observation fence the pause wrote, so a
	// denial observed earlier cannot re-pause the credential afterwards.
	result, err := c.applyGateWithPrivateFenceLocked(op, slot, true, upstreamBalanceSourceRefPrefix+reading.SourceID)
	if err != nil {
		return resource.GateResult{}, "", err
	}
	return result, "", nil
}

func (c *Catalog) upstreamBalanceRequestCurrentLocked(opID string, b resource.Binding, authIndex string) bool {
	return validID(opID) && authIndex != "" && len(authIndex) <= maxUpstreamBalanceAuthIndex &&
		len(b.Targets) > 0 && len(b.Targets) <= 64 && c.bindingLocked(&b)
}

func (c *Catalog) upstreamBalanceClearOperation(opID string, b resource.Binding, authIndex, reason, evidence string) resource.GateOperation {
	return resource.GateOperation{
		Version: 1, OpID: opID, ExpectedRevision: c.state.Gates.Revision, Binding: b, AuthIndex: authIndex,
		SourceVersion: sealValue(c.key, b.Targets), Subject: "credential", Owner: upstreamBalanceGateOwner,
		Action: "clear", Reason: reason, EvidenceID: evidence,
	}
}

// upstreamBalancePauseLocked reports the automatic pause this binding may
// retire, or the reason it must not be retired now. Only a row on the same
// primary credential slot belongs to this reason; a drifted lifecycle row is
// left for reconciliation instead of being silently dropped.
func (c *Catalog) upstreamBalancePauseLocked(b resource.Binding) (resource.Gate, string) {
	for _, gate := range c.state.Gates.Gates {
		if gate.Owner != upstreamBalanceGateOwner || gate.Subject == "provider" || gate.Model != "" || !sameGateCredentialSlot(gate.Targets, b.Targets) {
			continue
		}
		if !sameGateSubjects(gate.Targets, b.Targets) || !c.gateLifecyclesCurrentLocked([]resource.Gate{gate}) {
			return gate, UpstreamBalanceResumeReasonLifecycleChanged
		}
		return gate, ""
	}
	return resource.Gate{}, UpstreamBalanceResumeReasonNoPause
}

func (c *Catalog) upstreamBalanceFenceLocked(slot string) int64 {
	prior := c.state.Gates.Operations[slot].Operation
	return BalanceGateObservedAtMS(prior.Owner, prior.EvidenceID)
}

// The fence only moves forward: replaying an older manual resume must not let a
// denial it already outran become authoritative again.
func (c *Catalog) upstreamBalanceFenceSlotLocked(b resource.Binding, observedMS int64) string {
	slot := upstreamBalanceSlot(b)
	if observedMS <= c.upstreamBalanceFenceLocked(slot) {
		return ""
	}
	return slot
}

func (c *Catalog) upstreamBalanceUnchangedLocked(opID string) resource.GateResult {
	revision := c.state.Gates.Revision
	return resource.GateResult{Version: 1, OpID: opID, Status: "unchanged", Revision: revision, DurableRevision: revision, Durable: true}
}

func sameUpstreamBalanceOperation(saved, proposed resource.GateOperation) bool {
	// The expected revision is state-derived; the request is not. Compare the
	// request-derived identity so a legitimate replay after unrelated ledger
	// traffic still matches its receipt. A manual resume also records the moment
	// the operator decided, which is deliberately not part of that identity.
	saved.ExpectedRevision, proposed.ExpectedRevision = 0, 0
	if saved.Reason == UpstreamBalanceManualResumeReason && proposed.Reason == UpstreamBalanceManualResumeReason {
		saved.EvidenceID, proposed.EvidenceID = "", ""
	}
	return reflect.DeepEqual(saved, proposed)
}

func upstreamBalanceEvidence(observedMS int64, targets []resource.Target, sourceRef string) string {
	parts := make([]string, 0, 2*len(targets)+2)
	for _, target := range targets {
		parts = append(parts, target.ResourceID, target.Incarnation)
	}
	stamp := strconv.FormatInt(observedMS, 10)
	parts = append(parts, stamp, sourceRef)
	digest := sha256.Sum256([]byte(strings.Join(parts, "/")))
	return upstreamBalanceEvidencePrefix + stamp + "/" + hex.EncodeToString(digest[:16])
}
