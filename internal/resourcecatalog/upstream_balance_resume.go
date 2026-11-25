package resourcecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
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
	upstreamBalanceNegativeReadingOp = "upstream_balance_reading_negative"
	upstreamBalanceSourceRefPrefix   = "source/"
	maxUpstreamBalanceSourceID       = 128
)

var (
	ErrInvalidBalanceResumeReason = fmt.Errorf("%w: invalid balance resume reason", ErrConflict)
	ErrInvalidBalanceReading      = fmt.Errorf("%w: invalid balance reading", ErrConflict)
)

// MaxUpstreamBalanceAuthIndex bounds the runtime index in balance requests.
const MaxUpstreamBalanceAuthIndex = 256

// UpstreamBalanceManualResumeReason is the only operator-supplied resume
// reason; any other request reason is refused.
const UpstreamBalanceManualResumeReason = "manual_resume"

// UpstreamBalanceReading is one operator-supplied balance observation. A reading
// by itself never pauses anything: only a positive reading strictly newer than
// the recorded pause retires it.
type UpstreamBalanceReading struct {
	ObservedAtMS int64  `json:"observedAtMs"`
	Available    bool   `json:"available"`
	SourceID     string `json:"sourceId"`
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

// ResumeUpstreamBalance explicitly clears a current balance pause.
func (c *Catalog) ResumeUpstreamBalance(opID string, b resource.Binding, authIndex, reason string, now time.Time) (resource.GateResult, string, error) {
	result, _, err := c.RetireUpstreamBalance(UpstreamBalanceRetirement{OpID: opID, Binding: b, AuthIndex: authIndex, Reason: reason}, now, nil)
	return result, result.Reason, err
}

// ObserveUpstreamBalanceReading clears a pause only for a newer positive reading.
func (c *Catalog) ObserveUpstreamBalanceReading(opID string, b resource.Binding, authIndex string, reading UpstreamBalanceReading, now time.Time) (resource.GateResult, string, error) {
	result, _, err := c.RetireUpstreamBalance(UpstreamBalanceRetirement{OpID: opID, Binding: b, AuthIndex: authIndex, Reading: &reading}, now, nil)
	return result, result.Reason, err
}

// UpstreamBalanceRetirement identifies a manual resume or a balance reading.
// A nil Reading means manual resume; only that operation uses Reason.
type UpstreamBalanceRetirement struct {
	OpID      string
	Binding   resource.Binding
	AuthIndex string
	Reason    string
	Reading   *UpstreamBalanceReading
}

// RetireUpstreamBalance returns the durable receipt and whether this call
// actually cleared a pause. Historical replays never authorize or clear again.
// The optional live authority check runs outside the catalog lock because it
// may itself read the catalog. The receipt is checked again under lock before
// a new decision can commit.
func (c *Catalog) RetireUpstreamBalance(request UpstreamBalanceRetirement, now time.Time, authorize func() bool) (resource.GateResult, bool, error) {
	b := request.Binding
	if !validID(request.OpID) || request.AuthIndex == "" || len(request.AuthIndex) > MaxUpstreamBalanceAuthIndex || len(b.Targets) == 0 || len(b.Targets) > 64 {
		return resource.GateResult{}, false, ErrConflict
	}
	observedMS := max(now.UnixMilli(), 1)
	reason, source := request.Reason, UpstreamBalanceManualResumeReason
	if reading := request.Reading; reading != nil {
		observedMS, source = reading.ObservedAtMS, reading.SourceID
		reason = upstreamBalancePositiveReadingOp
		if !reading.Available {
			reason = upstreamBalanceNegativeReadingOp
		}
	} else if reason == "" {
		reason = UpstreamBalanceManualResumeReason
	}

	op := c.upstreamBalanceClearOperation(request.OpID, b, request.AuthIndex, reason, upstreamBalanceEvidence(observedMS, b.Targets, source))
	c.mu.Lock()
	defer c.mu.Unlock()
	reading := request.Reading
	authorized := true
	for {
		if !c.currentLocked() || !c.gateCurrentLocked() {
			return resource.GateResult{}, false, ErrUnavailable
		}
		if saved, ok := c.state.Gates.Operations[op.OpID]; ok {
			if !sameUpstreamBalanceOperation(saved.Operation, op) {
				return resource.GateResult{}, false, ErrOperationConflict
			}
			return saved.Result, false, nil
		}
		if reading == nil && op.Reason != UpstreamBalanceManualResumeReason {
			return resource.GateResult{}, false, ErrInvalidBalanceResumeReason
		}
		if reading != nil && (observedMS <= 0 || observedMS > now.UnixMilli() || !ValidUpstreamBalanceSourceID(reading.SourceID)) {
			return resource.GateResult{}, false, ErrInvalidBalanceReading
		}
		if authorize == nil {
			break
		}
		c.mu.Unlock()
		authorized = authorize()
		c.mu.Lock()
		authorize = nil
	}
	if !authorized || !c.bindingLocked(&op.Binding) {
		return resource.GateResult{}, false, ErrConflict
	}
	op.ExpectedRevision = c.state.Gates.Revision
	if reading != nil && !reading.Available {
		return c.recordUnchangedBalanceLocked(op, UpstreamBalanceResumeReasonNotPositive)
	}
	gate, blocked := c.upstreamBalancePauseLocked(op.Binding)
	if blocked != "" {
		return c.recordUnchangedBalanceLocked(op, blocked)
	}

	slot := c.upstreamBalanceFenceSlotLocked(op.Binding, observedMS)
	privateRef := UpstreamBalanceManualResumeReason
	if reading != nil {
		if slot == "" || observedMS <= BalanceGateObservedAtMS(gate.Owner, gate.EvidenceID) {
			return c.recordUnchangedBalanceLocked(op, UpstreamBalanceResumeReasonStale)
		}
		// Advance the same fence so an older denial cannot re-pause afterwards.
		privateRef = upstreamBalanceSourceRefPrefix + reading.SourceID
	}
	result, err := c.applyGateWithPrivateFenceLocked(op, slot, true, privateRef)
	return result, err == nil, err
}

func (c *Catalog) upstreamBalanceClearOperation(opID string, b resource.Binding, authIndex, reason, evidence string) resource.GateOperation {
	return resource.GateOperation{
		Version: 1, OpID: opID, Binding: b, AuthIndex: authIndex,
		SourceVersion: sealValue(c.key, b.Targets), Subject: "credential", Owner: UpstreamBalanceGateOwner,
		Action: "clear", Reason: reason, EvidenceID: evidence,
	}
}

// upstreamBalancePauseLocked reports the automatic pause this binding may
// retire, or the reason it must not be retired now. Only a row on the same
// primary credential slot belongs to this reason; a drifted lifecycle row is
// left for reconciliation instead of being silently dropped.
func (c *Catalog) upstreamBalancePauseLocked(b resource.Binding) (resource.Gate, string) {
	for _, gate := range c.state.Gates.Gates {
		if gate.Owner != UpstreamBalanceGateOwner || gate.Subject == "provider" || gate.Model != "" || !sameGateCredentialSlot(gate.Targets, b.Targets) {
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

func (c *Catalog) recordUnchangedBalanceLocked(op resource.GateOperation, reason string) (resource.GateResult, bool, error) {
	next := *c.state
	ledger := *next.Gates
	ledger.Operations = maps.Clone(ledger.Operations)
	next.Gates = &ledger
	result := resource.GateResult{Version: 1, OpID: op.OpID, Status: "unchanged", Revision: ledger.Revision, DurableRevision: ledger.Revision, Durable: true, Reason: reason}
	ledger.Operations[op.OpID] = gateReceipt{Operation: op, Result: result}
	if err := c.publishGateStateLocked(&next); err != nil {
		return resource.GateResult{}, false, err
	}
	return result, false, nil
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
