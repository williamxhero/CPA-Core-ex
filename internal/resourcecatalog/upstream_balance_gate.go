package resourcecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const upstreamBalanceGateOwner = "core.upstream-balance.v1"
const upstreamBalanceEvidencePrefix = "upstream-balance/v1/"

// IsCoreBalanceGateOwner reserves the balance owner and its namespaced variants.
func IsCoreBalanceGateOwner(owner string) bool {
	return owner == upstreamBalanceGateOwner || strings.HasPrefix(owner, upstreamBalanceGateOwner+"/")
}

// BalanceGateObservedAtMS returns the observation timestamp from sealed gate
// evidence, or zero when the owner or evidence format is unrecognized.
func BalanceGateObservedAtMS(owner, evidence string) int64 {
	if !IsCoreBalanceGateOwner(owner) || !strings.HasPrefix(evidence, upstreamBalanceEvidencePrefix) {
		return 0
	}
	stamp, digest, ok := strings.Cut(strings.TrimPrefix(evidence, upstreamBalanceEvidencePrefix), "/")
	if !ok || len(digest) != 32 {
		return 0
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return 0
	}
	observedMS, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || observedMS <= 0 {
		return 0
	}
	return observedMS
}

// ObserveUpstreamBalanceExhaustion pauses the current credential lifecycle
// without a user policy. The pause and its observation fence commit together.
func (c *Catalog) ObserveUpstreamBalanceExhaustion(b resource.Binding, authIndex string, observedAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if len(b.Targets) == 0 || !c.bindingLocked(&b) {
		return ErrConflict
	}
	ids := make([]string, 0, len(b.Targets)+1)
	for _, target := range b.Targets {
		if !validID(target.ResourceID) {
			return ErrConflict
		}
		ids = append(ids, target.ResourceID)
	}
	observedMS := observedAt.UnixMilli()
	if observedMS <= 0 || observedAt.After(time.Now()) {
		return ErrConflict
	}
	slot := upstreamBalanceEvidencePrefix + ids[0]
	prior := c.state.Gates.Operations[slot].Operation
	if observedMS <= BalanceGateObservedAtMS(prior.Owner, prior.EvidenceID) {
		return nil
	}
	active := false
	for _, gate := range c.state.Gates.Gates {
		if gate.Owner == upstreamBalanceGateOwner && gate.Subject != "provider" && gate.Model == "" && sameGateSubjects(gate.Targets, b.Targets) {
			active = true
			break
		}
	}
	stamp := strconv.FormatInt(observedMS, 10)
	digest := sha256.Sum256([]byte(strings.Join(append(ids, stamp), "/")))
	op := resource.GateOperation{
		Version: 1, OpID: uuid.NewString(), ExpectedRevision: c.state.Gates.Revision, Binding: b, AuthIndex: authIndex,
		SourceVersion: sealValue(c.key, b.Targets), Subject: "credential", Owner: upstreamBalanceGateOwner,
		Action: "pause", Reason: "upstream_balance_exhausted", EvidenceID: upstreamBalanceEvidencePrefix + stamp + "/" + hex.EncodeToString(digest[:16]),
	}
	// Advance the fence even when the original pause needs no new revision.
	_, err := c.applyGateWithPrivateFenceLocked(op, slot, !active, "")
	return err
}
