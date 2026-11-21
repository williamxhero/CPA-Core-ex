package resourcecatalog

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const codexQuotaOwnerPrefix = "core.codex-quota.v1/"
const codexQuotaEvidencePrefix = "codex-quota/v1/"

func IsCoreQuotaGateOwner(owner string) bool {
	return strings.HasPrefix(owner, codexQuotaOwnerPrefix)
}

func codexQuotaGateOwner(w resource.QuotaGateEvidence) string {
	return fmt.Sprintf("%s%s/%d", codexQuotaOwnerPrefix, w.Window, w.WindowSeconds)
}

// QuotaGateDetails projects typed diagnostics out of existing sealed fields.
// Older binaries can still validate the ledger and honor a durable restriction.
func QuotaGateDetails(owner, evidence string) (*resource.QuotaGateEvidence, int64) {
	if !IsCoreQuotaGateOwner(owner) || !strings.HasPrefix(evidence, codexQuotaEvidencePrefix) {
		return nil, 0
	}
	scope := strings.Split(strings.TrimPrefix(owner, codexQuotaOwnerPrefix), "/")
	fields := strings.Split(strings.TrimPrefix(evidence, codexQuotaEvidencePrefix), "/")
	if len(scope) != 2 || (scope[0] != "primary" && scope[0] != "secondary") || len(fields) != 4 || !validID(fields[3]) {
		return nil, 0
	}
	unit, errUnit := strconv.ParseInt(scope[1], 10, 64)
	observed, errObserved := strconv.ParseInt(fields[0], 10, 64)
	recheck, errRecheck := strconv.ParseInt(fields[1], 10, 64)
	intake, errIntake := strconv.ParseInt(fields[2], 10, 64)
	if errUnit != nil || errObserved != nil || errRecheck != nil || errIntake != nil || unit <= 0 || observed <= 0 || intake <= 0 || (recheck != 0 && recheck <= observed) {
		return nil, 0
	}
	return &resource.QuotaGateEvidence{Window: scope[0], WindowSeconds: unit, ObservedAtMS: observed, RecheckAtMS: recheck}, intake
}

// matchingCodexGateTarget preserves an existing restriction if the same
// credential's non-identity config (e.g. manual intent) changes. New evidence
// still has to pass full current binding CAS before any mutation.
func matchingCodexGateTarget(g resource.Gate, b resource.Binding) bool {
	return len(b.Targets) == 1 && len(g.Targets) == 1 && sameGateLifecycle(g.Targets[0], b.Targets[0])
}

// CodexQuotaRecheckCurrent joins a read-only gate snapshot and exact live
// source binding. The lifecycle comparison uses the same scope as admission.
func (c *Catalog) CodexQuotaRecheckCurrent(revision uint64, g resource.Gate, b resource.Binding) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentLocked() && c.gateCurrentLocked() && revision == c.state.Gates.Revision &&
		IsCoreQuotaGateOwner(g.Owner) && c.bindingLocked(&b) && matchingCodexGateTarget(g, b)
}

func (c *Catalog) codexQuotaFenceLocked(op resource.GateOperation) (gateReceipt, *resource.QuotaGateEvidence, int64) {
	var latest gateReceipt
	var facts *resource.QuotaGateEvidence
	var intake int64
	for _, receipt := range c.state.Gates.Operations {
		prior := receipt.Operation
		if latest.Result.Revision >= receipt.Result.Revision || prior.Owner != op.Owner || prior.Model != op.Model ||
			prior.SourceVersion != op.SourceVersion || prior.Scope.InstanceID != op.Scope.InstanceID ||
			prior.Scope.InstanceIncarnation != op.Scope.InstanceIncarnation ||
			(!gateRefreshConfigurationForward(prior.Targets, op.Targets) && !c.gateRefreshContinuityLocked(prior.Binding, op.Binding)) {
			continue
		}
		if details, stamp := QuotaGateDetails(prior.Owner, prior.EvidenceID); details != nil {
			latest, facts, intake = receipt, details, stamp
		}
	}
	return latest, facts, intake
}

func (c *Catalog) ObserveCodexQuotaRejection(b resource.Binding, index, sourceVersion string, start time.Time, evidence resource.CodexQuotaRejection) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return false, ErrUnavailable
	}
	if len(b.Targets) != 1 || !c.bindingLocked(&b) || (evidence.Model != resource.CodexSparkModel && evidence.Model != "") {
		return false, ErrConflict
	}
	w := resource.QuotaGateEvidence{Window: evidence.Window, WindowSeconds: evidence.WindowSeconds, ObservedAtMS: evidence.ObservedAtMS, RecheckAtMS: evidence.ResetAtMS}
	if (w.Window != "primary" && w.Window != "secondary") || w.WindowSeconds <= 0 || w.ObservedAtMS <= 0 || w.RecheckAtMS <= w.ObservedAtMS {
		return false, ErrConflict
	}
	op := c.codexQuotaOperationLocked(b, index, sourceVersion, evidence.Model, "pause", w, time.Now())
	prior, facts, intake := c.codexQuotaFenceLocked(op)
	if facts != nil && (facts.ObservedAtMS >= w.ObservedAtMS || start.UnixNano() <= intake && prior.Operation.Action == "clear") {
		// Do not add the same event as a legacy cooldown after accepting
		// it on the durable authority, even after that pause recovered.
		return true, nil
	}
	_, err := c.applyGateLocked(op)
	return err == nil, err
}

// RecheckCodexQuota consumes the host's selected live WHAM read after a second
// full source check. Callers cannot post quota evidence.
func (c *Catalog) RecheckCodexQuota(index string, start time.Time, obs resource.QuotaObservation) ([]resource.QuotaGateEvidence, error) {
	if obs.Protocol != "codex-oauth-wham" || obs.ProtocolVersion != 1 || obs.QueryStatus != "success" ||
		obs.AccountProvenance != "selected_oauth_account" || obs.TimestampProvenance != "upstream_http_date" {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return nil, ErrUnavailable
	}
	if len(obs.Targets) != 1 || !c.bindingLocked(&obs.Binding) {
		return nil, ErrConflict
	}
	var recovered []resource.QuotaGateEvidence
	for _, g := range c.state.Gates.Gates {
		if !IsCoreQuotaGateOwner(g.Owner) || (g.Model != resource.CodexSparkModel && g.Model != "") ||
			g.SourceVersion != obs.SourceVersion || !matchingCodexGateTarget(g, obs.Binding) {
			continue
		}
		// The sealed active row carries the pause's original intake across
		// certified rotation. Historical operation receipts remain unchanged.
		facts, intake := QuotaGateDetails(g.Owner, g.EvidenceID)
		if facts == nil || start.UnixNano() <= intake || obs.ObservedAtMS <= facts.ObservedAtMS ||
			!canClearCodexQuotaWindow(g.Model, *facts, obs.Windows, time.Now()) && !canClearCodexQuotaWithPaidFunding(g.Model, *facts, obs, time.Now()) {
			continue
		}
		w := resource.QuotaGateEvidence{Window: facts.Window, WindowSeconds: facts.WindowSeconds, ObservedAtMS: obs.ObservedAtMS}
		op := c.codexQuotaOperationLocked(obs.Binding, index, obs.SourceVersion, g.Model, "clear", w, time.Now())
		if _, err := c.applyGateLocked(op); err != nil {
			return recovered, err
		}
		recovered = append(recovered, w)
	}
	return recovered, nil
}

func (c *Catalog) codexQuotaOperationLocked(b resource.Binding, index, sourceVersion, model, action string, evidence resource.QuotaGateEvidence, at time.Time) resource.GateOperation {
	id := uuid.NewString()
	return resource.GateOperation{
		Version: 1, OpID: id, ExpectedRevision: c.state.Gates.Revision, Binding: b, AuthIndex: index,
		SourceVersion: sourceVersion, Subject: "credential", Owner: codexQuotaGateOwner(evidence), Model: model,
		Action: action, Reason: "quota_windows_exhausted", EvidenceID: fmt.Sprintf("%s%d/%d/%d/%s", codexQuotaEvidencePrefix, evidence.ObservedAtMS, evidence.RecheckAtMS, at.UnixNano(), id),
	}
}

func canClearCodexQuotaWindow(model string, paused resource.QuotaGateEvidence, windows []resource.QuotaWindow, now time.Time) bool {
	feature, name := "", ""
	if model == resource.CodexSparkModel {
		feature, name = resource.CodexSparkLimit, resource.CodexSparkLimitName
	}
	seen := map[string]bool{}
	matches := false
	for _, w := range windows {
		if w.Model != feature {
			continue
		}
		if w.LimitName != name {
			return false
		}
		if seen[w.Name] {
			return false
		}
		seen[w.Name] = true
		reset, err := time.Parse(time.RFC3339Nano, w.ResetAt)
		if err != nil || !reset.After(now) || w.SourceStatus != "allowed" || w.CodexUsage != resource.CodexWindowUsageBelowLimit {
			return false
		}
		if w.Name == paused.Window && w.LimitWindowSeconds == paused.WindowSeconds {
			matches = true
		}
	}
	return matches && seen["primary"] && seen["secondary"]
}

// hasExternalGateLocked preserves the legacy unbound protective boundary for
// external owners. Native evidence cannot establish unrelated source scope.
func (c *Catalog) hasExternalGateLocked() bool {
	for _, g := range c.state.Gates.Gates {
		if !IsCoreAdmissionGateOwner(g.Owner) {
			return true
		}
	}
	return false
}

func canClearCodexQuotaWithPaidFunding(model string, paused resource.QuotaGateEvidence, obs resource.QuotaObservation, now time.Time) bool {
	if model != "" || !obs.Complete || !obs.StandardPaidFunding || len(obs.Windows) != 2 {
		return false
	}
	seen := map[string]bool{}
	matches := false
	for _, w := range obs.Windows {
		reset, err := time.Parse(time.RFC3339, w.ResetAt)
		if err != nil || !reset.After(now) || w.Model != "" || w.LimitName != "" || seen[w.Name] ||
			(w.SourceStatus != "rate-limited" && w.SourceStatus != "allowed") {
			return false
		}
		seen[w.Name] = true
		matches = matches || w.Name == paused.Window && w.LimitWindowSeconds == paused.WindowSeconds
	}
	return matches && seen["primary"] && seen["secondary"]
}
