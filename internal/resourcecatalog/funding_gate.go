package resourcecatalog

import (
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MoeForge/moego/regexp"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const fundingGateOwner = "core.funding.v1/deepseek"
const deepInfraGateOwner = "core.funding.v1/deepinfra"
const fundingEvidencePrefix = "funding/deepseek/v1/"
const deepInfraEvidencePrefix = "funding/deepinfra/v1/"

var fundingDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,59})(\.[0-9]{1,30})?$`)

// DeepSeek's paid and granted balances compose the total within one native
// currency. Validate that arithmetic before trusting the availability flag.
// Zero/negative totals never establish exhaustion when a positive grant or
// top-up is still reported, or the platform still considers the key usable.
func deepSeekFundingState(reading resource.FundingReading) string {
	if reading.DeepInfra != nil || reading.Available == nil || len(reading.Balances) == 0 || len(reading.Balances) > 2 {
		return ""
	}
	seen := map[string]bool{}
	positive, positivePart := false, false
	for _, b := range reading.Balances {
		if (b.Currency != "CNY" && b.Currency != "USD") || seen[b.Currency] {
			return ""
		}
		seen[b.Currency] = true
		if !fundingDecimal.MatchString(b.Total) || !fundingDecimal.MatchString(b.Granted) || !fundingDecimal.MatchString(b.ToppedUp) {
			return ""
		}
		total, _ := new(big.Rat).SetString(b.Total)
		granted, _ := new(big.Rat).SetString(b.Granted)
		toppedUp, _ := new(big.Rat).SetString(b.ToppedUp)
		if granted.Sign() < 0 || total.Cmp(new(big.Rat).Add(granted, toppedUp)) != 0 {
			return ""
		}
		positive = positive || total.Sign() > 0
		positivePart = positivePart || granted.Sign() > 0 || toppedUp.Sign() > 0
	}
	if *reading.Available && positive {
		return "clear"
	}
	if !*reading.Available && !positive && !positivePart {
		return "pause"
	}
	return ""
}

func IsCoreAdmissionGateOwner(owner string) bool {
	return owner == legacyFundingOwner || owner == fundingGateOwner || owner == deepInfraGateOwner || IsCoreQuotaGateOwner(owner)
}

func FundingGateDetails(owner, evidence string) *resource.FundingGateEvidence {
	prefix, adapter := fundingEvidencePrefix, "deepseek"
	if owner == deepInfraGateOwner {
		prefix, adapter = deepInfraEvidencePrefix, "deepinfra"
	} else if owner != fundingGateOwner {
		return nil
	}
	if !strings.HasPrefix(evidence, prefix) {
		return nil
	}
	fields := strings.Split(strings.TrimPrefix(evidence, prefix), "/")
	if len(fields) != 2 || !validID(fields[1]) {
		return nil
	}
	date, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || date <= 0 {
		return nil
	}
	return &resource.FundingGateEvidence{Source: adapter, ObservedAtMS: date}
}

// The gate mutation and the ordering fence share the same signed v1 ledger
// commit. A fixed private receipt slot records the latest definitive reading
// even when there is no gate change. Old readers deserialize the same shape.
func (c *Catalog) ObserveProviderFunding(adapter string, b resource.Binding, index, sourceVersion string, reading resource.FundingReading, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if len(b.Targets) != 1 || !c.bindingLocked(&b) || !validSeal(sourceVersion) || !validID(reading.QueryID) {
		return ErrConflict
	}
	if reading.ObservedAtMS <= 0 || reading.ObservedAtMS > now.UnixMilli() || now.UnixMilli()-reading.ObservedAtMS >= time.Hour.Milliseconds() {
		return nil
	}
	action, owner, prefix, payerFence := "", fundingGateOwner, fundingEvidencePrefix, ""
	slot := "funding-state/" + b.Targets[0].ResourceID
	switch adapter {
	case "deepseek":
		action = deepSeekFundingState(reading)
	case "deepinfra":
		action = deepInfraFundingState(reading, now)
		if action != "" {
			payerFence = "payer/" + reading.DeepInfra.Payer + "/" + strconv.FormatInt(reading.DeepInfra.CheckedAt, 10)
		}
		owner, prefix, slot = deepInfraGateOwner, deepInfraEvidencePrefix, "funding-state/deepinfra/"+b.Targets[0].ResourceID
	}
	if action == "" {
		return nil
	}
	stamp := prefix + strconv.FormatInt(reading.ObservedAtMS, 10) + "/" + reading.QueryID
	prior := c.state.Gates.Operations[slot].Operation
	if facts := FundingGateDetails(prior.Owner, prior.EvidenceID); facts != nil && prior.SourceVersion == sourceVersion &&
		sameGateSubjects(prior.Targets, b.Targets) && (facts.ObservedAtMS >= reading.ObservedAtMS ||
		(payerFence != "" && staleDeepInfraWallet(prior, reading.DeepInfra))) {
		return nil
	}

	op := resource.GateOperation{Version: 1, OpID: uuid.NewString(), ExpectedRevision: c.state.Gates.Revision, Binding: b, AuthIndex: index,
		SourceVersion: sourceVersion, Subject: "credential", Owner: owner, Action: action, Reason: "funding_exhausted", EvidenceID: stamp}
	active := false
	for _, gate := range c.state.Gates.Gates {
		if gate.Owner == op.Owner && gate.Model == "" && gate.Subject != "provider" && sameGateSubjects(gate.Targets, b.Targets) {
			active = true
			break
		}
	}
	_, err := c.applyGateWithPrivateFenceLocked(op, slot, (action == "pause") != active, payerFence)
	return err
}
