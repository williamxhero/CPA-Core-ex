package resourcecatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

var ErrGateRevisionConflict = fmt.Errorf("%w: gate revision", ErrConflict)

var ErrOperationConflict = errors.New("operation conflict")
var ErrGateDenied = errors.New("inference gate denied")
var gateReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)

type gateReceipt struct {
	Operation resource.GateOperation `json:"operation"`
	Result    resource.GateResult    `json:"result"`
}
type gateRefreshEdge struct {
	From resource.Binding  `json:"from"`
	To   []resource.Target `json:"to"`
}

type gateLedger struct {
	Refreshes  []gateRefreshEdge      `json:"native_refreshes,omitempty"`
	Version    int                    `json:"version"`
	Revision   uint64                 `json:"revision"`
	Gates      []resource.Gate        `json:"gates"`
	Operations map[string]gateReceipt `json:"operations"`
}

// initializeGates is called before publishing any runtime identity or traffic.
// The independent floor detects a ledger silently dropped by an older writer.
func (c *Catalog) initializeGates() error {
	floor := filepath.Join(c.stateDir, "gate-floor-v1")
	if c.state.Gates == nil {
		if _, err := os.Stat(floor); !os.IsNotExist(err) {
			return ErrUnavailable
		}
		next := *c.state
		next.Gates = &gateLedger{Version: 1, Gates: []resource.Gate{}, Operations: map[string]gateReceipt{}}
		next.GateSeal = sealValue(c.key, next.Gates)
		if c.writeFile(floor, []byte("independent-gate-v1\n")) != nil {
			return ErrUnavailable
		}
		raw, _ := json.Marshal(&next)
		if c.writeFile(filepath.Join(c.stateDir, "catalog.json"), raw) != nil {
			return ErrUnavailable
		}
		c.state = &next
	}
	floorRaw, err := os.ReadFile(floor)
	if err != nil || string(floorRaw) != "independent-gate-v1\n" || c.state.Gates.Version != 1 || c.state.Gates.Operations == nil || c.state.Gates.Gates == nil || c.state.GateSeal != sealValue(c.key, c.state.Gates) {
		return ErrUnavailable
	}
	if !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	return nil
}

func (c *Catalog) gateCurrentLocked() bool {
	raw, err := os.ReadFile(filepath.Join(c.stateDir, "gate-floor-v1"))
	return err == nil && string(raw) == "independent-gate-v1\n" && c.state.Gates != nil && c.state.Gates.Version == 1 && c.state.GateSeal == sealValue(c.key, c.state.Gates) && c.gateAnchorCurrentLocked()
}

// bindingLocked also enforces the full projection group, never a target subset.
func (c *Catalog) bindingLocked(b *resource.Binding) bool {
	if b == nil || b.Scope != c.versionLocked() || len(b.Targets) == 0 {
		return false
	}
	for i, t := range b.Targets {
		found := false
		for _, r := range c.snapshot.Resources {
			if r.Target == t && r.Identity == "valid" && r.Readiness == "ready" {
				if i == 0 && !reflect.DeepEqual(append([]resource.Target{r.Target}, r.SourceBindings...), b.Targets) {
					return false
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ValidGateOperation(op resource.GateOperation) bool {
	subjectValid := (op.Subject == "credential" && op.AuthIndex != "" && len(op.AuthIndex) <= 256) || (op.Subject == "provider" && op.AuthIndex == "")
	return op.Version == 1 && validID(op.OpID) && subjectValid && (op.Action == "pause" || op.Action == "clear") && gateReference.MatchString(op.Owner) && gateReference.MatchString(op.Reason) && gateReference.MatchString(op.EvidenceID) && len(op.Model) <= 256 && (op.Model == "" || gateReference.MatchString(op.Model)) && validSeal(op.SourceVersion) && len(op.Targets) > 0 && len(op.Targets) <= 64
}

func (c *Catalog) GateState() (resource.GateState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.GateState{}, ErrUnavailable
	}
	raw, _ := json.Marshal(c.state.Gates.Gates)
	var gates []resource.Gate
	_ = json.Unmarshal(raw, &gates)
	for i := range gates {
		gates[i].Applicability = "current"
		if !c.gateLifecyclesCurrentLocked([]resource.Gate{gates[i]}) {
			gates[i].Applicability = "reconciliation_required"
		}
	}
	return resource.GateState{Version: 1, Scope: c.versionLocked(), Revision: c.state.Gates.Revision, Ready: true, AllSourcesReady: c.gateLifecyclesCurrentLocked(gates), Gates: gates}, nil
}

// ApplyGate commits and publishes under the same mutex as AdmitInference.
// No I/O to an upstream and no response lifetime is covered by this mutex.
func (c *Catalog) ApplyGate(op resource.GateOperation) (resource.GateResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.GateResult{}, ErrUnavailable
	}
	if saved, ok := c.state.Gates.Operations[op.OpID]; ok {
		if !reflect.DeepEqual(saved.Operation, op) {
			return resource.GateResult{}, ErrOperationConflict
		}
		return saved.Result, nil
	}
	targets := op.Targets
	if op.Subject == "provider" {
		if !ValidGateOperation(op) {
			return resource.GateResult{}, ErrConflict
		}
		binding, err := c.providerGateBindingLocked(op.Binding)
		if err != nil {
			return resource.GateResult{}, err
		}
		targets = binding.Targets
	} else if op.Subject != "credential" || !c.bindingLocked(&op.Binding) {
		return resource.GateResult{}, ErrConflict
	}
	if op.ExpectedRevision != c.state.Gates.Revision {
		return resource.GateResult{}, ErrGateRevisionConflict
	}
	if c.state.Gates.Revision == ^uint64(0) {
		return resource.GateResult{}, ErrUnavailable
	}
	raw, _ := json.Marshal(c.state)
	var next diskState
	_ = json.Unmarshal(raw, &next)
	ledger := next.Gates
	ledger.Revision++
	// Provider reconciliation replaces only its own stable parent lineage.
	// Credential matching remains the original issued lifecycle group.
	filtered := []resource.Gate{}
	for _, g := range ledger.Gates {
		matching := g.Subject != "provider" && op.Subject == "credential" && sameGateSubjects(g.Targets, targets)
		if g.Subject == "provider" && op.Subject == "provider" && len(g.Targets) > 0 {
			matching = sameProviderLineage(g.Targets[0], targets[0])
		}
		if g.Owner == op.Owner && g.Model == op.Model && matching {
			continue
		}
		filtered = append(filtered, g)
	}
	ledger.Gates = filtered
	if op.Action == "pause" {
		subject := ""
		if op.Subject == "provider" {
			subject = "provider"
		}
		ledger.Gates = append(ledger.Gates, resource.Gate{Subject: subject, Targets: append([]resource.Target(nil), targets...), Owner: op.Owner, Model: op.Model, Reason: op.Reason, EvidenceID: op.EvidenceID, SourceVersion: op.SourceVersion, Revision: ledger.Revision})
	}
	result := resource.GateResult{Version: 1, OpID: op.OpID, Status: "applied", Revision: ledger.Revision, DurableRevision: ledger.Revision, AppliedRevision: ledger.Revision, Durable: true, Applied: true}
	ledger.Operations[op.OpID] = gateReceipt{Operation: op, Result: result}
	next.GateSeal = sealValue(c.key, ledger)
	raw, _ = json.Marshal(&next)
	values, errValues := sourceContentValues(c.configPath, c.authDir, c.key)
	if errValues != nil || c.publish(&next, nil, nil, values) != nil {
		c.failed = true
		return resource.GateResult{}, ErrUnavailable
	}
	c.state = &next
	return result, nil
}

func sameGateSubjects(a, b []resource.Target) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameGateLifecycle(a[i], b[i]) {
			return false
		}
	}
	return true
}

func (c *Catalog) GateOperation(id string) (resource.GateOperation, resource.GateResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return resource.GateOperation{}, resource.GateResult{}, ErrUnavailable
	}
	r, ok := c.state.Gates.Operations[id]
	if !ok {
		return resource.GateOperation{}, resource.GateResult{}, os.ErrNotExist
	}
	return r.Operation, r.Result, nil
}

// AdmitInference linearizes ONE new business attempt. Its caller may drain the
// admitted attempt after a later pause, but must call again for every resend.
func (c *Catalog) AdmitInference(b *resource.Binding, model string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if !c.bindingLocked(b) {
		// Unsupported/unbound sources retain legacy routing only when the verified
		// durable owner set is EMPTY. This is never a positive protection capability.
		// Once any restriction exists, unknown attribution cannot bypass it.
		if len(c.state.Gates.Gates) == 0 {
			return nil
		}
		return ErrConflict
	}
	parents, err := c.providerParentsLocked(b)
	if err != nil {
		return err
	}
	for _, g := range c.state.Gates.Gates {
		if g.Model != "" && g.Model != model {
			continue
		}
		if g.Subject == "provider" {
			applies, err := c.providerGateAppliesLocked(g, parents, b)
			if err != nil {
				return err
			}
			if applies {
				return ErrGateDenied
			}
			continue
		}
		for _, gt := range g.Targets {
			for _, t := range b.Targets {
				if gt.ResourceID == t.ResourceID {
					if !sameGateLifecycle(gt, t) {
						return ErrUnavailable
					}
					return ErrGateDenied
				}
			}
		}
	}
	return nil
}

// BeginOwnedAuthSave serializes a local native store write with publication.
// It holds no lock across network I/O. An owned physical replacement is certified
// by this invocation, not a matching filename, token hash or account label.
func (c *Catalog) BeginOwnedAuthSave(path string, a *coreauth.Auth) (func(*coreauth.Auth, *resource.Binding, bool) error, error) {
	c.mu.Lock()
	if !c.currentLocked() || !c.gateCurrentLocked() || a == nil || !c.bindingLocked(a.ResourceIdentity) {
		c.mu.Unlock()
		return nil, ErrUnavailable
	}
	before, err := readSource(path, true)
	if err != nil || scalar(before.root, "resource_id") != a.ResourceIdentity.Targets[0].ResourceID {
		c.mu.Unlock()
		return nil, ErrConflict
	}
	return func(a *coreauth.Auth, previous *resource.Binding, success bool) error {
		defer c.mu.Unlock()
		if !success {
			c.failed = true
			return ErrUnavailable
		}
		after, err := readSource(path, true)
		if err != nil || scalar(after.root, "resource_id") != scalar(before.root, "resource_id") {
			c.failed = true
			return ErrUnavailable
		}
		data := after.original
		c.ownedFileReplacements = map[string]string{scalar(before.root, "resource_id"): seal(c.key, []byte(after.fileID))}
		defer func() { c.ownedFileReplacements = nil }()
		continuity := !refreshAuthorityDisagrees(before, after) && previous != nil && previous.Scope.InstanceID == c.state.InstanceID && previous.Scope.InstanceIncarnation == c.state.InstanceIncarnation && previous.Scope.BootEpoch == c.boot && len(previous.Targets) == 1
		if continuity {
			for _, t := range previous.Targets {
				r := c.state.Records[t.ResourceID]
				if r == nil || r.Target != t || r.Blocked || r.Deleted {
					continuity = false
				}
			}
		}
		if err := c.reconcileLocked(); err != nil {
			c.failed = true
			return err
		}
		if err := c.bindAuthsLocked(path, data, []*coreauth.Auth{a}); err != nil {
			c.failed = true
			return err
		}
		if !continuity || a.ResourceIdentity == nil || len(a.ResourceIdentity.Targets) != 1 || !sameRefreshAuthority(previous.Targets[0], a.ResourceIdentity.Targets[0]) {
			return nil
		}
		// A successful native refresh can leave the persisted source unchanged.
		// There is no lifecycle transition to certify in that case. Publishing a
		// self-edge would invalidate unrelated gate CAS operations indefinitely.
		if reflect.DeepEqual(previous.Targets, a.ResourceIdentity.Targets) {
			return nil
		}
		raw, _ := json.Marshal(c.state)
		var next diskState
		_ = json.Unmarshal(raw, &next)
		for i, g := range next.Gates.Gates {
			if sameGateSubjects(g.Targets, previous.Targets) {
				next.Gates.Gates[i].Targets = append([]resource.Target(nil), a.ResourceIdentity.Targets...)
			}
		}
		// A certified rotation is also durable proof for healthy intents with no gate row.
		next.Gates.Refreshes = append(next.Gates.Refreshes, gateRefreshEdge{From: *previous, To: append([]resource.Target(nil), a.ResourceIdentity.Targets...)})
		if !advance(&next.Gates.Revision) {
			c.failed = true
			return ErrUnavailable
		}
		for i := range next.Gates.Gates {
			if sameGateSubjects(next.Gates.Gates[i].Targets, a.ResourceIdentity.Targets) {
				next.Gates.Gates[i].Revision = next.Gates.Revision
			}
		}
		next.GateSeal = sealValue(c.key, next.Gates)
		raw, _ = json.Marshal(&next)
		values, errValues := sourceContentValues(c.configPath, c.authDir, c.key)
		if errValues != nil || c.publish(&next, nil, nil, values) != nil {
			c.failed = true
			return ErrUnavailable
		}
		c.state = &next
		return nil
	}, nil
}

func sameGateLifecycle(a, b resource.Target) bool {
	return a.ResourceID == b.ResourceID && a.Incarnation == b.Incarnation && a.IdentityVersion == b.IdentityVersion && a.CredentialVersion == b.CredentialVersion && a.MembershipVersion == b.MembershipVersion
}

func (c *Catalog) gateLifecyclesCurrentLocked(gates []resource.Gate) bool {
	for _, g := range gates {
		if g.Subject == "provider" {
			if _, err := c.providerGateBindingLocked(resource.Binding{Scope: c.versionLocked(), Targets: g.Targets}); err != nil {
				return false
			}
			continue
		}
		for _, t := range g.Targets {
			r := c.state.Records[t.ResourceID]
			if r == nil || r.Deleted || r.Blocked || !sameGateLifecycle(t, r.Target) {
				return false
			}
		}
	}
	return true
}

// GateFloorRequired is a side-effect-free managed startup guard. Even a malformed
// receipt requires a gate-capable startup; disabling the catalog cannot erase it.
func GateFloorRequired(configPath string, stateDirs ...string) bool {
	paths := []string{configPath + ".gate-floor-v1", filepath.Join(statePath(configPath, ""), "gate-floor-v1")}
	for _, dir := range stateDirs {
		paths = append(paths, filepath.Join(statePath(configPath, dir), "gate-floor-v1"))
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return true
		}
	}
	return false
}
func (c *Catalog) gateAnchorBytes(state *diskState) []byte {
	raw, _ := json.Marshal(struct {
		Version     int    `json:"version"`
		InstanceID  string `json:"instance_id"`
		Incarnation string `json:"instance_incarnation"`
		Revision    uint64 `json:"gateRevision"`
	}{1, state.InstanceID, state.InstanceIncarnation, state.Gates.Revision})
	out, _ := json.Marshal(journalEnvelope{Data: raw, Seal: seal(c.key, raw)})
	return out
}
func (c *Catalog) gateAnchorCurrentLocked() bool {
	raw, err := os.ReadFile(c.configPath + ".gate-floor-v1")
	if os.IsNotExist(err) {
		return c.state.Gates.Revision == 0
	}
	return err == nil && bytes.Equal(raw, c.gateAnchorBytes(c.state))
}

// GateBindingReady is a side-effect-free source-scoped applicability read. It
// does not register an attempt or interpret an active owner pause as unready.
func (c *Catalog) GateBindingReady(b *resource.Binding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if !c.bindingLocked(b) {
		return ErrConflict
	}
	parents, err := c.providerParentsLocked(b)
	if err != nil {
		return err
	}
	for _, g := range c.state.Gates.Gates {
		if g.Subject == "provider" {
			if _, err := c.providerGateAppliesLocked(g, parents, b); err != nil {
				return err
			}
			continue
		}
		for _, old := range g.Targets {
			for _, t := range b.Targets {
				if old.ResourceID == t.ResourceID && !sameGateLifecycle(old, t) {
					return ErrUnavailable
				}
			}
		}
	}
	return nil
}

// GateRefreshContinuity proves an exact host-certified native rotation chain.
// It never infers ownership from account labels or token/key content.
func (c *Catalog) GateRefreshContinuity(previous, current resource.Binding) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return false, ErrUnavailable
	}
	if !c.bindingLocked(&current) {
		return false, ErrConflict
	}
	if previous.Scope.InstanceID != c.state.InstanceID || previous.Scope.InstanceIncarnation != c.state.InstanceIncarnation || len(previous.Targets) == 0 {
		return false, nil
	}
	cursor := previous.Targets
	traversed := false
	for _, edge := range c.state.Gates.Refreshes {
		if edge.From.Scope.InstanceID != previous.Scope.InstanceID || edge.From.Scope.InstanceIncarnation != previous.Scope.InstanceIncarnation || !reflect.DeepEqual(edge.From.Targets, cursor) {
			continue
		}
		cursor = edge.To
		traversed = true
		if reflect.DeepEqual(cursor, current.Targets) {
			return traversed, nil
		}
	}
	return false, nil
}
