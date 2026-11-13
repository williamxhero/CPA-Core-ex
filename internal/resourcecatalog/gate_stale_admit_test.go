package resourcecatalog

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestAdmitInferenceIgnoresDriftedCredentialGate(t *testing.T) {
	c, path, _, before := publicationFixture(t)
	var current resource.Binding
	for _, r := range before.Resources {
		if r.Kind == "credential" && r.ParentID == "" {
			current = resource.Binding{Scope: before.Version, Targets: append([]resource.Target{r.Target}, r.SourceBindings...)}
			break
		}
	}
	if len(current.Targets) == 0 {
		t.Fatal("missing current credential")
	}
	pause := resource.GateOperation{
		Version: 1, OpID: "6ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3d", Binding: current, Owner: "owner-a",
		Action: "pause", Subject: "credential", SourceVersion: strings.Repeat("a", 64),
		AuthIndex: "synthetic", Reason: "quota_windows_exhausted", EvidenceID: "evidence",
	}
	if _, err := c.ApplyGate(pause); err != nil {
		t.Fatal(err)
	}
	if err := c.AdmitInference(&current, "deepseek-v4.1-flash"); !errors.Is(err, ErrGateDenied) {
		t.Fatalf("current pause must deny: %v", err)
	}

	c.mu.Lock()
	if len(c.state.Gates.Gates) != 1 {
		c.mu.Unlock()
		t.Fatal("expected one pause gate")
	}
	c.state.Gates.Gates[0].Targets[0].Incarnation = "00000000-0000-4000-8000-000000000099"
	c.state.Gates.Gates[0].Targets[0].IdentityVersion = 1
	c.state.Gates.Gates[0].Targets[0].CredentialVersion = 1
	c.state.GateSeal = sealValue(c.key, c.state.Gates)
	raw, err := json.Marshal(c.state)
	if err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	if err := c.writeFile(filepath.Join(c.stateDir, "catalog.json"), raw); err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	if err := c.writeFile(path+".gate-floor-v1", c.gateAnchorBytes(c.state)); err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	c.mu.Unlock()

	if err := c.AdmitInference(&current, "deepseek-v4.1-flash"); err != nil {
		t.Fatalf("drifted gate must not block current binding: %v", err)
	}

	clear := pause
	clear.OpID = "7ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3e"
	clear.Action = "clear"
	clear.ExpectedRevision = 1
	if _, err := c.ApplyGate(clear); err != nil {
		t.Fatal(err)
	}
	state, err := c.GateState()
	if err != nil || len(state.Gates) != 0 {
		t.Fatalf("clear must drop drifted resource-id gate: %+v %v", state, err)
	}
}

func TestApplyGateClearMatchesPrimaryCredentialSlot(t *testing.T) {
	c, path, _, before := publicationFixture(t)
	var current resource.Binding
	for _, r := range before.Resources {
		if r.Kind == "credential" && r.ParentID == "" {
			current = resource.Binding{Scope: before.Version, Targets: append([]resource.Target{r.Target}, r.SourceBindings...)}
			break
		}
	}
	if len(current.Targets) == 0 {
		t.Fatal("missing current credential")
	}
	pause := resource.GateOperation{
		Version: 1, OpID: "8ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3f", Binding: current, Owner: "owner-a",
		Action: "pause", Subject: "credential", SourceVersion: strings.Repeat("a", 64),
		AuthIndex: "synthetic", Reason: "quota_windows_exhausted", EvidenceID: "evidence",
	}
	if _, err := c.ApplyGate(pause); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	stale := append([]resource.Target{c.state.Gates.Gates[0].Targets[0]}, resource.Target{
		ResourceID: "00000000-0000-4000-8000-0000000000aa", Incarnation: "00000000-0000-4000-8000-0000000000bb",
		IdentityVersion: 1, CredentialVersion: 1, ConfigVersion: 1,
	})
	stale[0].Incarnation = "00000000-0000-4000-8000-000000000099"
	c.state.Gates.Gates[0].Targets = stale
	c.state.GateSeal = sealValue(c.key, c.state.Gates)
	raw, err := json.Marshal(c.state)
	if err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	if err := c.writeFile(filepath.Join(c.stateDir, "catalog.json"), raw); err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	if err := c.writeFile(path+".gate-floor-v1", c.gateAnchorBytes(c.state)); err != nil {
		c.mu.Unlock()
		t.Fatal(err)
	}
	c.mu.Unlock()

	clear := pause
	clear.OpID = "9ee26bfc-a9ab-4ad9-bb41-d76ab49b6e40"
	clear.Action = "clear"
	clear.ExpectedRevision = 1
	if _, err := c.ApplyGate(clear); err != nil {
		t.Fatal(err)
	}
	state, err := c.GateState()
	if err != nil || len(state.Gates) != 0 {
		t.Fatalf("clear must drop gate when only primary slot matches: %+v %v", state, err)
	}
}
