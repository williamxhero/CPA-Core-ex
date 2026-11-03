package resourcecatalog

import (
	"errors"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferenceGateDurablePublicationRecovery(t *testing.T) {
	c, path, authPath, before := publicationFixture(t)
	var b resource.Binding
	for _, r := range before.Resources {
		if r.Kind == "credential" && r.ParentID == "" {
			b = resource.Binding{Scope: before.Version, Targets: append([]resource.Target{r.Target}, r.SourceBindings...)}
		}
	}
	if len(b.Targets) == 0 {
		t.Fatal("missing current credential")
	}
	hit := false
	c.writeFile = func(dst string, raw []byte) error {
		if dst == path+".gate-floor-v1" {
			hit = true
			return ErrUnavailable
		}
		return atomicWrite(dst, raw)
	}
	op := resource.GateOperation{Version: 1, OpID: "6ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3d", Binding: b, Owner: "owner-a", Action: "pause", Subject: "credential", SourceVersion: strings.Repeat("a", 64), AuthIndex: "synthetic", Reason: "quota_exhausted", EvidenceID: "evidence"}
	result, err := c.ApplyGate(op)
	if !hit || !errors.Is(err, ErrUnavailable) || result.Applied {
		t.Fatal("failed publication returned applied ACK")
	}
	if c.AdmitInference(&b, "") == nil {
		t.Fatal("failed publication allowed traffic")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(path, filepath.Dir(authPath), "")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	state, err := next.GateState()
	if err != nil || !state.Ready || state.Revision != 1 || len(state.Gates) != 1 {
		t.Fatalf("durable journal recovery: %+v %v", state, err)
	}
	_, receipt, err := next.GateOperation(op.OpID)
	if err != nil || !receipt.Applied || receipt.Revision != 1 {
		t.Fatal("recovery lost receipt")
	}
	// Old boot authority remains stale even when receipt is retained.
	if next.AdmitInference(&b, "") == nil {
		t.Fatal("old boot binding restored traffic")
	}
}

func TestProviderGateDurablePublicationRecovery(t *testing.T) {
	c, path, authPath, before := publicationFixture(t)
	var group resource.Binding
	group.Scope = before.Version
	for _, row := range before.Resources {
		if row.Kind == "provider" {
			group.Targets = append(group.Targets, row.Target)
		}
	}
	for _, row := range before.Resources {
		if row.ParentID == group.Targets[0].ResourceID {
			group.Targets = append(group.Targets, row.Target)
		}
	}
	canonical, err := c.ProviderGateBinding(group)
	if err != nil {
		t.Fatal(err)
	}
	hit := false
	c.writeFile = func(dst string, raw []byte) error {
		if dst == path+".gate-floor-v1" {
			hit = true
			return ErrUnavailable
		}
		return atomicWrite(dst, raw)
	}
	op := resource.GateOperation{Version: 1, OpID: "6ee26bfc-a9ab-4ad9-bb41-d76ab49b6e3d", Binding: canonical, Owner: "provider-owner", Action: "pause", Subject: "provider", SourceVersion: strings.Repeat("a", 64), Reason: "low_balance", EvidenceID: "evidence"}
	result, err := c.ApplyGate(op)
	if !hit || !errors.Is(err, ErrUnavailable) || result.Applied {
		t.Fatal("failed provider publication returned applied ACK", result, err)
	}
	member := resource.Binding{Scope: canonical.Scope, Targets: canonical.Targets[1:]}
	if err := c.AdmitInference(&member, ""); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed publication admitted another business attempt", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(path, filepath.Dir(authPath), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	}()
	state, err := next.GateState()
	if err != nil || !state.AllSourcesReady || state.Revision != 1 || len(state.Gates) != 1 || state.Gates[0].Subject != "provider" {
		t.Fatal("provider durable journal recovery lost current gate", state, err)
	}
	_, receipt, err := next.GateOperation(op.OpID)
	if err != nil || !receipt.Applied || receipt.Revision != 1 || receipt.DurableRevision != 1 || receipt.AppliedRevision != 1 {
		t.Fatal("recovery lost provider publication receipt", receipt, err)
	}
	member.Scope = next.Version()
	if err := next.AdmitInference(&member, ""); !errors.Is(err, ErrGateDenied) {
		t.Fatal("recovered provider gate did not deny a current member", err)
	}
}
