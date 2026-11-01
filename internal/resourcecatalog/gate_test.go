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
