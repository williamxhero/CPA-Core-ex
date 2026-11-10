package resourcecatalog

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func quotaStopBinding(t *testing.T, c *Catalog) resource.Binding {
	t.Helper()
	snapshot, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range snapshot.Resources {
		if row.Kind == "credential" && row.ParentID == "" {
			return resource.Binding{Scope: snapshot.Version, Targets: append([]resource.Target{row.Target}, row.SourceBindings...)}
		}
	}
	t.Fatal("missing fixture credential")
	return resource.Binding{}
}

func quotaStopPolicy(b resource.Binding) QuotaAutoStop {
	return QuotaAutoStop{Version: 1, Binding: b, AuthIndex: "synthetic", SourceVersion: strings.Repeat("a", 64), Subject: "credential", Owner: "owner-quota", Generation: 1, Enabled: true}
}

func TestQuotaAutoStopRestartOffAndRecoveryFence(t *testing.T) {
	c, configPath, authPath, _ := publicationFixture(t)
	b := quotaStopBinding(t, c)
	p := quotaStopPolicy(b)
	if err := c.SetQuotaAutoStop(p); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := Open(configPath, filepath.Dir(authPath), "")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	b = quotaStopBinding(t, c)
	if err := c.ObserveQuotaExhaustion(b, "synthetic", p.SourceVersion); err != nil {
		t.Fatal(err)
	}
	state, err := c.GateState()
	if err != nil || len(state.Gates) != 1 || c.AdmitInference(&b, "other-model") != ErrGateDenied {
		t.Fatal("restored intent did not immediately pause all models", err)
	}
	p.Binding = b
	p.Generation = 2
	p.Enabled = false
	if err := c.SetQuotaAutoStop(p); err != nil {
		t.Fatal(err)
	}
	stale := p
	stale.Generation = 1
	stale.Enabled = true
	if !errors.Is(c.SetQuotaAutoStop(stale), ErrConflict) {
		t.Fatal("stale ON replaced newer OFF")
	}
	if c.AdmitInference(&b, "") != ErrGateDenied {
		t.Fatal("OFF erased existing owner pause")
	}
	clear := resource.GateOperation{Version: 1, OpID: uuid.NewString(), Binding: b, AuthIndex: "synthetic", SourceVersion: p.SourceVersion, Subject: "credential", Owner: p.Owner, Action: "clear", Reason: "quota_windows_exhausted", EvidenceID: "recovery", ExpectedRevision: state.Revision}
	if _, err := c.ApplyObservedGate(clear, c.quotaAutoStops[0].LastFailureMS, false); !errors.Is(err, ErrConflict) {
		t.Fatal("pre-failure query cleared newer quota pause", err)
	}
	if _, err := c.ApplyObservedGate(clear, 0, true); err != nil {
		t.Fatal("explicit resume failed", err)
	}
	if err := c.ObserveQuotaExhaustion(b, "synthetic", p.SourceVersion); err != nil {
		t.Fatal(err)
	}
	if err := c.AdmitInference(&b, ""); err != nil {
		t.Fatal("OFF policy repaused after explicit resume", err)
	}
	p.Enabled = true
	p.Generation = 3
	if err := c.SetQuotaAutoStop(p); err != nil {
		t.Fatal(err)
	}
	if err := c.ObserveQuotaExhaustion(b, "synthetic", p.SourceVersion); err != nil {
		t.Fatal(err)
	}
	state, _ = c.GateState()
	clear.OpID = uuid.NewString()
	clear.ExpectedRevision = state.Revision
	if _, err := c.ApplyObservedGate(clear, c.quotaAutoStops[0].LastFailureMS+1, false); err != nil {
		t.Fatal("new authoritative recovery could not resume", err)
	}
}

func TestQuotaAutoStopStorageFailureDoesNotAllowRetry(t *testing.T) {
	c, _, _, _ := publicationFixture(t)
	b := quotaStopBinding(t, c)
	p := quotaStopPolicy(b)
	if err := c.SetQuotaAutoStop(p); err != nil {
		t.Fatal(err)
	}
	c.writeFile = func(path string, raw []byte) error {
		if filepath.Base(path) == "quota-auto-stop-v1.json" {
			return ErrUnavailable
		}
		return atomicWrite(path, raw)
	}
	if err := c.ObserveQuotaExhaustion(b, "synthetic", p.SourceVersion); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed write reported success", err)
	}
	if c.AdmitInference(&b, "") == nil {
		t.Fatal("failed quota-stop publication allowed another upstream attempt")
	}
}
