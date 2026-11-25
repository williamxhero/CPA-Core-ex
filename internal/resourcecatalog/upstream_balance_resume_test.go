package resourcecatalog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// The catalog seam owns the decision logic: which automatic reason may be
// lifted, which readings are admissible, and how replays are answered.
func TestUpstreamBalanceResumeLiftsOnlyItsOwnAutomaticPause(t *testing.T) {
	c, configPath, authPath, snapshot := publicationFixture(t)
	binding := func(s resource.Snapshot, configured bool) resource.Binding {
		t.Helper()
		for _, r := range s.Resources {
			if r.Kind == "credential" && (r.ParentID != "") == configured {
				return resource.Binding{Scope: s.Version, Targets: []resource.Target{r.Target}}
			}
		}
		t.Fatal("no credential in fixture")
		return resource.Binding{}
	}
	b := binding(snapshot, true)
	other := binding(snapshot, false)
	state := func() resource.GateState {
		t.Helper()
		s, err := c.GateState()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	pause := func(at time.Time) {
		t.Helper()
		if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", at); err != nil {
			t.Fatal(err)
		}
	}
	resume := func(opID, reason string) (resource.GateResult, string, error) {
		return c.ResumeUpstreamBalance(opID, b, "synthetic", reason, time.Now())
	}
	observe := func(target resource.Binding, opID string, observedAtMS int64, available bool, sourceID string) (resource.GateResult, string, error) {
		return c.ObserveUpstreamBalanceReading(opID, target, "synthetic", UpstreamBalanceReading{ObservedAtMS: observedAtMS, Available: available, SourceID: sourceID}, time.Now())
	}

	pause(time.Now().Add(-3 * time.Second))
	if got := state(); len(got.Gates) != 1 || !errors.Is(c.AdmitInference(&b, "any-model"), ErrGateDenied) {
		t.Fatalf("fixture did not pause: %+v", got)
	}

	opID := uuid.NewString()
	first, reason, err := resume(opID, "manual_resume")
	if err != nil || !first.Applied || reason != "" || first.Revision != 2 {
		t.Fatalf("manual resume: %+v reason=%q err=%v", first, reason, err)
	}
	if got := state(); len(got.Gates) != 0 || got.Revision != first.Revision {
		t.Fatalf("manual resume left its own pause behind: %+v", got)
	}
	if err := c.AdmitInference(&b, "any-model"); err != nil {
		t.Fatalf("manual resume did not restore dispatch: %v", err)
	}
	if repeat, _, err := resume(opID, "manual_resume"); err != nil || repeat != first {
		t.Fatalf("replay changed the receipt: %+v err=%v want %+v", repeat, err, first)
	}
	if _, _, err := c.ResumeUpstreamBalance(opID, b, "other-index", "manual_resume", time.Now()); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("opId reuse with different content: %v; want operation conflict", err)
	}
	if _, _, err := resume(uuid.NewString(), "operator_override"); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown manual reason: %v; want conflict", err)
	}
	noop, reason, err := resume(uuid.NewString(), "manual_resume")
	if err != nil || noop.Applied || reason != UpstreamBalanceResumeReasonNoPause || noop.Revision != first.Revision {
		t.Fatalf("resume without a pause: %+v reason=%q err=%v", noop, reason, err)
	}

	// A denial observed before the resume must not re-pause the credential.
	pause(time.Now().Add(-time.Second))
	if got := state(); len(got.Gates) != 0 || c.AdmitInference(&b, "any-model") != nil {
		t.Fatalf("late evidence re-paused after a resume: %+v", got)
	}
	// Evidence observed after the resume legitimately pauses again.
	time.Sleep(5 * time.Millisecond)
	pause(time.Now())
	repaused := state()
	if len(repaused.Gates) != 1 || !errors.Is(c.AdmitInference(&b, "any-model"), ErrGateDenied) {
		t.Fatalf("fresh evidence did not pause: %+v", repaused)
	}
	fence := BalanceGateObservedAtMS(repaused.Gates[0].Owner, repaused.Gates[0].EvidenceID)

	readings := []struct {
		name      string
		target    resource.Binding
		observed  int64
		available bool
		source    string
		want      string
	}{
		{"failed", b, fence + 1, false, "billing-api", UpstreamBalanceResumeReasonNotPositive},
		{"equal", b, fence, true, "billing-api", UpstreamBalanceResumeReasonStale},
		{"earlier", b, fence - 60000, true, "billing-api", UpstreamBalanceResumeReasonStale},
		{"foreign", other, fence + 1, true, "billing-api", UpstreamBalanceResumeReasonNoPause},
	}
	for _, reading := range readings {
		result, reason, err := observe(reading.target, uuid.NewString(), reading.observed, reading.available, reading.source)
		if err != nil || result.Applied || reason != reading.want {
			t.Fatalf("%s reading: %+v reason=%q err=%v want %q", reading.name, result, reason, err, reading.want)
		}
	}
	if got := state(); len(got.Gates) != 1 || got.Gates[0].EvidenceID != repaused.Gates[0].EvidenceID {
		t.Fatalf("non-lifting readings changed the ledger: %+v", got)
	}
	if !errors.Is(c.AdmitInference(&b, "any-model"), ErrGateDenied) {
		t.Fatal("non-lifting readings admitted traffic")
	}
	for name, observed := range map[string]int64{"zero": 0, "future": time.Now().Add(time.Hour).UnixMilli()} {
		if _, _, err := observe(b, uuid.NewString(), observed, true, "billing-api"); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s observation: %v; want conflict", name, err)
		}
	}
	if _, _, err := observe(b, uuid.NewString(), fence+1, true, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("observation without a source: %v; want conflict", err)
	}

	time.Sleep(5 * time.Millisecond)
	fresh := time.Now().UnixMilli()
	observeID := uuid.NewString()
	lifted, reason, err := observe(b, observeID, fresh, true, "billing-api")
	if err != nil || !lifted.Applied || reason != "" || lifted.Revision != repaused.Revision+1 {
		t.Fatalf("fresh positive reading: %+v reason=%q err=%v", lifted, reason, err)
	}
	if got := state(); len(got.Gates) != 0 || c.AdmitInference(&b, "any-model") != nil {
		t.Fatalf("positive reading did not restore dispatch: %+v", got)
	}
	if repeat, _, err := observe(b, observeID, fresh, true, "billing-api"); err != nil || repeat != lifted {
		t.Fatalf("observation replay changed the receipt: %+v err=%v", repeat, err)
	}
	if _, _, err := observe(b, observeID, fresh+1, true, "billing-api"); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("observation opId reuse with different content: %v; want operation conflict", err)
	}
	if again, reason, err := observe(b, uuid.NewString(), fresh, true, "billing-api"); err != nil || again.Applied || reason != UpstreamBalanceResumeReasonNoPause {
		t.Fatalf("repeat observation: %+v reason=%q err=%v", again, reason, err)
	}
	// A late exhaustion write cannot resurrect a pause the resume already ended.
	if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := state(); len(got.Gates) != 0 {
		t.Fatalf("late exhaustion re-paused after a positive reading: %+v", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// The receipt and the lifted state survive a restart.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(string(data), "synthetic-A", "synthetic-B", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = Open(configPath, filepath.Dir(authPath), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	restarted, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	current := binding(restarted, true)
	if sameGateSubjects(current.Targets, b.Targets) {
		t.Fatal("fixture did not replace the credential lifecycle")
	}
	if readback, result, err := c.GateOperation(observeID); err != nil || result != lifted || readback.OpID != observeID {
		t.Fatalf("restart lost the observation receipt: %+v %+v %v", readback, result, err)
	}
	// A replaced credential keeps its stale row out of traffic and out of reach.
	if got := state(); len(got.Gates) != 0 || c.AdmitInference(&current, "any-model") != nil {
		t.Fatalf("replacement inherited the lifted pause: %+v", got)
	}
}

func TestUpstreamBalanceResumeRejectsDriftedLifecycle(t *testing.T) {
	c, configPath, authPath, snapshot := publicationFixture(t)
	b := resource.Binding{Scope: snapshot.Version}
	for _, r := range snapshot.Resources {
		if r.Kind == "credential" && r.ParentID != "" {
			b.Targets = []resource.Target{r.Target}
		}
	}
	if len(b.Targets) != 1 {
		t.Fatal("fixture lost its configured credential")
	}
	if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", time.Now().Add(-2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(string(data), "synthetic-A", "synthetic-B", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = Open(configPath, filepath.Dir(authPath), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	restarted, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	current := resource.Binding{Scope: restarted.Version}
	for _, r := range restarted.Resources {
		if r.Kind == "credential" && r.ParentID != "" {
			current.Targets = append(current.Targets, r.Target)
		}
	}
	if result, reason, err := c.ObserveUpstreamBalanceReading(uuid.NewString(), current, "synthetic", UpstreamBalanceReading{ObservedAtMS: time.Now().UnixMilli(), Available: true, SourceID: "billing-api"}, time.Now()); err != nil ||
		result.Applied || reason != UpstreamBalanceResumeReasonLifecycleChanged {
		t.Fatalf("drifted lifecycle: %+v reason=%q err=%v", result, reason, err)
	}
	if result, reason, err := c.ResumeUpstreamBalance(uuid.NewString(), current, "synthetic", "manual_resume", time.Now()); err != nil ||
		result.Applied || reason != UpstreamBalanceResumeReasonLifecycleChanged {
		t.Fatalf("drifted lifecycle resume: %+v reason=%q err=%v", result, reason, err)
	}
	state, err := c.GateState()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Gates) != 1 || state.Gates[0].Applicability != "reconciliation_required" {
		t.Fatalf("drifted pause was cleared or hid its state: %+v", state)
	}
	if err := c.AdmitInference(&current, "any-model"); err != nil {
		t.Fatalf("replacement stayed blocked: %v", err)
	}
}
