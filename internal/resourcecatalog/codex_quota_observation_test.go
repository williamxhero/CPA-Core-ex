package resourcecatalog

import (
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"strings"
	"testing"
	"time"
)

func TestObserveCodexQuotaRejectionPausesCurrentCredentialWithoutPolicy(t *testing.T) {
	c, _, _, snapshot := publicationFixture(t)
	var b resource.Binding
	for _, r := range snapshot.Resources {
		if r.Kind == "credential" && r.ParentID == "" {
			b = resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{r.Target}}
			break
		}
	}
	start := time.Now()
	evidence := resource.CodexQuotaRejection{
		Window:        "secondary",
		WindowSeconds: 604800,
		ObservedAtMS:  start.Add(-time.Second).UnixMilli(),
		ResetAtMS:     start.Add(120 * time.Hour).UnixMilli(),
	}
	for i := 0; i < 2; i++ {
		handled, err := c.ObserveCodexQuotaRejection(b, "synthetic", strings.Repeat("a", 64), start, evidence)
		if err != nil || !handled {
			t.Fatalf("ObserveCodexQuotaRejection() = (%t, %v), want (true, nil)", handled, err)
		}
	}
	if c.AdmitInference(&b, "gpt-6.2-astra") == nil {
		t.Fatal("weekly exhausted credential admitted without a Manager policy")
	}
	state, _ := c.GateState()
	if len(state.Gates) != 1 || state.Revision != 1 {
		t.Fatalf("duplicate pause: %d gates, revision %d", len(state.Gates), state.Revision)
	}
	if state.Gates[0].Owner != "core.codex-quota.v1/secondary/604800" || state.Gates[0].Reason != "quota_windows_exhausted" {
		t.Fatalf("unexpected pause owner/reason: %+v", state.Gates[0])
	}
}

func TestQuotaReadPausesCurrentCredentialWithoutPolicyAndRecovers(t *testing.T) {
	c, _, _, snapshot := publicationFixture(t)
	var b resource.Binding
	for _, r := range snapshot.Resources {
		if r.Kind == "credential" && r.ParentID == "" {
			b = resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{r.Target}}
			break
		}
	}
	now := time.Now()
	o := resource.QuotaObservation{Binding: b, SourceVersion: strings.Repeat("a", 64), ProtocolVersion: 1, Protocol: "codex-oauth-wham", AccountProvenance: "selected_oauth_account", TimestampProvenance: "upstream_http_date", QueryStatus: "success", StandardOnlyNoCredits: true, Complete: true, ObservedAtMS: now.Add(-2 * time.Second).UnixMilli(), Windows: []resource.QuotaWindow{{Name: "primary", LimitWindowSeconds: 604800, ResetAt: now.Add(120 * time.Hour).Format(time.RFC3339), SourceStatus: "rate-limited", CodexUsage: resource.CodexWindowUsageAtLimit}}}
	for i := 0; i < 2; i++ {
		if _, err := c.RecheckCodexQuota("synthetic", now, o); err != nil {
			t.Fatal(err)
		}
	}
	if c.AdmitInference(&b, "gpt-6.2-astra") == nil {
		t.Fatal("exhausted weekly credential admitted after successful quota read")
	}
	state, _ := c.GateState()
	if len(state.Gates) != 1 || state.Revision != 1 {
		t.Fatalf("duplicate pause: %d gates, revision %d", len(state.Gates), state.Revision)
	}
	o.Windows[0].CodexUsage = resource.CodexWindowUsageBelowLimit
	o.Windows[0].SourceStatus = "allowed"
	o.ObservedAtMS = now.UnixMilli()
	if _, err := c.RecheckCodexQuota("synthetic", time.Now(), o); err != nil || c.AdmitInference(&b, "gpt-6.2-astra") != nil {
		t.Fatalf("fresh recovery failed: %v", err)
	}
}
