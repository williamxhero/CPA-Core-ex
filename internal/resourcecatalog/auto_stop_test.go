package resourcecatalog

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestAutoStopProjectionIgnoresModelScopedCodexGate(t *testing.T) {
	c, _, _, snapshot := publicationFixture(t)
	var b resource.Binding
	var providerID string
	for _, row := range snapshot.Resources {
		if row.Kind == "credential" && row.ParentID != "" {
			b = resource.Binding{Scope: snapshot.Version, Targets: []resource.Target{row.Target}}
			providerID = row.ParentID
			break
		}
	}
	now := time.Now()
	handled, err := c.ObserveCodexQuotaRejection(b, "synthetic", strings.Repeat("a", 64), now, resource.CodexQuotaRejection{
		Model: resource.CodexSparkModel, Window: "secondary", WindowSeconds: 604800,
		ObservedAtMS: now.Add(-time.Second).UnixMilli(), ResetAtMS: now.Add(time.Hour).UnixMilli(),
	})
	if err != nil || !handled {
		t.Fatalf("could not publish spark gate: handled=%v err=%v", handled, err)
	}
	if err := c.AdmitInference(&b, resource.CodexSparkModel); !errors.Is(err, ErrGateDenied) {
		t.Fatalf("spark admission: %v, want gate denial", err)
	}
	if err := c.AdmitInference(&b, "gpt-6.2-astra"); err != nil {
		t.Fatalf("spark gate denied another model: %v", err)
	}
	view, err := c.AutoStopProjection()
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range view.Providers {
		if provider.ResourceID != providerID {
			continue
		}
		if provider.State != "available" || provider.PausedCount != 0 || len(provider.Reasons) != 0 ||
			len(provider.Members) != 1 || provider.Members[0].State != "available" || len(provider.Members[0].Reasons) != 0 {
			t.Fatalf("spark gate paused an entire access point: %+v", provider)
		}
		return
	}
	t.Fatal("configured provider missing from projection")
}
