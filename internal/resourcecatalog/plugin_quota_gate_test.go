package resourcecatalog

import (
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionLimitsPreventRepeatDispatchAcrossRestart(t *testing.T) {
	for _, bucket := range []string{"rolling", "weekly", "monthly", "upstream", "monthly-only"} {
		t.Run(bucket, func(t *testing.T) {
			c, path, authPath, snap := publicationFixture(t)
			var b resource.Binding
			for _, r := range snap.Resources {
				if r.Kind == "credential" && r.ParentID == "" {
					b = resource.Binding{Scope: snap.Version, Targets: append([]resource.Target{r.Target}, r.SourceBindings...)}
					break
				}
			}
			now := time.Now()
			o := resource.QuotaObservation{Binding: b, SourceVersion: strings.Repeat("b", 64), ProtocolVersion: 1, Protocol: "opencode-go-usage", AccountProvenance: "selected_key_subscription", TimestampProvenance: "upstream_http_date", QueryStatus: "success", Complete: true, ObservedAtMS: now.Add(-time.Second).UnixMilli()}
			for _, n := range []string{"rolling", "weekly", "monthly"} {
				w := resource.QuotaWindow{Name: n, SourceStatus: "ok", UsedPercent: 25, RemainingFraction: .75, ResetAt: now.Add(24 * time.Hour).Format(time.RFC3339)}
				if n == bucket || bucket == "monthly-only" && n == "monthly" {
					w.SourceStatus = "rate-limited"
					w.RemainingFraction = 0
					w.UsedPercent = 100
				}
				o.Windows = append(o.Windows, w)
			}
			if bucket == "monthly-only" {
				o.Protocol = "qwen-coding-plan-cli"
				o.AccountProvenance = "configured_cli_profile"
				o.TimestampProvenance = "local_cli_acquisition_time"
				o.Windows = o.Windows[2:]
				o.Complete = false
			}
			if bucket == "upstream" {
				if err := c.PluginQuotaRejected(resource.QuotaSource{Binding: b, State: "ready", AuthIndex: "a", SourceVersion: o.SourceVersion, Protocol: o.Protocol}, now); err != nil {
					t.Fatal(err)
				}
			} else if err := c.RecheckPluginQuota("a", now, o); err != nil {
				t.Fatal(err)
			}
			check := func() {
				t.Helper()
				for i := 0; i < 2; i++ {
					if c.AdmitInference(&o.Binding, "m") == nil {
						t.Fatal("dispatched exhausted subscription")
					}
				}
			}
			check()
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			var err error
			c, err = Open(path, filepath.Dir(authPath), "")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			s, err := c.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			o.Scope = s.Version
			check()
			for i := range o.Windows {
				o.Windows[i].SourceStatus = "ok"
				o.Windows[i].RemainingFraction = .8
				o.Windows[i].UsedPercent = 20
			}
			if err = c.RecheckPluginQuota("a", now.Add(-time.Hour), o); err != nil {
				t.Fatal(err)
			}
			check()
			o.ObservedAtMS = time.Now().Add(time.Second).UnixMilli()
			if err = c.RecheckPluginQuota("a", time.Now(), o); err != nil {
				t.Fatal(err)
			}
			if c.AdmitInference(&o.Binding, "m") != nil {
				t.Fatal("fresh recovery did not restore route")
			}
		})
	}
}
