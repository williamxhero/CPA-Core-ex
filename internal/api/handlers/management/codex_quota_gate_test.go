package management

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestCodexQuotaConfirmsWholeAccountWithAnotherAllowedWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	weeklyReset := now.Add(7 * 24 * time.Hour)
	fiveHourReset := now.Add(4 * time.Hour)
	evidence := resource.CodexQuotaRejection{
		Window:        "secondary",
		WindowSeconds: 604800,
		ObservedAtMS:  now.UnixMilli(),
		ResetAtMS:     weeklyReset.UnixMilli(),
	}
	standardWindows := func() []resource.QuotaWindow {
		return []resource.QuotaWindow{
			{Name: "primary", LimitWindowSeconds: 18000, ResetAt: fiveHourReset.Format(time.RFC3339), SourceStatus: "allowed", CodexUsage: resource.CodexWindowUsageBelowLimit},
			{Name: "secondary", LimitWindowSeconds: 604800, ResetAt: weeklyReset.Format(time.RFC3339), SourceStatus: "rate-limited", CodexUsage: resource.CodexWindowUsageAtLimit},
		}
	}
	observation := func() resource.QuotaObservation {
		return resource.QuotaObservation{
			QueryStatus:           "success",
			Complete:              true,
			StandardOnlyNoCredits: true,
			TimestampProvenance:   "upstream_http_date",
			ObservedAtMS:          now.Add(time.Second).UnixMilli(),
			Windows:               standardWindows(),
		}
	}
	tests := []struct {
		name   string
		mutate func(*resource.QuotaObservation, *resource.CodexQuotaRejection)
		want   bool
	}{
		{
			name: "weekly exhausted while five hour window still allowed",
			want: true,
		},
		{
			name: "prolite single weekly window",
			mutate: func(obs *resource.QuotaObservation, ev *resource.CodexQuotaRejection) {
				obs.Windows = []resource.QuotaWindow{{Name: "primary", LimitWindowSeconds: 604800, ResetAt: weeklyReset.Format(time.RFC3339), SourceStatus: "rate-limited", CodexUsage: resource.CodexWindowUsageAtLimit}}
				ev.Window = "primary"
				ev.WindowSeconds = 604800
			},
			want: true,
		},
		{
			name: "usable credits forbid account wide pause",
			mutate: func(obs *resource.QuotaObservation, _ *resource.CodexQuotaRejection) {
				obs.StandardOnlyNoCredits = false
			},
			want: false,
		},
		{
			name: "independent model window forbids account wide pause",
			mutate: func(obs *resource.QuotaObservation, _ *resource.CodexQuotaRejection) {
				obs.Windows = append(obs.Windows, resource.QuotaWindow{Name: "spark", Model: resource.CodexSparkModel, LimitWindowSeconds: 604800, ResetAt: weeklyReset.Format(time.RFC3339), SourceStatus: "allowed", CodexUsage: resource.CodexWindowUsageBelowLimit})
			},
			want: false,
		},
		{
			name: "reset mismatch is not the same rejection",
			mutate: func(obs *resource.QuotaObservation, _ *resource.CodexQuotaRejection) {
				obs.Windows[1].ResetAt = weeklyReset.Add(time.Hour).Format(time.RFC3339)
			},
			want: false,
		},
		{
			name: "no exhausted window",
			mutate: func(obs *resource.QuotaObservation, _ *resource.CodexQuotaRejection) {
				obs.Windows[1].SourceStatus = "allowed"
				obs.Windows[1].CodexUsage = resource.CodexWindowUsageBelowLimit
			},
			want: false,
		},
		{
			name: "observation older than rejection",
			mutate: func(obs *resource.QuotaObservation, _ *resource.CodexQuotaRejection) {
				obs.ObservedAtMS = now.Add(-time.Minute).UnixMilli()
			},
			want: false,
		},
		{
			name: "incomplete read",
			mutate: func(obs *resource.QuotaObservation, _ *resource.CodexQuotaRejection) {
				obs.Complete = false
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := observation()
			ev := evidence
			if tc.mutate != nil {
				tc.mutate(&obs, &ev)
			}
			if got := codexQuotaConfirmsWholeAccount(obs, ev, now); got != tc.want {
				t.Fatalf("codexQuotaConfirmsWholeAccount() = %t, want %t", got, tc.want)
			}
		})
	}
}
