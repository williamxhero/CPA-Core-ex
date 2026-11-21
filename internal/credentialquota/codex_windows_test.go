package credentialquota

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestCodexQuotaPreservesActualWindowDurations(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		seconds    []int64
	}{
		{"single_weekly_primary", `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":4,"reset_at":2000000000,"limit_window_seconds":604800}}}`, []int64{604800}},
		{"five_hour_and_weekly", `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":34,"reset_at":2000000000,"limit_window_seconds":18000},"secondary_window":{"used_percent":5,"reset_at":2000000000,"limit_window_seconds":604800}}}`, []int64{18000, 604800}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codexUsageWindows(resource.QuotaObservation{QueryStatus: "success", Protocol: "codex-oauth-wham", ObservedAtMS: time.Now().UnixMilli()}, []byte(tc.body))
			if got.QueryStatus != "success" || len(got.Windows) != len(tc.seconds) {
				t.Fatalf("unexpected windows: %+v", got)
			}
			doc := ojson.NewDocString(`{}`)
			if err := doc.Set("windows", got.Windows); err != nil {
				t.Fatal(err)
			}
			windows := doc.Get("windows").Array()
			for i, w := range windows {
				if w.Get("limitWindowSeconds").Int() != tc.seconds[i] {
					t.Errorf("window %d duration=%d want=%d", i, w.Get("limitWindowSeconds").Int(), tc.seconds[i])
				}
			}
		})
	}
}

func TestCodexWHAMQuotaWindowUsesExactPercentForRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, used, status  string
		recovery, remaining bool
	}{
		{"below", "99.9999999999999999", "success", true, true},
		{"below_exponent", "9.99999999999999999e1", "success", true, true},
		{"display_underflows", "99." + strings.Repeat("9", 400), "success", true, false},
		{"exact", "100.0000000000000000", "success", false, false},
		{"above", "100.0000000000000001", "parse_error", false, false},
		{"negative_underflow", "-1e-1000", "parse_error", false, false},
		{"quoted", "\"100\"", "parse_error", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset := time.Now().Add(time.Hour).Unix()
			payload := fmt.Appendf(nil,
				"{\"rate_limit\":{\"allowed\":true,\"limit_reached\":false,\"primary_window\":{\"used_percent\":10,\"reset_at\":%d,\"limit_window_seconds\":18000},\"secondary_window\":{\"used_percent\":%s,\"reset_at\":%d,\"limit_window_seconds\":604800}}}",
				reset, tc.used, reset,
			)
			obs := codexUsageWindows(resource.QuotaObservation{
				QueryStatus: "success", Protocol: "codex-oauth-wham", AccountProvenance: "selected_oauth_account",
			}, payload)
			if obs.QueryStatus != tc.status || obs.RecoveryEligible != tc.recovery {
				t.Fatalf("status=%s recovery=%v, want %s/%v", obs.QueryStatus, obs.RecoveryEligible, tc.status, tc.recovery)
			}
			if tc.status == "success" && (len(obs.Windows) != 2 || obs.Windows[1].UsedPercent != 100 ||
				(obs.Windows[1].RemainingFraction > 0) != tc.remaining) {
				t.Fatalf("unexpected display windows: %+v", obs.Windows)
			}
		})
	}
}
