package credentialquota

import (
	"fmt"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"testing"
	"time"
)

func TestProliteSingleWeeklyFundingEvidence(t *testing.T) {
	reset := time.Now().Add(121 * time.Hour).Unix()
	for _, tc := range []struct {
		name, additional, credits string
		depleted, paid            bool
	}{
		{"exhausted", `,"additional_rate_limits":null`, `"has_credits":false,"unlimited":false,"balance":"0"`, true, false},
		{"paid", `,"additional_rate_limits":null`, `"has_credits":true,"unlimited":false,"balance":"1","overage_limit_reached":false`, false, true},
		{"missing scope", "", `"has_credits":false,"unlimited":false,"balance":"0"`, false, false},
		{"missing wallet flags", `,"additional_rate_limits":null`, `"balance":"0"`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := fmt.Sprintf(`{"plan_type":"prolite","rate_limit":{"allowed":false,"limit_reached":true,"primary_window":{"used_percent":100,"limit_window_seconds":604800,"reset_at":%d},"secondary_window":null}%s,"credits":{%s}}`, reset, tc.additional, tc.credits)
			obs := codexUsageWindows(resource.QuotaObservation{QueryStatus: "success"}, []byte(data))
			if obs.StandardOnlyNoCredits != tc.depleted || obs.StandardPaidFunding != tc.paid || (tc.depleted || tc.paid) && !obs.Complete {
				t.Fatalf("complete=%v, depleted=%v, paid=%v", obs.Complete, obs.StandardOnlyNoCredits, obs.StandardPaidFunding)
			}
		})
	}
}
