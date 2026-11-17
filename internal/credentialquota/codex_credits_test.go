package credentialquota

import "testing"

func TestCodexResetCreditsFromUsage(t *testing.T) {
	got := codexResetCreditsFromUsage([]byte(`{"rate_limit_reset_credits":{"available_count":1,"applicable_available_count":0}}`))
	if got == nil || got.AvailableCount != 1 || got.ApplicableAvailableCount == nil || *got.ApplicableAvailableCount != 0 {
		t.Fatalf("reset credits = %#v", got)
	}
	for _, tc := range []struct {
		name, body string
	}{
		{"missing object", `{"rate_limit":{}}`},
		{"missing count", `{"rate_limit_reset_credits":{"applicable_available_count":0}}`},
		{"negative count", `{"rate_limit_reset_credits":{"available_count":-1}}`},
		{"fractional count", `{"rate_limit_reset_credits":{"available_count":1.5}}`},
		{"text count", `{"rate_limit_reset_credits":{"available_count":"1"}}`},
		{"implausible count", `{"rate_limit_reset_credits":{"available_count":1001}}`},
		{"null object", `{"rate_limit_reset_credits":null}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if codexResetCreditsFromUsage([]byte(tc.body)) != nil {
				t.Fatalf("invented reset credits for %s", tc.body)
			}
		})
	}
	// Applicable can never exceed what was granted; inability to reconcile it
	// drops only that field, never the count that upstream did report.
	split := codexResetCreditsFromUsage([]byte(`{"rate_limit_reset_credits":{"available_count":1,"applicable_available_count":2}}`))
	if split == nil || split.AvailableCount != 1 || split.ApplicableAvailableCount != nil {
		t.Fatalf("split evidence = %#v", split)
	}
	withoutApplicable := codexResetCreditsFromUsage([]byte(`{"rate_limit_reset_credits":{"available_count":0}}`))
	if withoutApplicable == nil || withoutApplicable.AvailableCount != 0 || withoutApplicable.ApplicableAvailableCount != nil {
		t.Fatalf("count without applicable = %#v", withoutApplicable)
	}
}

func TestCodexCreditsFromUsage(t *testing.T) {
	got := codexCreditsFromUsage([]byte(`{"credits":{"has_credits":true,"unlimited":false,"balance":18.4,"overage_limit_reached":false}}`))
	if got == nil || !got.HasCredits || got.Unlimited || got.OverageLimitReached || got.Balance != "18.4" {
		t.Fatalf("credits = %#v", got)
	}
	if codexCreditsFromUsage([]byte(`{"rate_limit":{}}`)) != nil {
		t.Fatal("missing credits object was invented")
	}
	unlimited := codexCreditsFromUsage([]byte(`{"credits":{"unlimited":true,"balance":null}}`))
	if unlimited == nil || !unlimited.Unlimited || unlimited.Balance != "" {
		t.Fatalf("unlimited = %#v", unlimited)
	}
}
