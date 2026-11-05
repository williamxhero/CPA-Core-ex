package credentialquota

import "testing"

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
