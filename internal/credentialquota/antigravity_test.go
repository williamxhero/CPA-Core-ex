package credentialquota

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestAntigravityQuotaSummaryRejectsInventedWindows(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"groups":[]}`,
		`{"groups":[{"displayName":"Gemini","buckets":[{"window":"weekly","resetTime":"2099-01-01T00:00:00Z"}]}]}`,
		`{"groups":[{"displayName":"Gemini","buckets":[{"window":"weekly","remainingFraction":1.1,"resetTime":"2099-01-01T00:00:00Z"}]}]}`,
		`{"groups":[{"displayName":"Gemini","buckets":[{"window":"weekly","remainingFraction":0.5,"resetTime":"invalid"}]}]}`,
		`{"groups":[{"displayName":"Gemini","buckets":[{"window":"weekly","remainingFraction":0.5,"resetTime":"2099-01-01T00:00:00Z"},{"window":"weekly","remainingFraction":0.5,"resetTime":"2099-01-01T00:00:00Z"}]}]}`,
	} {
		obs := antigravityQuotaWindows(resource.QuotaObservation{}, []byte(body))
		if obs.QueryStatus != "parse_error" || len(obs.Windows) != 0 || obs.Complete || obs.RecoveryEligible {
			t.Fatalf("malformed quota acquired evidence: %+v", obs)
		}
	}
	obs := antigravityQuotaWindows(resource.QuotaObservation{}, []byte(`{"groups":[{"displayName":"Gemini","buckets":[{"window":"5h","remainingFraction":0,"resetTime":"2099-01-01T00:00:00Z"}]}]}`))
	if obs.QueryStatus != "success" || len(obs.Windows) != 1 || obs.Windows[0].RemainingFraction != 0 || obs.Windows[0].SourceStatus != "rate-limited" || obs.RecoveryEligible || obs.Complete {
		t.Fatal("zero quota was lost or promoted to policy evidence")
	}
}

func TestAntigravityQuotaEndpointFence(t *testing.T) {
	for _, endpoint := range []string{
		"http://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary",
		"https://daily-cloudcode-pa.googleapis.com.attacker.test/v1internal:retrieveUserQuotaSummary",
		"https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary?redirect=secret",
	} {
		_, status, _ := readAntigravityQuota(context.Background(), endpoint, "test-token", nil, NetworkOptions{})
		if status != "needs_configuration" {
			t.Fatal("unapproved OAuth quota destination accepted")
		}
	}
	if AllowedEndpoint(antigravityQuotaEndpoints[0]) {
		t.Fatal("plugin GET lane acquired native OAuth quota access")
	}
}
