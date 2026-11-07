package auth

import (
	"context"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestAggregatePlanQuotaKeepsPlanAvailableWhenAnyWindowRemains(t *testing.T) {
	if got := AggregatePlanQuota(QuotaExhausted, QuotaAvailable, QuotaExhausted); got != QuotaAvailable {
		t.Fatalf("plan with one available window = %v, want available", got)
	}
	if got := AggregatePlanQuota(QuotaExhausted, QuotaExhausted, QuotaExhausted); got != QuotaExhausted {
		t.Fatalf("all exhausted plan = %v, want exhausted", got)
	}
	if got := AggregatePlanQuota(QuotaExhausted, QuotaUnknown); got != QuotaUnknown {
		t.Fatalf("plan with unknown window = %v, want unknown", got)
	}
}

func TestQuotaTerminationFromSignalsRequiresBothResourceClasses(t *testing.T) {
	cases := []struct {
		name    string
		signals map[string]string
		want    QuotaTermination
	}{
		{
			name: "one plan window remains",
			signals: map[string]string{
				"X-Codex-5h-Used-Percent":    "100",
				"X-Codex-1week-Used-Percent": "0",
				"X-Codex-Credits-Balance":    "0",
			},
			want: QuotaTermination{Plan: QuotaAvailable, Recharge: QuotaExhausted},
		},
		{
			name: "plan exhausted credits available",
			signals: map[string]string{
				"X-Codex-5h-Used-Percent":    "100",
				"X-Codex-1week-Used-Percent": "100",
				"X-Codex-Credits-Balance":    "1",
			},
			want: QuotaTermination{Plan: QuotaExhausted, Recharge: QuotaAvailable},
		},
		{
			name: "both exhausted",
			signals: map[string]string{
				"X-Codex-5h-Used-Percent":     "100",
				"X-Codex-1week-Used-Percent":  "100",
				"X-Codex-1month-Used-Percent": "100",
				"X-Codex-Credits-Balance":     "0",
			},
			want: QuotaTermination{Plan: QuotaExhausted, Recharge: QuotaExhausted},
		},
		{
			name: "credits not observed",
			signals: map[string]string{
				"X-Codex-5h-Used-Percent":    "100",
				"X-Codex-1week-Used-Percent": "100",
			},
			want: QuotaTermination{Plan: QuotaExhausted, Recharge: QuotaUnknown},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quotaTerminationFromSignals("codex", tc.signals)
			if got != tc.want {
				t.Fatalf("quota termination = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestRechargeAvailabilityTreatsExplicitZeroAsExhausted(t *testing.T) {
	if got := rechargeAvailabilityFromSignals("codex", map[string]string{"X-Codex-Credits-Balance": "0"}); got != QuotaExhausted {
		t.Fatalf("zero credits = %v, want exhausted", got)
	}
	if got := rechargeAvailabilityFromSignals("codex", map[string]string{"X-Codex-Credits-Has-Credits": "False"}); got != QuotaExhausted {
		t.Fatalf("explicit no credits = %v, want exhausted", got)
	}
	if got := rechargeAvailabilityFromSignals("codex", map[string]string{"X-Codex-Credits-Balance": "not-a-number"}); got != QuotaUnknown {
		t.Fatalf("invalid credits read = %v, want unknown", got)
	}
}

func TestManagerAllCandidatesQuotaTerminatedUsesANDAcrossCredentials(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	now := time.Now()
	manager.auths = map[string]*Auth{
		"both": {
			ID: "both", Provider: "codex",
			Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
				"X-Codex-5h-Used-Percent": "100", "X-Codex-Credits-Balance": "0",
			}},
		},
		"partial": {
			ID: "partial", Provider: "codex",
			Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
				"X-Codex-5h-Used-Percent": "100", "X-Codex-Credits-Balance": "1",
			}},
		},
	}
	if manager.allCandidatesQuotaTerminated([]string{"codex"}) {
		t.Fatal("one credential with recharge remaining must keep the request retryable")
	}
	delete(manager.auths, "partial")
	if !manager.allCandidatesQuotaTerminated([]string{"codex"}) {
		t.Fatal("all credentials with both resources exhausted must terminate")
	}

	manager.auths["unknown"] = &Auth{ID: "unknown", Provider: "codex", Quota: QuotaState{ObservedAt: now}}
	if manager.allCandidatesQuotaTerminated([]string{"codex"}) {
		t.Fatal("unknown quota state must not terminate")
	}
}

func TestQuotaErrorWithOneResourceRemainingStillRetries(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.auths["quota-partial"] = &Auth{
		ID: "quota-partial", Provider: "codex",
		Quota: QuotaState{ObservedAt: time.Now(), Signals: map[string]string{
			"X-Codex-5h-Used-Percent": "100", "X-Codex-Credits-Balance": "1",
		}},
	}
	retryAfter := 2 * time.Second
	err := withTrustedRetryAfter(quotaTestStatusError{status: 429, msg: "quota exhausted"}, &retryAfter)
	wait, retry := manager.shouldRetryAfterErrorWithAttempted(context.Background(), cliproxyexecutor.Options{}, err, 0, []string{"codex"}, "model", time.Second, -1, 0, nil)
	if !retry || wait != retryAfter {
		t.Fatalf("quota with one resource remaining = wait %s retry %t, want %s/true", wait, retry, retryAfter)
	}
}

func TestQuotaErrorStopsOnlyWhenAllCandidatesHaveBothResourcesExhausted(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.auths["quota-both"] = &Auth{
		ID: "quota-both", Provider: "codex",
		Quota: QuotaState{ObservedAt: time.Now(), Signals: map[string]string{
			"X-Codex-5h-Used-Percent": "100", "X-Codex-Credits-Balance": "0",
		}},
	}
	err := quotaTestStatusError{status: 429, msg: "quota exhausted"}
	if wait, retry := manager.shouldRetryAfterErrorWithAttempted(context.Background(), cliproxyexecutor.Options{}, err, 0, []string{"codex"}, "model", time.Hour, -1, 0, nil); retry || wait != 0 {
		t.Fatalf("both resources exhausted = wait %s retry %t, want 0/false", wait, retry)
	}
}

type quotaTestStatusError struct {
	status int
	msg    string
}

func (e quotaTestStatusError) Error() string   { return e.msg }
func (e quotaTestStatusError) StatusCode() int { return e.status }
