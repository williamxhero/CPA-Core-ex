package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestOpenCodeQuotaFirstFailureRecordsZeroWithoutCooling(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "cooling", true: "no-cooling"}[disabled], func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			m.SetConfig(nil)
			a := &Auth{ID: "oc-hxm-test", Provider: "opencode-go", Metadata: map[string]any{"disable_cooling": disabled}}
			if _, err := m.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			reset := 403200 * time.Second
			failure := Result{AuthID: a.ID, Provider: a.Provider, Model: "deepseek", CredentialScope: true, RetryAfter: &reset, Error: &Error{Code: "credential_quota", HTTPStatus: http.StatusTooManyRequests, Message: "OpenCode Go usage limit reached (weekly, resets in 4d 16h). To keep going now, turn on Extra Usage or upgrade to Go Plus."}}
			m.MarkResult(context.Background(), failure)
			updated, _ := m.GetByID(a.ID)
			if updated.Quota.ObservedAt.IsZero() || updated.Quota.Signals["OpenCode-Go-Window"] != "weekly" || updated.Quota.Signals["OpenCode-Go-Remaining"] != "0" {
				t.Fatalf("first quota failure did not record zero: %+v", updated.Quota)
			}
			observed := updated.Quota.ObservedAt
			// Unrelated failures and late in-flight success do not prove recovery.
			m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: "deepseek", Success: true})
			m.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: "deepseek", Error: &Error{HTTPStatus: 429, Message: "rate limited"}})
			updated, _ = m.GetByID(a.ID)
			if !updated.Quota.ObservedAt.Equal(observed) || updated.Quota.Signals["OpenCode-Go-Remaining"] != "0" {
				t.Fatal("unrelated response erased exhaustion evidence")
			}
		})
	}
}

func TestOpenCodeQuotaDoesNotInventZeroForOtherFailures(t *testing.T) {
	for _, result := range []Result{
		{Provider: "opencode-go", Error: &Error{HTTPStatus: 429, Message: "rate limited"}},
		{Provider: "opencode-go", CredentialScope: true, Error: &Error{HTTPStatus: 503, Message: "OpenCode Go usage limit reached (weekly)."}},
		{Provider: "codex", CredentialScope: true, Error: &Error{HTTPStatus: 429, Message: "OpenCode Go usage limit reached (weekly)."}},
	} {
		m := NewManager(nil, nil, nil)
		a, err := m.Register(context.Background(), &Auth{ID: "negative-oc", Provider: result.Provider})
		if err != nil {
			t.Fatal(err)
		}
		result.AuthID = a.ID
		m.MarkResult(context.Background(), result)
		updated, _ := m.GetByID(a.ID)
		if len(updated.Quota.Signals) != 0 {
			t.Fatalf("unrelated failure fabricated zero: %+v", updated.Quota)
		}
	}
}
