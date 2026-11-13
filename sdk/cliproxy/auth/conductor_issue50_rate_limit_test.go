package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// Issue 50: a ChatGPT detail rate-limit 429 must cool as transient_rate_limit,
// never as reason=quota, so the only usable credential stays recoverable.
func TestIssue50MarkResultDetailRateLimitNotQuota(t *testing.T) {
	withQuotaCooldownEnabled(t)

	retryAfter := 37 * time.Second
	manager := NewManager(nil, nil, nil)
	auth := &Auth{
		ID:       "auth-detail-rate-limit",
		Provider: "codex",
		Metadata: map[string]any{"type": "codex"},
		ModelStates: map[string]*ModelState{
			"gpt-6.1-sol": {Status: StatusActive},
			"gpt-6-astra": {Status: StatusActive},
		},
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}

	before := time.Now()
	manager.MarkResult(context.Background(), Result{
		AuthID:     auth.ID,
		Provider:   "codex",
		Model:      "gpt-6.1-sol",
		Success:    false,
		RetryAfter: &retryAfter,
		Error: &Error{
			Code:       ErrorCodeTransientRateLimit,
			Message:    `{"detail":"Rate limit exceeded"}`,
			Retryable:  true,
			HTTPStatus: http.StatusTooManyRequests,
		},
	})

	got, ok := manager.GetByID(auth.ID)
	if !ok || got == nil {
		t.Fatal("auth not found after MarkResult")
	}
	state := got.ModelStates["gpt-6.1-sol"]
	if state == nil {
		t.Fatal("expected model state for gpt-6.1-sol")
	}
	if !state.Unavailable {
		t.Fatal("reporting model must cool during the rate-limit window")
	}
	if state.NextRetryAfter.Before(before.Add(30*time.Second)) || state.NextRetryAfter.After(before.Add(45*time.Second)) {
		t.Fatalf("NextRetryAfter = %v, want ~37s after start", state.NextRetryAfter)
	}
	if state.Quota.Exceeded || state.Quota.Reason == "quota" {
		t.Fatalf("detail rate limit must not be stored as quota, got %+v", state.Quota)
	}
	if got.Quota.Exceeded || got.Quota.Reason == "quota" || got.Quota.Reason == "credential_quota" {
		t.Fatalf("credential must not be labelled quota, got %+v", got.Quota)
	}
	sibling := got.ModelStates["gpt-6-astra"]
	if sibling != nil && (sibling.Unavailable || sibling.Quota.Exceeded) {
		t.Fatalf("sibling model must stay available, got %+v", sibling)
	}
}

func TestIssue50ResultErrorFromDetailRateLimit(t *testing.T) {
	err := issue50DetailRateLimitError{msg: `{"detail":"Rate limit exceeded"}`}
	resultErr := resultErrorFromError(err)
	if resultErr == nil || resultErr.Code != ErrorCodeTransientRateLimit {
		t.Fatalf("result error code = %v, want %q", resultErr, ErrorCodeTransientRateLimit)
	}
	if !isTransientRateLimitResultError(resultErr) {
		t.Fatal("isTransientRateLimitResultError must be true")
	}
}

type issue50DetailRateLimitError struct{ msg string }

func (e issue50DetailRateLimitError) Error() string              { return e.msg }
func (e issue50DetailRateLimitError) StatusCode() int            { return http.StatusTooManyRequests }
func (e issue50DetailRateLimitError) IsTransientRateLimit() bool { return true }
