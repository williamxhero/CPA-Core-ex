package executor

import (
	"errors"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Issue 50: chatgpt.com-style {"detail":"Rate limit exceeded"} must be a
// transient rate limit, not credential quota exhaustion.
func TestIssue50DetailRateLimitIsTransientNotQuota(t *testing.T) {
	body := []byte(`{"detail":"Rate limit exceeded"}`)
	headers := http.Header{"Retry-After": []string{"37"}}
	err := newCodexStatusErrWithHeaders(http.StatusTooManyRequests, headers, body)

	if err.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", err.StatusCode())
	}
	if err.IsCredentialScoped() {
		t.Fatal("detail rate limit must not be credential scoped")
	}
	var transient cliproxyexecutor.TransientRateLimitError
	if !errors.As(err, &transient) || transient == nil || !transient.IsTransientRateLimit() {
		t.Fatalf("detail rate limit must be transient, err=%v", err)
	}
	retry := err.RetryAfter()
	if retry == nil || *retry != 37*time.Second {
		t.Fatalf("Retry-After = %v, want 37s", retry)
	}
}

func TestIssue50TypedRateLimitExceededIsTransient(t *testing.T) {
	body := []byte(`{"error":{"type":"rate_limit_error","code":"rate_limit_exceeded","message":"Too many requests"}}`)
	err := newCodexStatusErr(http.StatusTooManyRequests, body)
	if err.IsCredentialScoped() || !err.IsTransientRateLimit() {
		t.Fatalf("rate_limit_exceeded must be transient non-quota, scoped=%t transient=%t", err.IsCredentialScoped(), err.IsTransientRateLimit())
	}
}

func TestIssue50UsageLimitStillQuota(t *testing.T) {
	body := []byte(`{"error":{"type":"usage_limit_reached","message":"You've hit your usage limit.","resets_in_seconds":3600}}`)
	err := newCodexStatusErr(http.StatusTooManyRequests, body)
	if !err.IsCredentialScoped() || err.IsTransientRateLimit() {
		t.Fatalf("usage_limit_reached must stay credential quota, scoped=%t transient=%t", err.IsCredentialScoped(), err.IsTransientRateLimit())
	}
}
