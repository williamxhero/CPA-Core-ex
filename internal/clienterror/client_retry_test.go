package clienterror

import (
	"net/http"
	"testing"
)

func TestIsHiddenClientRetry(t *testing.T) {
	openai := "stream disconnected before completion: An error occurred while processing your request. You can retry your request, or contact us through our help center at help.openai.com if the error persists. Please include the request ID dd477f75-8c37-4b8f-9390-03f6543fe6dd in your message"
	if !IsHiddenClientRetry(openai) {
		t.Fatal("openai processing failure should be retried inside CPA")
	}
	if !IsHiddenClientRetry("你已达到使用上限。请稍后再试。") {
		t.Fatal("usage-limit text should be retried inside CPA")
	}
	if !IsHiddenClientRetry(`{"error":{"message":"Selected model is at capacity. Please try a different model."}}`) {
		t.Fatal("model capacity text should be retried inside CPA")
	}
	if !IsHiddenClientRetry(`{"error":{"code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later."}}`) {
		t.Fatal("overload text should be retried inside CPA")
	}
	if !IsHiddenClientRetry(`{"error":{"code":"permission_denied","message":"We’re currently experiencing high demand, which may cause temporary errors."}}`) {
		t.Fatal("high-demand text should be retried inside CPA")
	}
	if IsHiddenClientRetry(`{"error":{"type":"usage_limit_reached","message":"Selected model is at capacity. Please try a different model."}}`) {
		t.Fatal("exhausted quota must not be replayed as capacity")
	}
	if !IsHiddenClientRetry("stream disconnected before completion: stream closed before response.completed") {
		t.Fatal("incomplete stream must be retried inside CPA")
	}
	if !IsHiddenClientRetry("stream error: stream disconnected before completion: stream closed before response.completed") {
		t.Fatal("codex incomplete-stream message must be retried inside CPA")
	}
	if !IsHiddenClientRetry("stream disconnected before completion: stream error: stream disconnected before completion: stream closed before response.completed") {
		t.Fatal("nested stream disconnect message must be retried inside CPA")
	}
	if IsHiddenClientRetry("invalid api key") {
		t.Fatal("unrelated errors must stay visible")
	}
}

func TestClassifyDoesNotUseHTTPStatusAsQuotaMeaning(t *testing.T) {
	if got := Classify(http.StatusSeeOther, "quota exhausted"); got != FailureQuotaExhausted {
		t.Fatalf("303 quota body classified as %v, want quota exhausted", got)
	}
	if got := Classify(http.StatusSeeOther, "temporary redirect"); got == FailureQuotaExhausted {
		t.Fatal("303 alone must not mean quota exhausted")
	}
	if got := Classify(http.StatusTooManyRequests, "We’re currently experiencing high demand, which may cause temporary errors."); got != FailureTransientUpstream {
		t.Fatalf("high-demand 429 classified as %v, want transient upstream", got)
	}
}
