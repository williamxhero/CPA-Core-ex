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

func TestClassifyTransientUpstreamFailureVariants(t *testing.T) {
	tests := []struct {
		name   string
		status int
		text   string
		hidden bool
	}{
		{name: "nested codex stream disconnect", text: "stream disconnected before completion: stream error: stream disconnected before completion: stream closed before response.completed", hidden: true},
		{name: "retry limit after 429", text: "exceeded retry limit, last status: 429 Too Many Requests", hidden: true},
		{name: "capacity", status: http.StatusBadGateway, text: "model is at capacity", hidden: true},
		{name: "busy", text: "upstream is busy, please try again", hidden: true},
		{name: "overload", text: "server is overloaded", hidden: true},
		{name: "connection reset", text: "read tcp 10.0.0.1:443: connection reset by peer", hidden: true},
		{name: "sse idle", text: "SSE idle timeout while waiting for event", hidden: true},
		{name: "http 5xx", status: http.StatusBadGateway, text: "bad gateway"},
		{name: "http 429", status: http.StatusTooManyRequests, text: "too many requests", hidden: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Classify(tt.status, tt.text); got != FailureTransientUpstream {
				t.Fatalf("Classify(%d, %q) = %v, want transient upstream", tt.status, tt.text, got)
			}
			if got := IsHiddenClientRetry(tt.text); got != tt.hidden {
				t.Fatalf("IsHiddenClientRetry(%q) = %t, want %t", tt.text, got, tt.hidden)
			}
		})
	}
}

func TestClassifyTransientUpstreamDoesNotPromoteRequestErrors(t *testing.T) {
	if got := Classify(http.StatusBadRequest, `{"error":{"type":"invalid_request_error","message":"invalid prompt"}}`); got != FailureRequestInvalid {
		t.Fatalf("request error classified as %v, want request invalid", got)
	}
	if got := Classify(http.StatusUnauthorized, "invalid api key"); got != FailurePermanentAuth {
		t.Fatalf("auth error classified as %v, want permanent auth", got)
	}
}
