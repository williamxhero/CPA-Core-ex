package clienterror

import "testing"

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
	if IsHiddenClientRetry("stream disconnected before completion: stream closed before response.completed") {
		t.Fatal("a plain incomplete stream is not this retry class")
	}
	if IsHiddenClientRetry("invalid api key") {
		t.Fatal("unrelated errors must stay visible")
	}
}
