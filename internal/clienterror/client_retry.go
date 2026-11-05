package clienterror

import "strings"

// HiddenClientRetryMinimum is the number of additional attempts CPA makes for
// upstream failures that must not be returned to the client on the first hit.
const HiddenClientRetryMinimum = 2

// IsHiddenClientRetry reports upstream failures CPA retries itself.
// The client sees them only after those attempts are exhausted.
func IsHiddenClientRetry(text string) bool {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return false
	}
	if strings.Contains(raw, "你已达到使用上限") {
		return true
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "selected model is at capacity") {
		return true
	}
	if strings.Contains(lower, "an error occurred while processing your request") &&
		(strings.Contains(lower, "you can retry your request") || strings.Contains(lower, "help.openai.com")) {
		return true
	}
	return strings.Contains(lower, "stream disconnected before completion") &&
		(strings.Contains(lower, "you can retry your request") ||
			strings.Contains(lower, "help.openai.com") ||
			strings.Contains(lower, "an error occurred while processing your request"))
}
