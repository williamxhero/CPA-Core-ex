package clienterror

import (
	"strings"
	"time"
)

// HiddenClientRetryMinimum is the number of additional attempts CPA makes for
// upstream failures that must not be returned to the client on the first hit.
const HiddenClientRetryMinimum = 2

// HiddenClientRetryExtra is how many further rounds CPA keeps after the
// configured request-retry budget, including rounds that max-retry-interval
// would otherwise hand back to the client.
const HiddenClientRetryExtra = 30

// HiddenClientRetryGap is the pause between those extra rounds.
const HiddenClientRetryGap = time.Second

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
	// Incomplete Codex streams and OpenAI "stream disconnected" failures must stay
	// inside CPA. The bare incomplete-stream wording has no help.openai.com hint,
	// but replaying on another credential is still the correct recovery.
	return strings.Contains(lower, "stream disconnected before completion") ||
		strings.Contains(lower, "stream closed before response.completed")
}
