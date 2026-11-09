package clienterror

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// FailureClass is the provider-agnostic disposition of an upstream failure.
// Provider adapters should map provider-specific codes into this vocabulary
// before the retry coordinator makes a termination decision.
type FailureClass int

// IsUpstreamHTTPResponse reports whether err came from an upstream HTTP
// response rather than from the downstream request context. This distinction
// matters for HTTP 499, which is also used by proxies for upstream disconnects.
func IsUpstreamHTTPResponse(err error) bool {
	if err == nil {
		return false
	}
	type upstreamResponseMarker interface {
		IsUpstreamHTTPResponse() bool
	}
	var marker upstreamResponseMarker
	return errors.As(err, &marker) && marker != nil && marker.IsUpstreamHTTPResponse()
}

const (
	FailureUnknown FailureClass = iota
	FailureClientCanceled
	FailureRequestInvalid
	FailurePermanentAuth
	FailureQuotaExhausted
	FailureTransientUpstream
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
	if isCapacityPressure(lower) {
		return true
	}
	if isQuotaExhausted(lower) {
		return false
	}
	if strings.Contains(lower, "an error occurred while processing your request") &&
		(strings.Contains(lower, "you can retry your request") || strings.Contains(lower, "help.openai.com")) {
		return true
	}
	// Incomplete Codex streams and OpenAI "stream disconnected" failures must stay
	// inside CPA. The bare incomplete-stream wording has no help.openai.com hint,
	// but replaying on another credential is still the correct recovery.
	return isTransientText(lower)
}

// Classify returns the shared retry disposition for an upstream status/body.
// Unknown errors remain conservative; callers may only retry them when they
// carry an explicit transient transport marker.
func Classify(status int, text string) FailureClass {
	raw := strings.TrimSpace(text)
	lower := strings.ToLower(raw)
	if status == StatusClientClosedRequest || strings.Contains(lower, "context canceled") || strings.Contains(lower, "client canceled") {
		return FailureClientCanceled
	}
	// Provider quota identifiers are authoritative even when the upstream uses
	// a generic 400/500 envelope. Check them before request-fault heuristics so
	// quota exhaustion can rotate to another credential/provider.
	if isQuotaExhausted(lower) {
		return FailureQuotaExhausted
	}
	if isCapacityPressure(lower) || isTransientText(lower) || status >= http.StatusInternalServerError || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return FailureTransientUpstream
	}
	if raw != "" && IsRequestFault(status, nil) {
		return FailureRequestInvalid
	}
	if status == http.StatusUnauthorized || (status == http.StatusForbidden && isPermanentAuthText(lower)) {
		return FailurePermanentAuth
	}
	return FailureUnknown
}

func isQuotaExhausted(lower string) bool {
	for _, phrase := range []string{
		"usage_limit_reached", "insufficient_quota", "credit_balance_exhausted", "billing_hard_limit_reached",
		"quota exhausted", "quota_exceeded", "quota exceeded",
		"usage limit has been reached", "credit balance too low", "insufficient credits",
		"overage_limit_reached", "no credits remaining", "you've reached your usage limit",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func isTransientText(lower string) bool {
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "exceeded retry limit") &&
		(strings.Contains(lower, "429") || strings.Contains(lower, "too many requests")) {
		return true
	}
	for _, phrase := range []string{
		"server is busy", "server_busy", "upstream is busy", "temporarily unavailable", "temporary error",
		"connection reset", "connection refused", "stream disconnected", "stream closed",
		"idle timeout", "sse idle", "i/o timeout", "eof", "inference admission unavailable", "admission unavailable",
		"overloaded", "overload", "at capacity", "high demand",
		"too many requests",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

func isPermanentAuthText(lower string) bool {
	for _, phrase := range []string{"invalid api key", "invalid_api_key", "authentication failed", "unauthorized", "token expired", "invalid_grant"} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// isCapacityPressure reports transient model admission failures. A credential
// whose quota is exhausted is not admission pressure and must not be replayed.
func isCapacityPressure(lower string) bool {
	if strings.Contains(lower, "usage_limit_reached") {
		return false
	}
	return strings.Contains(lower, "model is at capacity") ||
		strings.Contains(lower, "at capacity") ||
		strings.Contains(lower, "please try a different model") ||
		strings.Contains(lower, "server_is_overloaded") ||
		strings.Contains(lower, "server is overloaded") ||
		strings.Contains(lower, "servers are currently overloaded") ||
		strings.Contains(lower, "high demand")
}
