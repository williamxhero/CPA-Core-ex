package auth

import (
	"net/http"
	"strings"
	"time"
)

// Explicit inference rejection is independent of optional scheduling cooldowns.
// It records only the rejected window; other subscription windows are unknown.
func (q *QuotaState) observeOpenCodeQuotaFailure(result Result, now time.Time) {
	if q == nil || result.Success || !strings.EqualFold(result.Provider, "opencode-go") || !result.CredentialScope || result.Error == nil || result.Error.HTTPStatus != http.StatusTooManyRequests {
		return
	}
	message := strings.ToLower(strings.TrimSpace(result.Error.Message))
	for _, window := range []string{"rolling", "weekly", "monthly"} {
		prefix := "opencode go usage limit reached (" + window
		if !strings.HasPrefix(message, prefix+",") && !strings.HasPrefix(message, prefix+").") {
			continue
		}
		q.ObservedAt = now
		q.Signals = map[string]string{"OpenCode-Go-Window": window, "OpenCode-Go-Remaining": "0"}
		if result.RetryAfter != nil && *result.RetryAfter > 0 && *result.RetryAfter <= 366*24*time.Hour {
			q.Signals["OpenCode-Go-Reset-At"] = now.Add(*result.RetryAfter).UTC().Format(time.RFC3339Nano)
		}
		return
	}
}
