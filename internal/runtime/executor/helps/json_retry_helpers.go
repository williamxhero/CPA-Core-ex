package helps

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/MoeForge/moego/regexp"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
)

var reGoogleMessageRetryDuration = regexp.MustCompile(`(?i)\b(?:after|retry\s+in)\s+(\d+(?:\.\d+)?(?:h|ms|m|s)(?:\d+(?:\.\d+)?(?:ms|m|s))*)\b`)

// DeleteJSONField removes a top-level or nested JSON field from a payload.
func DeleteJSONField(body []byte, key string) []byte {
	if key == "" || len(body) == 0 {
		return body
	}
	updated, err := util.DeleteJSONBytesIfExists(body, key)
	if err != nil {
		return body
	}
	return updated
}

// DeleteJSONFieldDoc removes a top-level or nested JSON field from doc in place.
func DeleteJSONFieldDoc(doc *ojson.Doc, key string) bool {
	if key == "" || doc == nil || doc.Len() == 0 {
		return false
	}
	return util.DeleteJSONDocIfExists(doc, key) == nil
}

// ParseGoogleRetryAfter extracts a positive retry delay for HTTP 429 responses
// from structured Google RPC error details, standard HTTP Retry-After headers,
// or human-readable error messages.
func ParseGoogleRetryAfter(statusCode int, headers http.Header, errorBody []byte, now time.Time) *time.Duration {
	if statusCode != http.StatusTooManyRequests {
		return nil
	}
	if delay := parseGoogleStructuredRetryDelay(errorBody, false); delay != nil {
		return delay
	}
	if delay := parsePositiveRetryAfterHeader(headers, now); delay != nil {
		return delay
	}
	return parseGoogleMessageRetryDelay(errorBody, false)
}

// ParseAntigravityRecovery trusts only one HTTP Retry-After field or typed
// RetryInfo. The later valid time wins.
func ParseAntigravityRecovery(headers http.Header, body []byte, now time.Time) (time.Time, string) {
	var at time.Time
	source := ""
	if values := headers.Values("Retry-After"); len(values) == 1 {
		raw := strings.TrimSpace(values[0])
		if decimalRetryDigits(raw) {
			n, err := strconv.ParseUint(raw, 10, 64)
			if err == nil && n <= uint64(math.MaxInt64/int64(time.Second)) {
				at = now.Add(time.Duration(n) * time.Second)
			}
		} else if date, err := http.ParseTime(raw); err == nil && !date.Before(now) {
			at = date
		}
		if !at.IsZero() {
			source = "retry_after"
		}
	}
	for _, detail := range ojson.GetBytesNoCopy(body, "error.details").Array() {
		if detail.Get("@type").String() != "type.googleapis.com/google.rpc.RetryInfo" {
			continue
		}
		value := detail.Get("retryDelay")
		if value.Type != ojson.String {
			continue
		}
		raw := value.String()
		seconds, ok := strings.CutSuffix(raw, "s")
		whole, fraction, dotted := strings.Cut(seconds, ".")
		if !ok || !decimalRetryDigits(whole) || (dotted && (!decimalRetryDigits(fraction) || len(fraction) > 9)) {
			continue
		}
		n, err := strconv.ParseUint(whole, 10, 64)
		if err != nil || n > 315576000000 {
			continue
		}
		duration, err := time.ParseDuration(raw)
		if err != nil {
			duration = time.Duration(math.MaxInt64)
		}
		if candidate := now.Add(duration); candidate.After(at) {
			at, source = candidate, "retry_info"
		}
	}
	return at, source
}

func decimalRetryDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ParseRetryDelay extracts the retry delay from a Google API 429 error response,
// preserving explicit zero-delay hints used by callers such as Antigravity.
func ParseRetryDelay(errorBody []byte) (*time.Duration, error) {
	if delay := parseGoogleStructuredRetryDelay(errorBody, true); delay != nil {
		return delay, nil
	}
	if delay := parseGoogleMessageRetryDelay(errorBody, true); delay != nil {
		return delay, nil
	}
	return nil, fmt.Errorf("no RetryInfo found")
}

func isValidRetryDuration(d time.Duration, allowZero bool) bool {
	if allowZero {
		return d >= 0
	}
	return d > 0
}

func parseGoogleStructuredRetryDelay(errorBody []byte, allowZero bool) *time.Duration {
	if len(errorBody) == 0 {
		return nil
	}
	details := ojson.GetBytesNoCopy(errorBody, "error.details")
	if !details.Exists() || !details.IsArray() {
		details = ojson.GetBytesNoCopy(errorBody, "0.error.details")
	}
	if !details.Exists() || !details.IsArray() {
		return nil
	}
	items := details.Array()
	for _, detail := range items {
		if detail.Get("@type").String() != "type.googleapis.com/google.rpc.RetryInfo" {
			continue
		}
		retryDelay := strings.TrimSpace(detail.Get("retryDelay").String())
		if retryDelay == "" {
			continue
		}
		duration, errParse := time.ParseDuration(strings.ToLower(retryDelay))
		if errParse == nil && isValidRetryDuration(duration, allowZero) {
			return &duration
		}
	}
	for _, detail := range items {
		if detail.Get("@type").String() != "type.googleapis.com/google.rpc.ErrorInfo" {
			continue
		}
		quotaResetDelay := strings.TrimSpace(detail.Get("metadata.quotaResetDelay").String())
		if quotaResetDelay == "" {
			continue
		}
		duration, errParse := time.ParseDuration(strings.ToLower(quotaResetDelay))
		if errParse == nil && isValidRetryDuration(duration, allowZero) {
			return &duration
		}
	}
	return nil
}

func parsePositiveRetryAfterHeader(headers http.Header, now time.Time) *time.Duration {
	if headers == nil {
		return nil
	}
	raw := strings.TrimSpace(headers.Get("Retry-After"))
	if raw == "" {
		for key, values := range headers {
			if strings.EqualFold(key, "Retry-After") && len(values) > 0 {
				raw = strings.TrimSpace(values[0])
				break
			}
		}
	}
	if raw == "" {
		return nil
	}
	if seconds, errParse := strconv.ParseInt(raw, 10, 64); errParse == nil {
		if seconds <= 0 {
			return nil
		}
		if seconds > int64(math.MaxInt64)/int64(time.Second) {
			delay := time.Duration(math.MaxInt64)
			return &delay
		}
		delay := time.Duration(seconds) * time.Second
		return &delay
	}
	if deadline, errParse := http.ParseTime(raw); errParse == nil {
		delay := deadline.Sub(now)
		if delay > 0 {
			return &delay
		}
	}
	return nil
}

func parseGoogleMessageRetryDelay(errorBody []byte, allowZero bool) *time.Duration {
	if len(errorBody) == 0 {
		return nil
	}
	message := strings.TrimSpace(ojson.GetBytesNoCopy(errorBody, "error.message").String())
	if message == "" {
		message = strings.TrimSpace(ojson.GetBytesNoCopy(errorBody, "0.error.message").String())
	}
	if message == "" {
		return nil
	}
	for _, matches := range reGoogleMessageRetryDuration.FindAllStringSubmatch(message, -1) {
		if len(matches) < 2 || matches[1] == "" {
			continue
		}
		duration, errParse := time.ParseDuration(strings.ToLower(matches[1]))
		if errParse == nil && isValidRetryDuration(duration, allowZero) {
			return &duration
		}
	}
	return nil
}
