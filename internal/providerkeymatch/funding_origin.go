package providerkeymatch

import (
	"net/url"
	"strings"
)

// FundingAdapter resolves only the literal native inference endpoint. For a
// particular source, callers must also prove its actual dispatch credentials.
func FundingAdapter(base string) string {
	base = strings.TrimSpace(base)
	switch base {
	case "https://api.deepinfra.com/v1/openai", "https://api.deepinfra.com/v1/openai/":
		return "deepinfra"
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		(u.Host != "api.deepseek.com" && u.Host != "api.deepseek.com:443") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(base, "#") {
		return ""
	}
	switch u.Path {
	case "", "/", "/v1", "/v1/":
		return "deepseek"
	}
	return ""
}
