package helps

import (
	"net/url"
	"strings"
)

// OfficialDeepSeekBase accepts only literal official inference bases. Parsing
// grants no transport permission and performs no DNS lookup or network I/O.
func OfficialDeepSeekBase(base string) bool {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		(u.Host != "api.deepseek.com" && u.Host != "api.deepseek.com:443") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(base, "#") {
		return false
	}
	return u.Path == "" || u.Path == "/" || u.Path == "/v1" || u.Path == "/v1/"
}
