package executor

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/providerkeymatch"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ProviderKeyMatch checks the same credentials used by this native executor.
// The second result is support, not a match; neither result asserts money or
// account identity. Custom headers cannot substitute an unverified actual key.
func (e *OpenAICompatExecutor) ProviderKeyMatch(a *coreauth.Auth, q providerkeymatch.Request) (matched, supported bool) {
	if e == nil || e.cfg != nil && e.cfg.Home.Enabled || !helps.AssociationCandidateAllowed(a) {
		return false, false
	}
	base, key := e.resolveCredentials(a)
	if !helps.OfficialDeepSeekBase(base) || key == "" || strings.ContainsAny(key, "\r\n") {
		return false, false
	}
	return providerkeymatch.Matches(key, q), true
}
