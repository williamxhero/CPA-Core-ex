package executor

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/providerkeymatch"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// ProviderKeyMatch checks the same credentials used by this native executor.
// The second result is support, not a match; neither result asserts money or
// account identity. Custom headers cannot substitute an unverified actual key.
func (e *OpenAICompatExecutor) ProviderKeyMatch(a *coreauth.Auth, q providerkeymatch.Request) (matched, supported bool) {
	key, supported := e.officialDeepSeekKey(a)
	return supported && providerkeymatch.Matches(key, q), supported
}

func (e *OpenAICompatExecutor) ProviderFundingKeyMatch(a *coreauth.Auth, q providerkeymatch.Request, reading resource.FundingReading) (matched, supported bool) {
	if q.Adapter == "deepseek" {
		key, supported := e.officialDeepSeekKey(a)
		return supported && providerkeymatch.MatchesFunding(key, q, reading), supported
	}
	if q.Adapter != "deepinfra" || !e.nativeFundingKeyAllowed(a) {
		return false, false
	}
	base, key := e.resolveCredentials(a)
	if (base != "https://api.deepinfra.com/v1/openai" && base != "https://api.deepinfra.com/v1/openai/") || key == "" || strings.ContainsAny(key, "\r\n") {
		return false, false
	}
	return providerkeymatch.MatchesFunding(key, q, reading), true
}

func (e *OpenAICompatExecutor) officialDeepSeekKey(a *coreauth.Auth) (string, bool) {
	if !e.nativeFundingKeyAllowed(a) {
		return "", false
	}
	base, key := e.resolveCredentials(a)
	if !helps.OfficialDeepSeekBase(base) || key == "" || strings.ContainsAny(key, "\r\n") {
		return "", false
	}
	return key, true
}

func (e *OpenAICompatExecutor) nativeFundingKeyAllowed(a *coreauth.Auth) bool {
	return e != nil && (e.cfg == nil || !e.cfg.Home.Enabled) && helps.AssociationCandidateAllowed(a)
}
