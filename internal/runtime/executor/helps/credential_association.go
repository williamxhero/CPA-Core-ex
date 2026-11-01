package helps

import (
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// AssociationCandidateAllowed rejects unproven credential kinds and custom
// routing/auth headers. Native executors still resolve their own effective key;
// this guard never extracts or substitutes a credential.
func AssociationCandidateAllowed(a *coreauth.Auth) bool {
	if a == nil || a.SourcePluginID != "" || a.Attributes["api_key"] == "" {
		return false
	}
	for k := range a.Attributes {
		if strings.HasPrefix(strings.ToLower(k), "header:") {
			return false
		}
	}
	return true
}

// MatchCredentialAssociation validates the literal native business URL and
// compares this one envelope without network, session or payload side effects.
// The caller must supply its actual executor-resolved key and constructed URL.
func MatchCredentialAssociation(key, actual, path string, q credentialassociation.Request) (bool, string) {
	u, err := url.Parse(actual)
	if err != nil || u.Path != path || u.RawPath != "" || u.RawQuery != "" && !(path == "/v1/messages" && u.RawQuery == "beta=true") || u.ForceQuery || strings.ContainsAny(key, "\r\n") || key == "" {
		return false, "association_unsupported"
	}
	u.RawQuery = ""
	origin, ok := credentialassociation.HTTPSOrigin(u.String())
	if !ok {
		return false, "association_unsupported"
	}
	if origin != q.Origin {
		return false, "origin_mismatch"
	}
	if !credentialassociation.Matches(q, key) {
		return false, "credential_mismatch"
	}
	return true, "selected_credential_association"
}
