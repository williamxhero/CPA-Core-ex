package resourcecatalog

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// refreshAuthorityDisagrees is a NEGATIVE fence only. Equality or missing
// claims never certifies continuity; a trusted native invocation is mandatory.
func refreshAuthorityDisagrees(before, after *sourceFile) bool {
	for _, key := range []string{"type", "provider", "account_id", "organization_id", "workspace_id", "project_id", "tenant_id", "client_id", "base_url", "proxy_url"} {
		if scalar(before.root, key) != scalar(after.root, key) {
			return true
		}
	}
	beforeType, afterType := scalar(before.root, "token_type"), scalar(after.root, "token_type")
	if beforeType == "" {
		beforeType = "Bearer"
	}
	if afterType == "" {
		afterType = "Bearer"
	}
	if !strings.EqualFold(beforeType, afterType) {
		return true
	}
	if !reflect.DeepEqual(refreshStableConfig(before), refreshStableConfig(after)) {
		return true
	}
	oldClaims, newClaims := explicitRefreshClaims(scalar(before.root, "id_token")), explicitRefreshClaims(scalar(after.root, "id_token"))
	for key, old := range oldClaims {
		if current, explicit := newClaims[key]; explicit && !reflect.DeepEqual(old, current) {
			return true
		}
	}
	return false
}

func explicitRefreshClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var all map[string]any
	if json.Unmarshal(raw, &all) != nil {
		return nil
	}
	result := map[string]any{}
	for _, key := range []string{"iss", "sub", "aud", "tenant_id"} {
		if v, ok := all[key]; ok {
			result[key] = v
		}
	}
	if auth, ok := all["https://api.openai.com/auth"].(map[string]any); ok {
		for _, key := range []string{"chatgpt_account_id", "chatgpt_user_id", "user_id", "organization_id", "project_id", "organizations"} {
			if v, ok := auth[key]; ok {
				result["openai:"+key] = v
			}
		}
	}
	return result
}

// Catalog versions intentionally rotate with native credential bytes, including
// incarnation/configVersion. Compare the explicit non-token authority projection
// above instead; membership and issued slot still must remain unchanged.
func sameRefreshAuthority(before, after resource.Target) bool {
	return before.ResourceID == after.ResourceID && before.MembershipVersion == after.MembershipVersion
}
func refreshStableConfig(f *sourceFile) map[string]any {
	values := nodeValue(f.root, map[string]bool{"resource_id": true, "id_token": true, "access_token": true, "refresh_token": true, "expired": true, "expires_at": true, "expire": true, "expiresAt": true, "expiry": true, "expires": true, "expires_in": true, "last_refresh": true, "email": true, "plan_type": true, "token_type": true})
	if _, ok := values["disabled"]; !ok {
		values["disabled"] = false
	}
	return values
}
