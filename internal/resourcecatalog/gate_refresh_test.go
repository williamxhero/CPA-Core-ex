package resourcecatalog

import (
	"encoding/base64"
	"encoding/json"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestInferenceGateRefreshExplicitAuthorityFences(t *testing.T) {
	file := func(values map[string]any) *sourceFile {
		raw, _ := json.Marshal(values)
		var doc yaml.Node
		yaml.Unmarshal(raw, &doc)
		return &sourceFile{root: doc.Content[0]}
	}
	token := func(sub string) string {
		raw, _ := json.Marshal(map[string]any{"iss": "controlled", "sub": sub})
		return "a." + base64.RawURLEncoding.EncodeToString(raw) + ".b"
	}
	base := map[string]any{"type": "codex", "account_id": "account-a", "id_token": token("principal-a"), "access_token": "OLD"}
	for _, key := range []string{"type", "provider", "account_id", "organization_id", "workspace_id", "project_id", "tenant_id", "client_id", "base_url", "proxy_url", "id_token"} {
		t.Run(key, func(t *testing.T) {
			next := map[string]any{}
			for k, v := range base {
				next[k] = v
			}
			next[key] = "DIFFERENT"
			if key == "id_token" {
				next[key] = token("principal-b")
			}
			if !refreshAuthorityDisagrees(file(base), file(next)) {
				t.Fatal("explicit authority disagreement was not fenced")
			}
		})
	}
	next := map[string]any{}
	for k, v := range base {
		next[k] = v
	}
	next["access_token"] = "ROTATED"
	if refreshAuthorityDisagrees(file(base), file(next)) {
		t.Fatal("token rotation misclassified as account authority disagreement")
	}
	before := resource.Target{ResourceID: "resource", Incarnation: "incarnation", IdentityVersion: 1, CredentialVersion: 1, ConfigVersion: 1, MembershipVersion: 1}
	after := before
	after.CredentialVersion = 2
	if !sameRefreshAuthority(before, after) {
		t.Fatal("credential version cannot rotate")
	}
	after.ConfigVersion++
	if !sameRefreshAuthority(before, after) {
		t.Fatal("catalog version rotation rejected despite explicit authority projection")
	}
	next["excluded_models"] = []string{"different-model"}
	if !refreshAuthorityDisagrees(file(base), file(next)) {
		t.Fatal("explicit config disagreement certified")
	}

	after = before
	after.MembershipVersion++
	if sameRefreshAuthority(before, after) {
		t.Fatal("membership disagreement certified")
	}
}
