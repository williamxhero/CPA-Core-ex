package resourcecatalog

import (
	"encoding/base64"
	"encoding/json"
	"github.com/MoeForge/moego/ojson"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"testing"
)

func TestGateRefreshContinuityAcrossConfigurationChanges(t *testing.T) {
	c, _, path, _ := publicationFixture(t)
	a := &coreauth.Auth{ID: "synthetic.json", Provider: "codex", Attributes: map[string]string{}}
	bind := func() resource.Binding {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		a.Metadata = ojson.ParseBytes(raw).Value().(map[string]any)
		if err = c.BindAuths(path, raw, []*coreauth.Auth{a}); err != nil || a.ResourceIdentity == nil {
			t.Fatal("binding unavailable", err)
		}
		return resource.Binding{Scope: a.ResourceIdentity.Scope, Targets: append([]resource.Target(nil), a.ResourceIdentity.Targets...)}
	}
	write := func(priority int, token string) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc := ojson.NewDoc(raw)
		if err = doc.Set("priority", priority); err != nil {
			t.Fatal(err)
		}
		if err = doc.Set("access_token", token); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, doc.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := bind()
	write(210, "synthetic-token")
	if err := c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
	grantBefore := bind()
	if grantBefore.Targets[0].ConfigVersion <= before.Targets[0].ConfigVersion || !sameGateLifecycle(before.Targets[0], grantBefore.Targets[0]) {
		t.Fatal("priority edit did not isolate a config-only change")
	}
	if proven, err := c.GateRefreshContinuity(before, grantBefore); err != nil || proven {
		t.Fatal("metadata alone invented a native refresh certificate", err)
	}
	finish, err := c.BeginOwnedAuthSave(path, a)
	if err != nil {
		t.Fatal(err)
	}
	write(210, "synthetic-rotated-token")
	a.Metadata["access_token"] = "synthetic-rotated-token"
	if err = finish(a, &grantBefore, true); err != nil {
		t.Fatal(err)
	}
	after := bind()
	if reflect.DeepEqual(grantBefore.Targets, after.Targets) || len(c.state.Gates.Refreshes) != 1 {
		t.Fatal("native save did not publish an actual credential rotation")
	}
	if proven, err := c.GateRefreshContinuity(before, after); err != nil || !proven {
		t.Fatal("priority edit disconnected the certified native refresh chain", err)
	}
	write(220, "synthetic-rotated-token")
	if err = c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
	after = bind()
	if proven, err := c.GateRefreshContinuity(before, after); err != nil || !proven {
		t.Fatal("post-refresh config edit disconnected continuity", err)
	}
	for _, field := range []string{"identity", "credential", "incarnation", "membership", "future_config"} {
		t.Run(field, func(t *testing.T) {
			invalid := resource.Binding{Scope: before.Scope, Targets: append([]resource.Target(nil), before.Targets...)}
			switch field {
			case "identity":
				invalid.Targets[0].IdentityVersion++
			case "credential":
				invalid.Targets[0].CredentialVersion++
			case "incarnation":
				invalid.Targets[0].Incarnation = "unproven-source"
			case "membership":
				invalid.Targets[0].MembershipVersion++
			case "future_config":
				invalid.Targets[0].ConfigVersion = after.Targets[0].ConfigVersion + 1
			}
			if proven, err := c.GateRefreshContinuity(invalid, after); err != nil || proven {
				t.Fatal("unproven lifecycle/configuration accepted", err)
			}
		})
	}
}

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
