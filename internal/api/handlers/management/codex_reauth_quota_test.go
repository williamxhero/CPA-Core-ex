package management

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexReauthPublishesCurrentQuotaSource(t *testing.T) {
	for _, tc := range []struct {
		name      string
		targeted  bool
		blocked   bool
		ambiguous bool
	}{
		{name: "targeted", targeted: true},
		{name: "targeted_previously_blocked", targeted: true, blocked: true},
		{name: "untargeted_plan_change"},
		{name: "untargeted_multiple_matches", ambiguous: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auth")
			if err := os.MkdirAll(authDir, 0700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, "config.yaml")
			body := fmt.Sprintf("oauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\n", filepath.ToSlash(authDir))
			if err := os.WriteFile(configPath, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.ParseConfigBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			store := &sdkAuth.FileTokenStore{}
			store.SetBaseDir(authDir)
			manager := coreauth.NewManager(store, nil, nil)
			h := NewHandler(cfg, configPath, manager)
			h.tokenStore = store
			t.Cleanup(func() { _ = h.CloseResourceCatalog() })
			if h.resourceCatalog == nil {
				t.Fatal("catalog unavailable")
			}
			h.SetPostAuthPersistHook(func(ctx context.Context, a *coreauth.Auth) error {
				return h.upsertAuthRecord(coreauth.WithSkipPersist(ctx), a)
			})

			const id, account, email = "codex-local-name.json", "fixture-account", "user@example.test"
			record := func(name, accountID, grant, plan string) *coreauth.Auth {
				return &coreauth.Auth{
					ID: name, FileName: name, Provider: "codex",
					Storage:  &codex.CodexTokenStorage{AccessToken: grant, RefreshToken: "refresh-" + grant, AccountID: accountID, Email: email, PlanType: plan},
					Metadata: map[string]any{"email": email, "account_id": accountID, "plan_type": plan},
				}
			}
			old := record(id, account, "old", "prolite")
			old.Metadata["label"] = "custom alias"
			old.Metadata["priority"] = 17
			old.Metadata["excluded_models"] = []string{"excluded-model"}
			old.Metadata["headers"] = map[string]any{"X-Local": "keep"}
			old.Disabled = true
			path, err := h.saveTokenRecord(context.Background(), old)
			if err != nil {
				t.Fatal(err)
			}
			before, _ := manager.GetByID(id)
			before = h.currentRuntimeSource(before)
			if before == nil {
				t.Fatal("initial runtime source missing")
			}
			original := before.ResourceIdentity.Targets[0]

			if tc.blocked {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var file map[string]any
				if err := json.Unmarshal(raw, &file); err != nil {
					t.Fatal(err)
				}
				file["access_token"] = "legacy-unowned"
				if err := codex.WriteJSONFileAtomic(path, file); err != nil {
					t.Fatal(err)
				}
				if err := h.ReconcileResourceInventory(); err != nil {
					t.Fatal(err)
				}
				if h.currentRuntimeSource(before) != nil {
					t.Fatal("unowned replacement was accepted")
				}
			}

			// Even the same email is insufficient to match another account.
			otherAccount := "different-account"
			if tc.ambiguous {
				otherAccount = account
			}
			otherPath, err := h.saveTokenRecord(context.Background(), record("other-local-name.json", otherAccount, "other", "plus"))
			if err != nil {
				t.Fatal(err)
			}
			readFile := func(path string) []byte {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			originalFile, otherFile := string(readFile(path)), string(readFile(otherPath))
			newName := codex.CredentialFileName(email, "pro", "fixture", true)
			run := func(grantAccount, grant string) bool {
				state := "codex-reauth-catalog-" + tc.name + "-" + grant
				RegisterOAuthSession(state, "codex")
				t.Cleanup(func() { CancelOAuthSession(state) })
				if tc.targeted {
					SetOAuthSessionTarget(state, oauthRecoveryTarget{AuthID: id, FileName: id, Path: path, Provider: "codex", AccountID: account, Email: email})
				}
				_, ok := h.commitAndCompleteBuiltinOAuthSession(context.Background(), state, "codex", "", record(newName, grantAccount, grant, "pro"), "failed", true)
				return ok
			}
			if tc.targeted && run("different-account", "mismatch") {
				t.Fatal("wrong account was accepted")
			}
			if run(account, "new") == tc.ambiguous {
				t.Fatal("OAuth should save only when the credential to replace is unambiguous")
			}
			if _, err := os.Stat(filepath.Join(authDir, newName)); !os.IsNotExist(err) {
				t.Fatal("OAuth created a duplicate credential after the plan changed")
			}
			if string(readFile(otherPath)) != otherFile {
				t.Fatal("OAuth modified the other credential")
			}
			if tc.ambiguous {
				if string(readFile(path)) != originalFile {
					t.Fatal("ambiguous OAuth modified an existing credential")
				}
				return
			}
			now, _ := manager.GetByID(id)
			current := h.currentRuntimeSource(now)
			if current == nil {
				t.Fatal("OAuth saved the grant but quota lost its runtime binding")
			}
			if current.ResourceIdentity.Targets[0].ResourceID != original.ResourceID ||
				current.ResourceIdentity.Targets[0].CredentialVersion <= original.CredentialVersion ||
				current.ResourceIdentity.Targets[0].Incarnation == original.Incarnation {
				t.Fatal("reauth must preserve the local slot and fence the old credential generation")
			}
			view, ok := h.quotaSourceBindingsView(context.Background())
			if !ok {
				t.Fatal("quota source inventory unavailable")
			}
			ready := false
			for _, source := range view.Sources {
				if source.AuthIndex == current.Index && source.State == "ready" && source.Protocol == "codex-oauth-wham" {
					ready = true
				}
			}
			if !ready {
				t.Fatal("fresh Codex credential was not published as a ready quota source")
			}

			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var saved map[string]any
			if err := json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			headers, _ := saved["headers"].(map[string]any)
			excluded, _ := saved["excluded_models"].([]any)
			if saved["access_token"] != "new" || saved["refresh_token"] != "refresh-new" || saved["plan_type"] != "pro" ||
				saved["label"] != "custom alias" || saved["priority"] != float64(17) || saved["disabled"] != true ||
				headers["X-Local"] != "keep" || len(excluded) != 1 || excluded[0] != "excluded-model" {
				t.Fatal("new credentials and original local settings did not survive together")
			}
		})
	}
}
