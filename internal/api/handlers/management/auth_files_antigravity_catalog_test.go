package management

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestAntigravityOAuthSaveWithResourceCatalog(t *testing.T) {
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
	t.Cleanup(func() {
		if err := h.CloseResourceCatalog(); err != nil {
			t.Error(err)
		}
	})
	if h.resourceCatalog == nil {
		t.Fatal("catalog unavailable")
	}
	// Exercise both direct registration and the deployed synchronous adoption hook.
	for i := 0; i < 3; i++ {
		if i == 1 {
			h.SetPostAuthPersistHook(func(ctx context.Context, auth *coreauth.Auth) error {
				if auth.ResourceIdentity == nil || h.currentRuntimeSource(auth) == nil {
					return errors.New("persisted OAuth source was not bound before adoption")
				}
				return h.upsertAuthRecord(coreauth.WithSkipPersist(ctx), auth)
			})
		}
		state := fmt.Sprintf("antigravity-catalog-save-%d", i)
		RegisterOAuthSession(state, "antigravity")
		t.Cleanup(func() { CancelOAuthSession(state) })
		record := &coreauth.Auth{ID: "antigravity-user@example.test.json", FileName: "antigravity-user@example.test.json", Provider: "antigravity", Metadata: map[string]any{"type": "antigravity", "email": "user@example.test", "project_id": "selected-project", "access_token": fmt.Sprintf("access-%d", i), "refresh_token": "refresh"}}
		path, ok := h.commitAndCompleteBuiltinOAuthSession(context.Background(), state, "antigravity", "", record, "Failed to save token to file", false)
		if !ok {
			t.Fatalf("OAuth reported save failure on attempt %d; credential file may already exist", i)
		}
		raw, errRead := os.ReadFile(path)
		if errRead != nil {
			t.Fatal(errRead)
		}
		var saved map[string]any
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if saved["resource_id"] == nil {
			t.Fatal("OAuth file was saved without catalog enrollment")
		}
		if current, found := manager.GetByID(record.ID); !found || h.currentRuntimeSource(current) == nil {
			t.Fatal("saved OAuth credential has no current runtime binding")
		}
	}
}

func TestAntigravityOAuthPartialSaveReportsRuntimeFailure(t *testing.T) {
	h := NewHandler(&config.Config{AuthDir: t.TempDir()}, "", nil)
	h.SetPostAuthPersistHook(func(context.Context, *coreauth.Auth) error {
		return errors.New("runtime adoption unavailable")
	})
	state := "antigravity-partial-save"
	RegisterOAuthSession(state, "antigravity")
	t.Cleanup(func() { CancelOAuthSession(state) })
	record := &coreauth.Auth{ID: "antigravity-partial.json", FileName: "antigravity-partial.json", Provider: "antigravity", Metadata: map[string]any{"type": "antigravity", "access_token": "test-access", "refresh_token": "test-refresh"}}
	path, ok := h.commitAndCompleteBuiltinOAuthSession(context.Background(), state, "antigravity", "", record, "Failed to save token to file", false)
	if !ok || path == "" {
		t.Fatal("persisted credential was misreported as a file save failure")
	}
	session, found := oauthSessions.Get(state)
	if !found || !session.Saved || session.Adopted || session.AdoptError == "" {
		t.Fatal("partial persistence outcome was not recorded")
	}
}
