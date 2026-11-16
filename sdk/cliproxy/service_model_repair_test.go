package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestNeedsModelRegistrationRepair(t *testing.T) {
	active := &coreauth.Auth{ID: "auth-1", Provider: "plugin-provider", Status: coreauth.StatusActive}
	disabled := &coreauth.Auth{ID: "auth-2", Provider: "plugin-provider", Disabled: true}
	statusDisabled := &coreauth.Auth{ID: "auth-3", Provider: "plugin-provider", Status: coreauth.StatusDisabled}

	tests := []struct {
		name                 string
		auth                 *coreauth.Auth
		pluginModelProvider  bool
		registeredModelCount int
		want                 bool
	}{
		{name: "missing models", auth: active, pluginModelProvider: true, registeredModelCount: 0, want: true},
		{name: "models registered", auth: active, pluginModelProvider: true, registeredModelCount: 9, want: false},
		{name: "native provider", auth: active, pluginModelProvider: false, registeredModelCount: 0, want: false},
		{name: "disabled flag", auth: disabled, pluginModelProvider: true, registeredModelCount: 0, want: false},
		{name: "disabled status", auth: statusDisabled, pluginModelProvider: true, registeredModelCount: 0, want: false},
		{name: "nil auth", auth: nil, pluginModelProvider: true, registeredModelCount: 0, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsModelRegistrationRepair(tt.auth, tt.pluginModelProvider, tt.registeredModelCount); got != tt.want {
				t.Fatalf("needsModelRegistrationRepair() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthsMissingModelRegistrations(t *testing.T) {
	oldHasModelProvider := pluginHostHasAuthModelProvider
	pluginHostHasAuthModelProvider = func(host *pluginhost.Host, provider string) bool {
		return provider == "plugin-provider"
	}
	t.Cleanup(func() { pluginHostHasAuthModelProvider = oldHasModelProvider })

	manager := coreauth.NewManager(nil, nil, nil)
	registeredID := "model-repair-registered"
	missingID := "model-repair-missing"
	disabledID := "model-repair-disabled"
	for _, auth := range []*coreauth.Auth{
		{ID: registeredID, Provider: "plugin-provider", Status: coreauth.StatusActive},
		{ID: missingID, Provider: "plugin-provider", Status: coreauth.StatusActive},
		{ID: disabledID, Provider: "plugin-provider", Status: coreauth.StatusDisabled},
		{ID: "model-repair-native", Provider: "codex", Status: coreauth.StatusActive},
	} {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatalf("register auth %s: %v", auth.ID, errRegister)
		}
	}
	GlobalModelRegistry().RegisterClient(registeredID, "plugin-provider", []*ModelInfo{{ID: "deepseek-v4.1-flash"}})
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(registeredID)
		GlobalModelRegistry().UnregisterClient(missingID)
		GlobalModelRegistry().UnregisterClient(disabledID)
	})

	service := &Service{coreManager: manager, pluginHost: pluginhost.New()}
	missing := service.authsMissingModelRegistrations()
	if len(missing) != 1 || missing[0].ID != missingID {
		t.Fatalf("authsMissingModelRegistrations() = %v, want only %s", authIDs(missing), missingID)
	}
}

func authIDs(auths []*coreauth.Auth) []string {
	ids := make([]string, 0, len(auths))
	for _, auth := range auths {
		if auth != nil {
			ids = append(ids, auth.ID)
		}
	}
	return ids
}

func TestHasConfiguredOpenAICompatProvider(t *testing.T) {
	service := &Service{cfg: &config.Config{OpenAICompatibility: []config.OpenAICompatibility{
		{Name: "native-provider", BaseURL: "https://native.example.com/v1"},
		{Name: "disabled-provider", BaseURL: "https://disabled.example.com/v1", Disabled: true},
	}}}
	tests := []struct {
		providerKey string
		want        bool
	}{
		{providerKey: "native-provider", want: true},
		{providerKey: "disabled-provider", want: false},
		{providerKey: "opencode-go", want: false},
	}
	for _, tt := range tests {
		if got := service.hasConfiguredOpenAICompatProvider(tt.providerKey, service.cfg); got != tt.want {
			t.Fatalf("hasConfiguredOpenAICompatProvider(%q) = %v, want %v", tt.providerKey, got, tt.want)
		}
	}
}

func TestRegisterExecutorForAuthKeepsPluginOwnedProvider(t *testing.T) {
	oldHasExecutorCandidate := pluginHostHasExecutorCandidateProvider
	pluginHostHasExecutorCandidateProvider = func(host *pluginhost.Host, provider string) bool {
		return provider == "plugin-provider"
	}
	t.Cleanup(func() { pluginHostHasExecutorCandidateProvider = oldHasExecutorCandidate })

	manager := coreauth.NewManager(nil, nil, nil)
	service := &Service{
		cfg:         &config.Config{},
		coreManager: manager,
		pluginHost:  pluginhost.New(),
	}
	pluginAuth := &coreauth.Auth{
		ID:         "plugin-auth",
		Provider:   "plugin-provider",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"base_url": "https://plugin.example.com/v1"},
	}
	service.registerExecutorForAuth(pluginAuth, true)
	if executor, ok := manager.Executor("plugin-provider"); ok && executor != nil {
		t.Fatalf("plugin-owned provider got native executor %T; plugin executor must win", executor)
	}

	// A previously installed native compat executor must be removed instead of
	// silently taking over requests from the plugin.
	manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor("plugin-provider", service.cfg))
	service.registerExecutorForAuth(pluginAuth, true)
	if executor, ok := manager.Executor("plugin-provider"); ok && executor != nil {
		t.Fatalf("native compat executor for plugin-owned provider was not removed: %T", executor)
	}

	// An explicit native OpenAI-compat provider declaration still wins.
	service.cfg = &config.Config{OpenAICompatibility: []config.OpenAICompatibility{
		{Name: "plugin-provider", BaseURL: "https://native.example.com/v1"},
	}}
	service.registerExecutorForAuth(pluginAuth, true)
	if _, ok := manager.Executor("plugin-provider"); !ok {
		t.Fatal("configured native OpenAI-compat provider must still register its executor")
	}
}
