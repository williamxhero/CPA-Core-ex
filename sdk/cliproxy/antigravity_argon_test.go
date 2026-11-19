package cliproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestAntigravityArgonDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name, catalog string
		excluded      []string
		want          []string
	}{
		{"all", `{"models":{"gemini-4-argon-low":{},"gemini-4-argon-medium":{},"gemini-4-argon-high":{}}}`, nil, []string{"gemini-4-argon", "gemini-4-argon-low", "gemini-4-argon-medium", "gemini-4-argon-high"}},
		{"low-only", `{"models":{"gemini-4-argon-low":{}}}`, nil, []string{"gemini-4-argon-low"}},
		{"excluded-tier", `{"models":{"gemini-4-argon-low":{},"gemini-4-argon-medium":{},"gemini-4-argon-high":{}}}`, []string{"*-medium"}, []string{"gemini-4-argon-low", "gemini-4-argon-high"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetAntigravityCapabilityCache()
			t.Cleanup(resetAntigravityCapabilityCache)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.catalog)) }))
			defer server.Close()
			manager := coreauth.NewManager(nil, nil, nil)
			svc := &Service{cfg: &config.Config{OAuthExcludedModels: map[string][]string{"antigravity": tc.excluded}}, coreManager: manager}
			a, err := manager.Register(t.Context(), antigravityTestAuth("argon-"+tc.name, server.URL))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(a.ID) })
			svc.registerModelsForAuth(t.Context(), a)
			svc.WaitAntigravityProbes()
			got := GlobalModelRegistry().GetModelsForClient(a.ID)
			if len(got) != len(tc.want) {
				t.Errorf("got %d models, want %v", len(got), tc.want)
			}
			for _, id := range tc.want {
				if !GlobalModelRegistry().ClientSupportsModel(a.ID, id) {
					t.Errorf("model not published: %s", id)
				}
			}
		})
	}
}
