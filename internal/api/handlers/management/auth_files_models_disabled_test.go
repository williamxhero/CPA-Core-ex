package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type disabledCatalogProvider struct {
	models []pluginapi.ModelInfo
}

func (disabledCatalogProvider) Identifier() string { return "qwen" }

func (disabledCatalogProvider) ParseAuth(context.Context, pluginapi.AuthParseRequest) (pluginapi.AuthParseResponse, error) {
	return pluginapi.AuthParseResponse{}, nil
}

func (disabledCatalogProvider) StartLogin(context.Context, pluginapi.AuthLoginStartRequest) (pluginapi.AuthLoginStartResponse, error) {
	return pluginapi.AuthLoginStartResponse{}, nil
}

func (disabledCatalogProvider) PollLogin(context.Context, pluginapi.AuthLoginPollRequest) (pluginapi.AuthLoginPollResponse, error) {
	return pluginapi.AuthLoginPollResponse{}, nil
}

func (disabledCatalogProvider) RefreshAuth(context.Context, pluginapi.AuthRefreshRequest) (pluginapi.AuthRefreshResponse, error) {
	return pluginapi.AuthRefreshResponse{}, nil
}

func (disabledCatalogProvider) StaticModels(context.Context, pluginapi.StaticModelRequest) (pluginapi.ModelResponse, error) {
	return pluginapi.ModelResponse{}, nil
}

func (p disabledCatalogProvider) ModelsForAuth(context.Context, pluginapi.AuthModelRequest) (pluginapi.ModelResponse, error) {
	return pluginapi.ModelResponse{Provider: "qwen", Models: p.models}, nil
}

func TestGetAuthFileModelsReturnsCatalogWhenCredentialIsDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fileName := "qwen-disabled.json"
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "qwen",
		Disabled: true,
		Status:   coreauth.StatusDisabled,
		Attributes: map[string]string{
			"excluded_models": "qwen3.7-plus,qwen3.6-*",
		},
	}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("register auth: %v", err)
	}
	registry.GetGlobalRegistry().UnregisterClient(auth.ID)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	host := pluginhost.New()
	host.RegisterPluginForTest("cpa-credential-qwen", pluginapi.Plugin{
		Capabilities: pluginapi.Capabilities{
			AuthProvider: disabledCatalogProvider{},
			ModelProvider: disabledCatalogProvider{models: []pluginapi.ModelInfo{
				{ID: "qwen3.7-plus"},
				{ID: "qwen3.6-plus"},
				{ID: "kimi-k2.5"},
			}},
		},
	})

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.SetPluginHost(host)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/models?name="+fileName, nil)
	h.GetAuthFileModels(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := make([]string, 0, len(resp.Models))
	for _, model := range resp.Models {
		got = append(got, model.ID)
	}
	if len(got) != 1 || got[0] != "kimi-k2.5" {
		t.Fatalf("models = %#v, want [kimi-k2.5]", got)
	}
	if len(registry.GetGlobalRegistry().GetModelsForClient(auth.ID)) != 0 {
		t.Fatal("disabled credential was registered for routing")
	}
}
