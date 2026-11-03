package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func qwenHTTPPluginConfigs(t *testing.T, f *inventoryHarness) map[string]map[string]any {
	t.Helper()
	var configs map[string]map[string]any
	if err := json.Unmarshal(f.request("config/plugins/configs", http.StatusOK), &configs); err != nil {
		t.Fatal(err)
	}
	return configs
}

func qwenHTTPPutPluginConfigs(t *testing.T, f *inventoryHarness, configs map[string]map[string]any) {
	t.Helper()
	body, err := json.Marshal(configs)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/v8/management/config/plugins/configs", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	rec := httptest.NewRecorder()
	f.server.engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("plugin config save returned %d: %s", rec.Code, rec.Body.String())
	}
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	f.handler.SetConfig(resourceSaveConfig(t, f))
}

func qwenHTTPSourceForIndex(t *testing.T, f *inventoryHarness, authIndex string) resource.QuotaSource {
	t.Helper()
	var view struct {
		Sources []resource.QuotaSource `json:"sources"`
	}
	if err := json.Unmarshal(f.request("credential-quota/sources", http.StatusOK), &view); err != nil {
		t.Fatal(err)
	}
	for _, source := range view.Sources {
		if source.Protocol == "qwen-coding-plan-cli" && (authIndex == "" || source.AuthIndex == authIndex) {
			return source
		}
	}
	t.Fatal("configured Qwen resource missing from the source inventory")
	return resource.QuotaSource{}
}

func TestQwenCLIHTTPEnrollmentPreservesCurrentCredentialGenerations(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	configs := qwenHTTPPluginConfigs(t, f)
	qwen := configs["qwen-cliproxyapi"]
	qwen["quota-source"] = "command"
	qwen["command"] = "synthetic-helper.exe"
	qwen["command-args"] = []string{"--source", "coding-plan", "--protocol", "qwen-coding-plan-v1", "--bl-path", "synthetic-bl.cmd", "--cache-file", "synthetic-cache.json"}
	qwenHTTPPutPluginConfigs(t, f, configs)
	before := qwenHTTPSourceForIndex(t, f, "")
	if before.State != "needs_configuration" || len(before.Targets) == 0 {
		t.Fatalf("unenrolled Qwen source must remain unavailable: %+v", before)
	}
	var enrollments []map[string]any
	for _, target := range before.Targets {
		enrollments = append(enrollments, map[string]any{
			"resource-id":        target.ResourceID,
			"identity-version":   target.IdentityVersion,
			"credential-version": target.CredentialVersion,
			"config-version":     target.ConfigVersion,
			"membership-version": target.MembershipVersion,
		})
	}
	configs = qwenHTTPPluginConfigs(t, f)
	configs["qwen-cliproxyapi"]["quota-resource-bindings"] = enrollments
	qwenHTTPPutPluginConfigs(t, f, configs)
	after := qwenHTTPSourceForIndex(t, f, before.AuthIndex)
	if !reflect.DeepEqual(before.Targets, after.Targets) {
		t.Fatalf("enrollment invalidated the credential generations it enrolls: before=%+v after=%+v", before.Targets, after.Targets)
	}
	if after.State != "ready" || after.AccountProvenance != "configured_cli_profile" || before.SourceVersion == after.SourceVersion {
		t.Fatalf("exact enrollment did not produce a new configured source revision: %+v", after)
	}
}
