package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func qwenHTTPPluginConfigs(t *testing.T, f *inventoryHarness) map[string]map[string]any {
	t.Helper()
	var configs map[string]map[string]any
	if err := json.Unmarshal(f.request("config/plugins/configs", http.StatusOK), &configs); err != nil {
		t.Fatal(err)
	}
	return configs
}

// Inject only the external quota producer. Inventory, HTTP authorization,
// source selection and the cache receipt fence remain production code.
type qwenHTTPQuotaProducer struct {
	pluginapi.QuotaProvider
	response pluginapi.QuotaFetchResponse
}

func (p *qwenHTTPQuotaProducer) Identifier() string { return "qwen" }
func (p *qwenHTTPQuotaProducer) FetchQuota(context.Context, pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
	return p.response, nil
}

func TestQwenCLIHTTPRejectsPositiveRoundingOfExhaustedCache(t *testing.T) {
	f, _ := pluginInventoryFixture(t)
	host := pluginhost.New()
	producer := &qwenHTTPQuotaProducer{}
	host.SetAuthManager(f.manager)
	t.Cleanup(host.ShutdownAll)
	cache := filepath.Join(t.TempDir(), "quota.json")
	observed := time.Now().UTC().Add(-time.Second)
	reset := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	cacheBody := []byte(fmt.Sprintf(`{"protocol":"qwen-coding-plan-v1","product":"coding-plan","queryStatus":"success","observedAt":%q,"windows":[{"window":"5h","used":"100","total":"100","resetTime":%q},{"window":"week","used":"30","total":"100","resetTime":%q},{"window":"billing_month","used":"40","total":"100","resetTime":%q}]}`, observed.Format(time.RFC3339Nano), reset, reset, reset))
	if err := os.WriteFile(cache, cacheBody, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(cacheBody)
	receipt, err := json.Marshal(map[string]any{"version": 1, "state": "success", "observedAt": observed.Format(time.RFC3339Nano), "cacheSHA256": hex.EncodeToString(hash[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache+".attempt.json", receipt, 0600); err != nil {
		t.Fatal(err)
	}
	producer.response = pluginapi.QuotaFetchResponse{ObservedAtMS: observed.UnixMilli(), Protocol: "qwen-coding-plan-v1", AccountProvenance: "configured_cli_profile", TimestampProvenance: "local_cli_acquisition_time", Groups: []pluginapi.QuotaGroup{{Buckets: []pluginapi.QuotaBucket{{Window: "5h", RemainingFraction: 0, ResetTime: reset}, {Window: "week", RemainingFraction: .7, ResetTime: reset}, {Window: "billing_month", RemainingFraction: .6, ResetTime: reset}}}}}
	configs := qwenHTTPPluginConfigs(t, f)
	qwen := configs["qwen-cliproxyapi"]
	qwen["quota-source"] = "command"
	qwen["command"] = "synthetic-helper.exe"
	qwen["command-args"] = []string{"--source", "coding-plan", "--protocol", "qwen-coding-plan-v1", "--bl-path", "synthetic-bl.cmd", "--cache-file", cache}
	qwenHTTPPutPluginConfigs(t, f, configs)
	before := qwenHTTPSourceForIndex(t, f, "")
	var enrollments []map[string]any
	for _, target := range before.Targets {
		enrollments = append(enrollments, map[string]any{"resource-id": target.ResourceID, "identity-version": target.IdentityVersion, "credential-version": target.CredentialVersion, "config-version": target.ConfigVersion, "membership-version": target.MembershipVersion})
	}
	configs = qwenHTTPPluginConfigs(t, f)
	configs["qwen-cliproxyapi"]["quota-resource-bindings"] = enrollments
	qwenHTTPPutPluginConfigs(t, f, configs)
	host.RegisterPluginForTest("qwen-cliproxyapi", pluginapi.Plugin{Capabilities: pluginapi.Capabilities{AuthProvider: identityHostProvider{family: "qwen"}, QuotaProvider: producer}})
	f.handler.SetPluginHost(host)
	source := qwenHTTPSourceForIndex(t, f, before.AuthIndex)
	response, handled, fetchErr := host.FetchQuotaByPlugin(context.Background(), "qwen-cliproxyapi", pluginapi.QuotaFetchRequest{AuthIndex: source.AuthIndex, Provider: "qwen"})
	if !handled || fetchErr != nil || response.Protocol != "qwen-coding-plan-v1" {
		t.Fatalf("synthetic quota producer was not invoked: handled=%v err=%v response=%+v", handled, fetchErr, response)
	}
	q := resource.QuotaQuery{Binding: source.Binding, AuthIndex: source.AuthIndex, SourceVersion: source.SourceVersion}
	obs := queryQuota(t, f, q, http.StatusOK)
	if obs.QueryStatus != "success" || obs.RecoveryEligible || len(obs.Windows) != 3 || obs.Windows[0].RemainingFraction != 0 {
		t.Fatalf("original exhausted cache was not preserved: %+v", obs)
	}
	producer.response.Groups[0].Buckets[0].RemainingFraction = 5e-16
	obs = queryQuota(t, f, q, http.StatusOK)
	if obs.QueryStatus == "success" || obs.RecoveryEligible || obs.Complete {
		t.Fatalf("rounded positive balance bypassed the exact exhausted cache: %+v", obs)
	}
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
	// The production file store adds disabled:false on the first successful
	// inference save. This default materialization must not revoke enrollment;
	// a real manual disable must still rotate the configuration generation.
	authPath := filepath.Join(f.authDir, after.SourceID)
	raw, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	var authFile map[string]any
	if err := json.Unmarshal(raw, &authFile); err != nil {
		t.Fatal(err)
	}
	if _, present := authFile["disabled"]; present {
		t.Fatal("fixture must start with the implicit enabled default")
	}
	for _, disabled := range []bool{false, true} {
		authFile["disabled"] = disabled
		body, err := json.Marshal(authFile)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(authPath, body, 0600); err != nil {
			t.Fatal(err)
		}
		if err := f.watcher.ReconcileResourceInventory(); err != nil {
			t.Fatal(err)
		}
		current := qwenHTTPSourceForIndex(t, f, after.AuthIndex)
		if !disabled {
			if !reflect.DeepEqual(after.Targets, current.Targets) || after.SourceVersion != current.SourceVersion || current.State != "ready" {
				t.Fatalf("materializing disabled:false revoked current enrollment: before=%+v after=%+v", after, current)
			}
		} else if reflect.DeepEqual(after.Targets, current.Targets) || current.State == "ready" {
			t.Fatalf("manual disable escaped target-generation fence: %+v", current)
		}
	}
}
