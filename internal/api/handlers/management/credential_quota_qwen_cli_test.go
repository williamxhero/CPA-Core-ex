package management

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestQwenCLIConfiguredRequiresExplicitCodingPlanCLIConfiguration(t *testing.T) {
	cfg := testConfigForQwenCLI(t, "      command-args: [--source, coding-plan, --protocol, qwen-coding-plan-v1, --bl-path, C:/bl.cmd, --cache-file, C:/quota.json]\n")
	h := NewHandlerWithoutConfigFilePath(cfg, nil)
	a := &coreauth.Auth{Provider: "qwen", SourcePluginID: "qwen-cliproxyapi", ResourceIdentity: &resource.Binding{Targets: []resource.Target{{ResourceID: "test-resource"}}}}
	if !h.qwenCLIConfigured(nil, a) {
		t.Fatal("explicit Coding Plan CLI configuration was not accepted")
	}
	cfg = testConfigForQwenCLI(t, "      command-args: [--source, bl, --bl-path, C:/bl.cmd]\n")
	h = NewHandlerWithoutConfigFilePath(cfg, nil)
	if h.qwenCLIConfigured(nil, a) {
		t.Fatal("legacy Token Plan source was accepted as Coding Plan")
	}
}

func TestQwenCLIObservationPreservesAcquisitionTimeAndRejectsStaleData(t *testing.T) {
	now := time.Now().UTC()
	binding := resource.Binding{}
	source := resource.QuotaSource{Protocol: "qwen-coding-plan-cli", AccountProvenance: "configured_cli_profile"}
	response := pluginapi.QuotaFetchResponse{Protocol: "qwen-coding-plan-v1", AccountProvenance: "configured_cli_profile", TimestampProvenance: "local_cli_acquisition_time", ObservedAtMS: now.Add(-time.Second).UnixMilli(), Groups: []pluginapi.QuotaGroup{{Buckets: []pluginapi.QuotaBucket{
		{Window: "5h", RemainingFraction: .8, ResetTime: now.Add(time.Hour).Format(time.RFC3339Nano)},
		{Window: "week", RemainingFraction: .7, ResetTime: now.Add(2 * time.Hour).Format(time.RFC3339Nano)},
		{Window: "billing_month", RemainingFraction: .6, ResetTime: now.Add(3 * time.Hour).Format(time.RFC3339Nano)},
	}}}}
	obs := qwenCLIObservation(binding, source, response, true, nil)
	if obs.QueryStatus != "success" || !obs.Complete || !obs.RecoveryEligible || obs.ObservedAtMS != response.ObservedAtMS || obs.TimestampProvenance != "local_cli_acquisition_time" {
		t.Fatalf("valid CLI observation was not preserved: %+v", obs)
	}
	response.ObservedAtMS = now.Add(-6 * time.Minute).UnixMilli()
	if stale := qwenCLIObservation(binding, source, response, true, nil); stale.QueryStatus == "success" || stale.RecoveryEligible {
		t.Fatalf("stale CLI observation became policy evidence: %+v", stale)
	}
}

func TestQwenCLIReceiptBindsCurrentCacheAndLatestAttempt(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "quota.json")
	observed := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	reset := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	cacheBody := []byte(fmt.Sprintf(`{"protocol":"qwen-coding-plan-v1","product":"coding-plan","queryStatus":"success","observedAt":%q,"windows":[{"window":"5h","used":"20","total":"100","resetTime":%q},{"window":"week","used":"30","total":"100","resetTime":%q},{"window":"billing_month","used":"40","total":"100","resetTime":%q}]}`, observed, reset, reset, reset))
	if err := os.WriteFile(cache, cacheBody, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cacheBody)
	receipt, _ := json.Marshal(map[string]any{"version": 1, "state": "success", "observedAt": observed, "cacheSHA256": hex.EncodeToString(digest[:])})
	if err := os.WriteFile(cache+".attempt.json", receipt, 0600); err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("plugins:\n  enabled: true\n  configs:\n    qwen-cliproxyapi:\n      enabled: true\n      quota-source: command\n      command: %s\n      quota-resource-ids: [receipt-resource]\n      command-args: [--source, coding-plan, --protocol, qwen-coding-plan-v1, --bl-path, %s, --cache-file, %s]\n", filepath.ToSlash(cache), filepath.ToSlash(cache), filepath.ToSlash(cache))
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithoutConfigFilePath(cfg, nil)
	a := &coreauth.Auth{Provider: "qwen", SourcePluginID: "qwen-cliproxyapi", ResourceIdentity: &resource.Binding{Targets: []resource.Target{{ResourceID: "receipt-resource"}}}}
	stamp, _ := time.Parse(time.RFC3339Nano, observed)
	response := pluginapi.QuotaFetchResponse{ObservedAtMS: stamp.UnixMilli(), Protocol: "qwen-coding-plan-v1", AccountProvenance: "configured_cli_profile", TimestampProvenance: "local_cli_acquisition_time", Groups: []pluginapi.QuotaGroup{{Buckets: []pluginapi.QuotaBucket{{Window: "5h", RemainingFraction: .8, ResetTime: reset}, {Window: "week", RemainingFraction: .7, ResetTime: reset}, {Window: "billing_month", RemainingFraction: .6, ResetTime: reset}}}}}
	if !h.qwenCLIReceiptValid(a, response) {
		t.Fatal("matching cache receipt was rejected")
	}
	if err := os.WriteFile(cache, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if h.qwenCLIReceiptValid(a, response) {
		t.Fatal("changed cache escaped receipt fence")
	}
}

func testConfigForQwenCLI(t *testing.T, args string) *config.Config {
	t.Helper()
	text := "plugins:\n  enabled: true\n  configs:\n    qwen-cliproxyapi:\n      enabled: true\n      quota-source: command\n      command: bl.cmd\n      quota-resource-ids: [test-resource]\n" + args
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
