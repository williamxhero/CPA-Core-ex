package management

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	a := &coreauth.Auth{Provider: "qwen", SourcePluginID: "cpa-credential-qwen", ResourceIdentity: &resource.Binding{Targets: []resource.Target{{ResourceID: "test-resource", IdentityVersion: 1, CredentialVersion: 2, ConfigVersion: 3, MembershipVersion: 4}}}}
	if !h.qwenCLIConfigured(nil, a) {
		t.Fatal("explicit Coding Plan CLI configuration was not accepted")
	}
	cfg = testConfigForQwenCLI(t, "      command-args: [--source, bl, --bl-path, C:/bl.cmd]\n")
	h = NewHandlerWithoutConfigFilePath(cfg, nil)
	if h.qwenCLIConfigured(nil, a) {
		t.Fatal("legacy Token Plan source was accepted as Coding Plan")
	}
	cfg = testConfigForQwenCLI(t, "      quota-resource-bindings: [{resource-id: test-resource, identity-version: 9, credential-version: 2, config-version: 3, membership-version: 4}]\n      command-args: [--source, coding-plan, --protocol, qwen-coding-plan-v1, --bl-path, C:/bl.cmd, --cache-file, C:/quota.json]\n")
	h = NewHandlerWithoutConfigFilePath(cfg, nil)
	if h.qwenCLIConfigured(nil, a) {
		t.Fatal("stale identity binding was accepted")
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

func TestQwenCLIObservationAcceptsOneMonthlyCacheWindow(t *testing.T) {
	now := time.Now().UTC()
	binding := resource.Binding{}
	source := resource.QuotaSource{Protocol: "qwen-coding-plan-cli", AccountProvenance: "configured_cli_profile"}
	reset := now.Add(24 * time.Hour).Format(time.RFC3339Nano)
	response := pluginapi.QuotaFetchResponse{Protocol: "qwen-coding-plan-v1", AccountProvenance: "configured_cli_profile", TimestampProvenance: "local_cli_acquisition_time", ObservedAtMS: now.Add(-20 * time.Minute).UnixMilli(), Groups: []pluginapi.QuotaGroup{{Buckets: []pluginapi.QuotaBucket{
		{Window: "billing_month", RemainingFraction: 0.10849978466666672, ResetTime: reset},
	}}}}
	obs := qwenCLIObservation(binding, source, response, true, nil)
	if obs.QueryStatus != "success" || obs.Complete || obs.RecoveryEligible || len(obs.Windows) != 1 || obs.Windows[0].Name != "monthly" {
		t.Fatalf("monthly cache window was not accepted: %+v", obs)
	}
	response.Groups[0].Buckets = append(response.Groups[0].Buckets, pluginapi.QuotaBucket{Window: "5h", RemainingFraction: 1, ResetTime: reset})
	if invented := qwenCLIObservation(binding, source, response, true, nil); invented.QueryStatus == "success" {
		t.Fatalf("a partial extra window was accepted: %+v", invented)
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
	text := fmt.Sprintf("plugins:\n  enabled: true\n  configs:\n    cpa-credential-qwen:\n      enabled: true\n      quota-source: command\n      command: %s\n      quota-resource-bindings: [{resource-id: receipt-resource, identity-version: 1, credential-version: 2, config-version: 3, membership-version: 4}]\n      command-args: [--source, coding-plan, --protocol, qwen-coding-plan-v1, --bl-path, %s, --cache-file, %s]\n", filepath.ToSlash(cache), filepath.ToSlash(cache), filepath.ToSlash(cache))
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithoutConfigFilePath(cfg, nil)
	a := &coreauth.Auth{Provider: "qwen", SourcePluginID: "cpa-credential-qwen", ResourceIdentity: &resource.Binding{Targets: []resource.Target{{ResourceID: "receipt-resource", IdentityVersion: 1, CredentialVersion: 2, ConfigVersion: 3, MembershipVersion: 4}}}}
	stamp, _ := time.Parse(time.RFC3339Nano, observed)
	response := pluginapi.QuotaFetchResponse{ObservedAtMS: stamp.UnixMilli(), Protocol: "qwen-coding-plan-v1", AccountProvenance: "configured_cli_profile", TimestampProvenance: "local_cli_acquisition_time", Groups: []pluginapi.QuotaGroup{{Buckets: []pluginapi.QuotaBucket{{Window: "5h", RemainingFraction: .8, ResetTime: reset}, {Window: "week", RemainingFraction: .7, ResetTime: reset}, {Window: "billing_month", RemainingFraction: .6, ResetTime: reset}}}}}
	if !h.qwenCLIReceiptValid(a, response) {
		t.Fatal("matching cache receipt was rejected")
	}
	for _, tc := range []struct {
		name                   string
		cacheSize, receiptSize int
		want                   bool
	}{
		{"cache_at_limit", 4 << 20, 0, true},
		{"cache_over_limit", (4 << 20) + 1, 0, false},
		{"receipt_at_limit", 0, 16 << 10, true},
		{"receipt_over_limit", 0, (16 << 10) + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paddedCache := append([]byte(nil), cacheBody...)
			if tc.cacheSize > len(paddedCache) {
				paddedCache = append(paddedCache, []byte(strings.Repeat(" ", tc.cacheSize-len(paddedCache)))...)
			}
			digest := sha256.Sum256(paddedCache)
			receiptBody, err := json.Marshal(map[string]any{"version": 1, "state": "success", "observedAt": observed, "cacheSHA256": hex.EncodeToString(digest[:])})
			if err != nil {
				t.Fatal(err)
			}
			if tc.receiptSize > len(receiptBody) {
				receiptBody = append(receiptBody, []byte(strings.Repeat(" ", tc.receiptSize-len(receiptBody)))...)
			}
			if err := os.WriteFile(cache, paddedCache, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cache+".attempt.json", receiptBody, 0600); err != nil {
				t.Fatal(err)
			}
			if got := h.qwenCLIReceiptValid(a, response); got != tc.want {
				t.Fatalf("receipt validation=%v, want %v for cache=%d receipt=%d bytes", got, tc.want, len(paddedCache), len(receiptBody))
			}
		})
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
	enrollment := "      quota-resource-bindings: [{resource-id: test-resource, identity-version: 1, credential-version: 2, config-version: 3, membership-version: 4}]\n"
	if strings.Contains(args, "quota-resource-bindings:") {
		enrollment = ""
	}
	text := "plugins:\n  enabled: true\n  configs:\n    cpa-credential-qwen:\n      enabled: true\n      quota-source: command\n      command: bl.cmd\n" + enrollment + args
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
