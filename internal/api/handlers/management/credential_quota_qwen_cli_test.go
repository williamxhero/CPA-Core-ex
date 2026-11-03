package management

import (
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
	a := &coreauth.Auth{Provider: "qwen", SourcePluginID: "qwen-cliproxyapi"}
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

func testConfigForQwenCLI(t *testing.T, args string) *config.Config {
	t.Helper()
	text := "plugins:\n  enabled: true\n  configs:\n    qwen-cliproxyapi:\n      enabled: true\n      quota-source: command\n      command: bl.cmd\n" + args
	cfg, err := config.ParseConfigBytes([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
