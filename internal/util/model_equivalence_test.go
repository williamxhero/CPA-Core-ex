package util

import (
	"reflect"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func TestEquivalentModelCandidatesDeepSeek(t *testing.T) {
	got := EquivalentModelCandidates("deepseek-v4.1-flash-1017[1m]")
	want := []string{
		"deepseek-v4.1-flash-1017[1m]",
		"deepseek-v4.1-flash-1017",
		"deepseek-v4.1-flash",
		"deepseek-v4.1-flash[1m]",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %#v, want %#v", got, want)
	}
}

func TestResolveRegisteredModelMaps1017ToFlash(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-deepseek-equiv-opencode"
	reg.RegisterClient(clientID, "opencode-go", []*registry.ModelInfo{
		{ID: "deepseek-v4.1-flash", Created: time.Now().Unix()},
	})
	t.Cleanup(func() { reg.UnregisterClient(clientID) })

	for _, in := range []string{
		"deepseek-v4.1-flash-1017",
		"deepseek-v4.1-flash-1017[1m]",
		"deepseek-v4.1-flash",
	} {
		got, providers := ResolveRegisteredModel(in)
		if len(providers) == 0 || providers[0] != "opencode-go" {
			t.Fatalf("%s: providers = %#v", in, providers)
		}
		if got != "deepseek-v4.1-flash" {
			t.Fatalf("%s: resolved = %q, want deepseek-v4.1-flash", in, got)
		}
	}
}

func TestResolveRegisteredModelMapsFlashTo1017(t *testing.T) {
	reg := registry.GetGlobalRegistry()
	clientID := "test-deepseek-equiv-qwen"
	reg.RegisterClient(clientID, "qwen", []*registry.ModelInfo{
		{ID: "deepseek-v4.1-flash-1017", Created: time.Now().Unix()},
	})
	t.Cleanup(func() { reg.UnregisterClient(clientID) })

	got, providers := ResolveRegisteredModel("deepseek-v4.1-flash")
	if len(providers) == 0 || providers[0] != "qwen" {
		t.Fatalf("providers = %#v", providers)
	}
	if got != "deepseek-v4.1-flash-1017" {
		t.Fatalf("resolved = %q", got)
	}
}
