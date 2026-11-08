package executor

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"testing"
)

func TestResolveOpenAICompatModelMode(t *testing.T) {
	tests := map[string]openAICompatModelMode{
		"gpt-6.1-sol":     openAICompatModelModeResponses,
		"gpt-6-astra":     openAICompatModelModeResponses,
		"gpt-6.1-terra":   openAICompatModelModeResponses,
		"gpt-image-2.6":   openAICompatModelModeImage,
		" unknown-model ": openAICompatModelModeAuto,
	}
	for model, want := range tests {
		if got := resolveOpenAICompatModelMode(model); got != want {
			t.Errorf("resolveOpenAICompatModelMode(%q) = %q, want %q", model, got, want)
		}
	}
}

func TestResolveOpenAICompatModelModeForConfigHonorsOverride(t *testing.T) {
	if got := resolveOpenAICompatModelModeForConfig("gpt-6.1-sol", &config.OpenAICompatibility{UpstreamProtocol: "chat"}); got != openAICompatModelModeChat {
		t.Fatalf("override = %q", got)
	}
	if got := resolveOpenAICompatModelModeForConfig("other", &config.OpenAICompatibility{UpstreamProtocol: "responses"}); got != openAICompatModelModeResponses {
		t.Fatalf("responses override = %q", got)
	}
}
