package executor

import "testing"

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
