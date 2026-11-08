package executor

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"strings"
)

// openAICompatModelMode describes the upstream API shape a model expects.
// The table is deliberately data-driven so adding a model does not require
// another routing branch in the executor.
type openAICompatModelMode string

const (
	openAICompatModelModeAuto      openAICompatModelMode = "auto"
	openAICompatModelModeChat      openAICompatModelMode = "chat"
	openAICompatModelModeResponses openAICompatModelMode = "responses"
	openAICompatModelModeImage     openAICompatModelMode = "image"
)

var openAICompatModelModes = map[string]openAICompatModelMode{
	"gpt-6.1-sol":   openAICompatModelModeResponses,
	"gpt-6-astra":   openAICompatModelModeResponses,
	"gpt-6.1-terra": openAICompatModelModeResponses,
	"gpt-image-2.6": openAICompatModelModeImage,
}

func resolveOpenAICompatModelMode(model string) openAICompatModelMode {
	model = strings.TrimSpace(model)
	if mode, ok := openAICompatModelModes[model]; ok {
		return mode
	}
	return openAICompatModelModeAuto
}

func resolveOpenAICompatModelModeForConfig(model string, compat *config.OpenAICompatibility) openAICompatModelMode {
	if compat != nil {
		switch openAICompatModelMode(strings.ToLower(strings.TrimSpace(compat.UpstreamProtocol))) {
		case openAICompatModelModeChat, openAICompatModelModeResponses, openAICompatModelModeImage:
			return openAICompatModelMode(strings.ToLower(strings.TrimSpace(compat.UpstreamProtocol)))
		}
	}
	return resolveOpenAICompatModelMode(model)
}
