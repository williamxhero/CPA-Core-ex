package responses

import (
	. "github.com/router-for-me/CLIProxyAPI/v8/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	openai_claude "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/openai/claude"
	openai_responses "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/openai/openai/responses"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/translator/translator"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func init() {
	translator.Register(
		Claude,
		OpenaiResponse,
		ConvertClaudeRequestToOpenAIResponses,
		interfaces.TranslateResponse{
			Stream:    ConvertOpenAIResponsesResponseToClaude,
			NonStream: ConvertOpenAIResponsesResponseToClaudeNonStream,
		},
	)
	translator.Register(
		OpenaiResponse,
		Claude,
		nil,
		interfaces.TranslateResponse{
			Stream:    ConvertClaudeResponseToOpenAIResponses,
			NonStream: ConvertClaudeResponseToOpenAIResponsesNonStream,
		},
	)
	// The envelope form receives the request context, which carries the
	// upstream.claude.tool-search value the executor pinned for the request.
	sdktranslator.RegisterRequestEnvelope(
		sdktranslator.FormatOpenAIResponse,
		sdktranslator.FormatClaude,
		ConvertOpenAIResponsesRequestEnvelopeToClaude,
	)
}

// ConvertClaudeRequestToOpenAIResponses composes the existing Claude-to-Chat
// translator with the Chat-to-Responses bridge. OpenAI compatibility providers
// may select the Responses endpoint for a model, so leaving a Claude request
// in its messages shape would send an invalid payload to /responses.
func ConvertClaudeRequestToOpenAIResponses(modelName string, inputRawJSON []byte, stream bool) ([]byte, error) {
	chatPayload, errConvert := openai_claude.ConvertClaudeRequestToOpenAI(modelName, inputRawJSON, stream)
	if errConvert != nil {
		return nil, errConvert
	}
	return openai_responses.ConvertOpenAIChatCompletionsRequestToOpenAIResponses(modelName, chatPayload, stream)
}

// ConvertClaudeRequestToOpenAIResponsesWithCompat preserves the compatibility
// behavior used by configured OpenAI API-key models while applying the same
// final Chat-to-Responses conversion.
func ConvertClaudeRequestToOpenAIResponsesWithCompat(modelName string, inputRawJSON []byte, stream bool) ([]byte, error) {
	chatPayload, errConvert := openai_claude.ConvertClaudeRequestToOpenAIWithCompat(modelName, inputRawJSON, stream)
	if errConvert != nil {
		return nil, errConvert
	}
	return openai_responses.ConvertOpenAIChatCompletionsRequestToOpenAIResponses(modelName, chatPayload, stream)
}
