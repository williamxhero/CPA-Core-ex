package responses

import (
	"context"

	openaiclaude "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/openai/claude"
	openairesponses "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/openai/openai/responses"
)

type openAIResponsesToClaudeState struct {
	chatParam   any
	claudeParam any
}

// ConvertOpenAIResponsesResponseToClaude composes the Responses-to-Chat bridge
// with the existing OpenAI Chat-to-Claude response translator. This keeps the
// Responses endpoint usable for Claude clients without duplicating event logic.
func ConvertOpenAIResponsesResponseToClaude(ctx context.Context, model string, originalRequestRawJSON, requestRawJSON, rawJSON []byte, param *any) [][]byte {
	if param == nil {
		return nil
	}
	state, ok := (*param).(*openAIResponsesToClaudeState)
	if !ok || state == nil {
		state = &openAIResponsesToClaudeState{}
		*param = state
	}
	chatChunks := openairesponses.ConvertOpenAIResponsesResponseToOpenAIChatCompletions(
		ctx, model, originalRequestRawJSON, requestRawJSON, rawJSON, &state.chatParam,
	)
	var outputs [][]byte
	for _, chunk := range chatChunks {
		outputs = append(outputs, openaiclaude.ConvertOpenAIResponseToClaude(
			ctx, model, originalRequestRawJSON, requestRawJSON, chunk, &state.claudeParam,
		)...)
	}
	return outputs
}

func ConvertOpenAIResponsesResponseToClaudeNonStream(ctx context.Context, model string, originalRequestRawJSON, requestRawJSON, rawJSON []byte, param *any) []byte {
	chat := openairesponses.ConvertOpenAIResponsesResponseToOpenAIChatCompletionsNonStream(
		ctx, model, originalRequestRawJSON, requestRawJSON, rawJSON, param,
	)
	return openaiclaude.ConvertOpenAIResponseToClaudeNonStream(
		ctx, model, originalRequestRawJSON, requestRawJSON, chat, param,
	)
}
