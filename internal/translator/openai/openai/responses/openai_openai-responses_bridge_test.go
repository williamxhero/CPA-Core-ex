package responses

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
)

func TestConvertOpenAIChatCompletionsRequestToOpenAIResponsesPreservesReasoningTools(t *testing.T) {
	raw := []byte(`{"model":"gpt-6.1-sol","messages":[{"role":"system","content":"be concise"},{"role":"user","content":"hello"}],"reasoning_effort":"xhigh","max_tokens":42,"tools":[{"type":"function","function":{"name":"lookup","description":"find","parameters":{"type":"object"}}}],"stream":true}`)
	out, err := ConvertOpenAIChatCompletionsRequestToOpenAIResponses("gpt-6.1-sol", raw, true)
	if err != nil {
		t.Fatal(err)
	}
	root := ojson.NewDoc(out)
	if root.Get("model").String() != "gpt-6.1-sol" || root.Get("instructions").String() != "be concise" || root.Get("reasoning.effort").String() != "xhigh" {
		t.Fatalf("request fields not preserved: %s", out)
	}
	if root.Get("max_output_tokens").Int() != 42 || len(root.Get("tools").Array()) != 1 || root.Get("tools.0.name").String() != "lookup" {
		t.Fatalf("response shape mismatch: %s", out)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestConvertOpenAIChatCompletionsRequestToOpenAIResponsesUsesOutputTextForAssistantHistory(t *testing.T) {
	raw := []byte(`{"model":"gpt-6.1-sol","messages":[{"role":"user","content":"hello"},{"role":"assistant","content":"hi"},{"role":"user","content":[{"type":"text","text":"next"}]}]}`)
	out, err := ConvertOpenAIChatCompletionsRequestToOpenAIResponses("gpt-6.1-sol", raw, false)
	if err != nil {
		t.Fatal(err)
	}
	root := ojson.NewDoc(out)
	if got := root.Get("input.0.content.0.type").String(); got != "input_text" {
		t.Fatalf("user history content type = %q, want input_text: %s", got, out)
	}
	if got := root.Get("input.1.content.0.type").String(); got != "output_text" {
		t.Fatalf("assistant history content type = %q, want output_text: %s", got, out)
	}
	if got := root.Get("input.2.content.0.type").String(); got != "input_text" {
		t.Fatalf("later user content type = %q, want input_text: %s", got, out)
	}
}

func TestConvertOpenAIChatCompletionsRequestToOpenAIResponsesDefersOverflowTools(t *testing.T) {
	tools := make([]map[string]any, 129)
	for i := range tools {
		tools[i] = map[string]any{"type": "function", "function": map[string]any{"name": "tool_" + fmt.Sprint(i), "parameters": map[string]any{"type": "object"}}}
	}
	b, _ := json.Marshal(map[string]any{"model": "gpt-6.1-sol", "messages": []any{map[string]any{"role": "user", "content": "x"}}, "tools": tools})
	out, err := ConvertOpenAIChatCompletionsRequestToOpenAIResponses("gpt-6.1-sol", b, false)
	if err != nil {
		t.Fatal(err)
	}
	root := ojson.NewDoc(out)
	if len(root.Get("tools").Array()) != 121 {
		t.Fatalf("tools=%d want 121", len(root.Get("tools").Array()))
	}
	if !strings.Contains(root.Get("tools.120.description").String(), "tool_128") {
		t.Fatalf("overflow manifest missing: %s", root.Get("tools.120.description").String())
	}
}

func TestConvertOpenAIResponsesToolStreamToChatSSE(t *testing.T) {
	var state any
	added := ConvertOpenAIResponsesResponseToOpenAIChatCompletions(context.Background(), "gpt-6.1-sol", nil, nil, []byte(`{"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call-1","name":"lookup"}}`), &state)
	delta := ConvertOpenAIResponsesResponseToOpenAIChatCompletions(context.Background(), "gpt-6.1-sol", nil, nil, []byte(`{"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"q\":1}"}`), &state)
	completed := ConvertOpenAIResponsesResponseToOpenAIChatCompletions(context.Background(), "gpt-6.1-sol", nil, nil, []byte(`{"type":"response.completed","response":{"id":"resp-1"}}`), &state)
	var joined []byte
	for _, frame := range append(append(added, delta...), completed...) {
		joined = append(joined, frame...)
	}
	text := string(joined)
	if !strings.Contains(text, `"id":"call-1"`) || !strings.Contains(text, `"name":"lookup"`) || !strings.Contains(text, `q`) || !strings.Contains(text, `"finish_reason":"stop"`) {
		t.Fatalf("tool stream was not bridged: %s", text)
	}
}

func TestConvertOpenAIResponsesFailedStreamRemainsError(t *testing.T) {
	var state any
	out := ConvertOpenAIResponsesResponseToOpenAIChatCompletions(context.Background(), "gpt-6.1-sol", nil, nil, []byte(`{"type":"response.failed","response":{"id":"resp-1"}}`), &state)
	if len(out) != 1 || !strings.Contains(string(out[0]), `"error"`) || strings.Contains(string(out[0]), "[DONE]") {
		t.Fatalf("failed Responses event was masked: %q", out)
	}
}
