package responses

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
)

// ConvertOpenAIChatCompletionsRequestToOpenAIResponses keeps the downstream
// Chat Completions contract while sending the equivalent Responses request
// upstream. It intentionally uses a small JSON seam so provider routing does
// not depend on private request structs.
func ConvertOpenAIChatCompletionsRequestToOpenAIResponses(model string, raw []byte, stream bool) ([]byte, error) {
	root := util.ParseGJSONBytesNoCopy(raw)
	out := ojson.NewDocString(`{"model":"","input":[],"stream":false}`)
	_ = out.Set("model", model)
	_ = out.Set("stream", stream)
	if v := root.Get("instructions"); v.Exists() {
		_ = out.Set("instructions", v.String())
	}
	if v := root.Get("reasoning_effort"); v.Exists() && v.String() != "" && v.String() != "none" {
		_ = out.Set("reasoning.effort", v.String())
	}
	if v := root.Get("max_completion_tokens"); v.Exists() {
		_ = out.SetRaw("max_output_tokens", v.Raw)
	} else if v := root.Get("max_tokens"); v.Exists() {
		_ = out.SetRaw("max_output_tokens", v.Raw)
	}
	if v := root.Get("tool_choice"); v.Exists() {
		_ = out.SetRaw("tool_choice", v.Raw)
	}
	if v := root.Get("parallel_tool_calls"); v.Exists() {
		_ = out.SetRaw("parallel_tool_calls", v.Raw)
	}
	if tools := root.Get("tools"); tools.Exists() && tools.IsArray() {
		converted := make([]json.RawMessage, 0, len(tools.Array()))
		allTools := tools.Array()
		deferred := make([]string, 0)
		limit := len(allTools)
		if limit > 120 {
			limit = 120
			for _, t := range allTools[limit:] {
				name := t.Get("function.name").String()
				if name == "" {
					name = t.Get("name").String()
				}
				if name != "" {
					deferred = append(deferred, name)
				}
			}
		}
		for _, t := range allTools[:limit] {
			if t.Get("type").String() != "function" {
				converted = append(converted, json.RawMessage(t.Raw))
				continue
			}
			fn := t.Get("function")
			if !fn.Exists() {
				converted = append(converted, json.RawMessage(t.Raw))
				continue
			}
			d := ojson.NewDocString(`{"type":"function","name":"","description":"","parameters":{}}`)
			_ = d.Set("name", fn.Get("name").String())
			if v := fn.Get("description"); v.Exists() {
				_ = d.Set("description", v.String())
			}
			if v := fn.Get("parameters"); v.Exists() {
				_ = d.SetRaw("parameters", v.Raw)
			}
			converted = append(converted, json.RawMessage(d.Bytes()))
		}
		if len(deferred) > 0 {
			search := ojson.NewDocString(`{"type":"function","name":"tool_search","description":"Search deferred tools by name. Deferred tools: ","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}`)
			_ = search.Set("description", "Search deferred tools by name. Deferred tools: "+strings.Join(deferred, ", "))
			converted = append(converted, json.RawMessage(search.Bytes()))
		}
		b, _ := json.Marshal(converted)
		_ = out.SetRawBytes("tools", b)
	}
	var input []json.RawMessage
	for _, m := range root.Get("messages").Array() {
		role := m.Get("role").String()
		if role == "system" || role == "developer" {
			if out.Get("instructions").String() == "" {
				_ = out.Set("instructions", m.Get("content").String())
			}
			continue
		}
		if role == "tool" {
			item := ojson.NewDocString(`{"type":"function_call_output","call_id":"","output":""}`)
			_ = item.Set("call_id", m.Get("tool_call_id").String())
			_ = item.Set("output", m.Get("content").String())
			input = append(input, json.RawMessage(item.Bytes()))
			continue
		}
		item := ojson.NewDocString(`{"type":"message","role":"user","content":[]}`)
		if role == "assistant" {
			_ = item.Set("role", "assistant")
		}
		content := m.Get("content")
		if content.Type == ojson.String {
			_ = item.SetRawBytes("content", []byte(fmt.Sprintf(`[{"type":"input_text","text":%q}]`, content.String())))
		} else if content.Exists() {
			_ = item.SetRaw("content", content.Raw)
		}
		input = append(input, json.RawMessage(item.Bytes()))
		for _, tc := range m.Get("tool_calls").Array() {
			fn := tc.Get("function")
			call := ojson.NewDocString(`{"type":"function_call","call_id":"","name":"","arguments":""}`)
			_ = call.Set("call_id", tc.Get("id").String())
			_ = call.Set("name", fn.Get("name").String())
			_ = call.Set("arguments", fn.Get("arguments").String())
			input = append(input, json.RawMessage(call.Bytes()))
		}
	}
	b, _ := json.Marshal(input)
	_ = out.SetRawBytes("input", b)
	return out.Bytes(), nil
}

func ConvertOpenAIResponsesResponseToOpenAIChatCompletionsNonStream(_ context.Context, model string, _ []byte, _ []byte, raw []byte, _ *any) []byte {
	root := util.ParseGJSONBytesNoCopy(raw)
	text := root.Get("output.0.content.0.text").String()
	if text == "" {
		text = root.Get("output_text").String()
	}
	out := ojson.NewDocString(`{"id":"","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{}}`)
	_ = out.Set("id", root.Get("id").String())
	_ = out.Set("model", model)
	_ = out.Set("choices.0.message.content", text)
	if v := root.Get("usage.input_tokens"); v.Exists() {
		_ = out.Set("usage.prompt_tokens", v.Int())
	}
	if v := root.Get("usage.output_tokens"); v.Exists() {
		_ = out.Set("usage.completion_tokens", v.Int())
	}
	return out.Bytes()
}

func ConvertOpenAIResponsesResponseToOpenAIChatCompletions(ctx context.Context, model string, original, request, raw []byte, param *any) [][]byte {
	if bytes := strings.TrimSpace(string(raw)); bytes == "" {
		return nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "data:") {
		raw = []byte(strings.TrimSpace(strings.TrimSpace(string(raw))[5:]))
	}
	if string(raw) == "[DONE]" {
		return [][]byte{[]byte("data: [DONE]\n\n")}
	}
	root := util.ParseGJSONBytesNoCopy(raw)
	typ := root.Get("type").String()
	if typ == "response.output_text.delta" {
		out := ojson.NewDocString(`{"id":"","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`)
		_ = out.Set("id", root.Get("response_id").String())
		_ = out.Set("model", model)
		_ = out.Set("choices.0.delta.content", root.Get("delta").String())
		return [][]byte{[]byte("data: " + string(out.Bytes()) + "\n\n")}
	}
	if typ == "response.completed" || typ == "response.failed" {
		out := ojson.NewDocString(`{"id":"","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)
		_ = out.Set("id", root.Get("response.id").String())
		_ = out.Set("model", model)
		return [][]byte{[]byte("data: " + string(out.Bytes()) + "\n\n"), []byte("data: [DONE]\n\n")}
	}
	return nil
}
