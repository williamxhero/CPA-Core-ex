package responses

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
)

type chatBridgeStreamState struct {
	ID       string
	Model    string
	ToolName map[int]string
	ToolID   map[int]string
	ToolOrd  map[int]int
	NextTool int
}

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
		if v.Get("type").String() == "function" && v.Get("function.name").String() != "" {
			choice := ojson.NewDocString(`{"type":"function","name":""}`)
			_ = choice.Set("name", v.Get("function.name").String())
			_ = out.SetRawBytes("tool_choice", choice.Bytes())
		} else {
			_ = out.SetRaw("tool_choice", v.Raw)
		}
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
			instruction := m.Get("content").String()
			if prior := out.Get("instructions").String(); prior != "" {
				instruction = prior + "\n" + instruction
			}
			_ = out.Set("instructions", instruction)
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
			parts := make([]json.RawMessage, 0, len(content.Array()))
			for _, part := range content.Array() {
				p := ojson.NewDoc([]byte(part.Raw))
				switch p.Get("type").String() {
				case "text":
					_ = p.Set("type", "input_text")
				case "image_url":
					_ = p.Set("type", "input_image")
					if u := p.Get("image_url.url"); u.Exists() {
						_ = p.Set("image_url", u.String())
					}
				}
				parts = append(parts, json.RawMessage(p.Bytes()))
			}
			if len(parts) > 0 {
				b, _ := json.Marshal(parts)
				_ = item.SetRawBytes("content", b)
			} else {
				_ = item.SetRaw("content", content.Raw)
			}
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
	toolCalls := make([]json.RawMessage, 0)
	for _, item := range root.Get("output").Array() {
		if item.Get("type").String() != "function_call" && item.Get("type").String() != "custom_tool_call" {
			continue
		}
		call := ojson.NewDocString(`{"id":"","type":"function","function":{"name":"","arguments":""}}`)
		_ = call.Set("id", item.Get("call_id").String())
		_ = call.Set("function.name", item.Get("name").String())
		args := item.Get("arguments").String()
		if args == "" {
			args = item.Get("input").String()
		}
		_ = call.Set("function.arguments", args)
		toolCalls = append(toolCalls, json.RawMessage(call.Bytes()))
	}
	if len(toolCalls) > 0 {
		b, _ := json.Marshal(toolCalls)
		_ = out.SetRawBytes("choices.0.message.tool_calls", b)
		_ = out.Set("choices.0.finish_reason", "tool_calls")
	}
	if v := root.Get("output.0.summary.0.text"); v.Exists() {
		_ = out.Set("choices.0.message.reasoning_content", v.String())
	}
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
	if *param == nil {
		*param = &chatBridgeStreamState{Model: model, ToolName: map[int]string{}, ToolID: map[int]string{}, ToolOrd: map[int]int{}}
	}
	state, _ := (*param).(*chatBridgeStreamState)
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
	if typ == "response.output_item.added" {
		item := root.Get("item")
		if item.Get("type").String() == "function_call" || item.Get("type").String() == "custom_tool_call" {
			ix := int(root.Get("output_index").Int())
			state.ToolName[ix] = item.Get("name").String()
			state.ToolID[ix] = item.Get("call_id").String()
			if _, ok := state.ToolOrd[ix]; !ok {
				state.ToolOrd[ix] = state.NextTool
				state.NextTool++
			}
			out := ojson.NewDocString(`{"id":"","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"","type":"function","function":{"name":"","arguments":""}}]},"finish_reason":null}]}`)
			_ = out.Set("id", root.Get("response_id").String())
			_ = out.Set("model", model)
			_ = out.Set("choices.0.delta.tool_calls.0.id", state.ToolID[ix])
			_ = out.Set("choices.0.delta.tool_calls.0.function.name", state.ToolName[ix])
			_ = out.Set("choices.0.delta.tool_calls.0.index", state.ToolOrd[ix])
			return [][]byte{[]byte("data: " + string(out.Bytes()) + "\n\n")}
		}
	}
	if typ == "response.function_call_arguments.delta" || typ == "response.custom_tool_call_input.delta" {
		ix := int(root.Get("output_index").Int())
		out := ojson.NewDocString(`{"id":"","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":""}}]},"finish_reason":null}]}`)
		_ = out.Set("id", root.Get("response_id").String())
		_ = out.Set("model", model)
		if _, ok := state.ToolOrd[ix]; !ok {
			state.ToolOrd[ix] = state.NextTool
			state.NextTool++
		}
		_ = out.Set("choices.0.delta.tool_calls.0.index", state.ToolOrd[ix])
		_ = out.Set("choices.0.delta.tool_calls.0.function.arguments", root.Get("delta").String())
		return [][]byte{[]byte("data: " + string(out.Bytes()) + "\n\n")}
	}
	if typ == "response.completed" || typ == "response.failed" {
		if typ == "response.failed" {
			return [][]byte{[]byte("data: {\"error\":{\"message\":\"upstream Responses request failed\",\"type\":\"upstream_error\"}}\n\n")}
		}
		out := ojson.NewDocString(`{"id":"","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)
		_ = out.Set("id", root.Get("response.id").String())
		_ = out.Set("model", model)
		return [][]byte{[]byte("data: " + string(out.Bytes()) + "\n\n"), []byte("data: [DONE]\n\n")}
	}
	return nil
}
