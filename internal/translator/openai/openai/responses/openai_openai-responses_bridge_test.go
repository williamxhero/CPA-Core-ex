package responses

import (
	"encoding/json"
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
