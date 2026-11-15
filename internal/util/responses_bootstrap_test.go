package util

import "testing"

func TestIsResponsesBootstrapEvent(t *testing.T) {
	cases := []struct {
		name    string
		event   string
		payload string
		want    bool
	}{
		{"empty heartbeat", "", ``, true},
		{"created", "response.created", `{"type":"response.created"}`, true},
		{"in progress", "response.in_progress", `{"type":"response.in_progress"}`, true},
		{"keepalive", "keepalive", `{"type":"keepalive"}`, true},
		{"metadata", "response.metadata", `{"type":"response.metadata"}`, true},
		{"empty text delta", "response.output_text.delta", `{"type":"response.output_text.delta","delta":""}`, true},
		{"visible text delta", "response.output_text.delta", `{"type":"response.output_text.delta","delta":"x"}`, false},
		{"reasoning item added", "response.output_item.added", `{"type":"response.output_item.added","item":{"type":"reasoning","summary":[]}}`, true},
		{"reasoning item added encrypted", "response.output_item.added", `{"type":"response.output_item.added","item":{"type":"reasoning","summary":[],"encrypted_content":"sig"}}`, true},
		{"reasoning item added signature summary", "response.output_item.added", `{"type":"response.output_item.added","item":{"type":"reasoning","summary":[{"type":"signature","signature":"sig"}],"content":[]}}`, true},
		{"reasoning item done encrypted", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"reasoning","summary":[],"encrypted_content":"sig"}}`, true},
		{"reasoning item done signature summary", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"reasoning","summary":[{"type":"signature","signature":"sig"}],"content":[]}}`, true},
		{"reasoning item done visible", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"reasoning","summary":[{"type":"summary_text","text":"visible"}]}}`, false},
		{"message item done empty", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"message","content":[]}}`, true},
		{"message item done visible", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"message","content":[{"type":"output_text","text":"visible"}]}}`, false},
		{"function item done empty", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"function_call","arguments":""}}`, true},
		{"function item done arguments", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"function_call","arguments":"{}"}}`, false},
		{"web search item done", "response.output_item.done", `{"type":"response.output_item.done","item":{"type":"web_search_call"}}`, false},
		{"summary part added empty", "response.reasoning_summary_part.added", `{"type":"response.reasoning_summary_part.added","part":{"type":"summary_text","text":""}}`, true},
		{"summary part added signature", "response.reasoning_summary_part.added", `{"type":"response.reasoning_summary_part.added","part":{"type":"signature","signature":"sig"}}`, true},
		{"summary part done empty", "response.reasoning_summary_part.done", `{"type":"response.reasoning_summary_part.done","part":{"type":"summary_text","text":""}}`, true},
		{"summary part done visible", "response.reasoning_summary_part.done", `{"type":"response.reasoning_summary_part.done","part":{"type":"summary_text","text":"visible"}}`, false},
		{"content part done empty", "response.content_part.done", `{"type":"response.content_part.done","part":{"type":"output_text","text":""}}`, true},
		{"content part done visible", "response.content_part.done", `{"type":"response.content_part.done","part":{"type":"output_text","text":"visible"}}`, false},
		{"summary text done empty", "response.reasoning_summary_text.done", `{"type":"response.reasoning_summary_text.done","text":""}`, true},
		{"summary text done visible", "response.reasoning_summary_text.done", `{"type":"response.reasoning_summary_text.done","text":"visible"}`, false},
		{"reasoning text done empty", "response.reasoning_text.done", `{"type":"response.reasoning_text.done","text":""}`, true},
		{"output text done empty", "response.output_text.done", `{"type":"response.output_text.done","text":""}`, true},
		{"unknown event", "response.unknown", `{"type":"response.unknown"}`, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsResponsesBootstrapEvent(tt.event, []byte(tt.payload)); got != tt.want {
				t.Fatalf("IsResponsesBootstrapEvent(%q) = %t, want %t", tt.event, got, tt.want)
			}
		})
	}
}
