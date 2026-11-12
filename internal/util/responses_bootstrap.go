package util

import (
	"bytes"

	"github.com/MoeForge/moego/ojson"
)

// IsResponsesBootstrapEvent reports whether a frame may be held back before the downstream
// response headers are committed, i.e. whether nothing observable has happened yet.
//
// The list is closed on purpose. "Nothing has happened yet" cannot be derived from the absence of a
// TTFT token: TTFT deliberately ignores server-side tool traffic such as
// response.shell_call_output_content.delta and its .done counterpart, and holding one of those back
// would let a later rejection replay a tool call, and its side effects, on another credential. An
// unrecognised frame therefore releases the stream.
//
// Beyond the handshake preamble the list covers what upstream interleaves before the first token:
// keepalive heartbeats, and the *.added frames that announce an item or part with no content yet.
func IsResponsesBootstrapEvent(eventType string, payload []byte) bool {
	// An empty data: frame is the SSE heartbeat idiom and carries nothing at all, which is how the
	// websocket loop already treats an empty message. Without this it would fall through to the
	// default and release the stream, turning the feature off for any upstream that sends one.
	if len(bytes.TrimSpace(payload)) == 0 {
		return true
	}
	switch eventType {
	// response.metadata carries prompt-moderation flags, not generated output. Upstream now sends it
	// between response.in_progress and a server_is_overloaded rejection, so releasing on it leaked
	// the rejection to the client instead of failing over (issue #6856).
	case "response.created", "response.in_progress", "codex.rate_limits", "codex.response.metadata", "response.metadata", "keepalive", "rate_limits.updated":
		return true
	case "response.output_text.delta", "response.reasoning_text.delta", "response.reasoning_summary_text.delta",
		"response.function_call_arguments.delta", "response.custom_tool_call_input.delta", "response.refusal.delta":
		// Only explicit empty string deltas are safe to retain. Missing, null,
		// structured or non-empty deltas and server-side tool events still commit.
		delta := ojson.GetBytes(payload, "delta")
		return delta.Type == ojson.String && delta.String() == ""
	case "response.output_item.added":
		return isResponsesBufferableOutputItem(payload)
	case "response.output_item.done":
		// Encrypted reasoning alone is replay state, not visible model output.
		return ojson.GetBytesNoCopy(payload, "item.type").String() == "reasoning" && isResponsesBufferableOutputItem(payload)
	case "response.content_part.added":
		return isResponsesEmptyPart(payload)
	case "response.reasoning_summary_part.added":
		return isResponsesEmptyPart(payload)
	default:
		return false
	}
}

// isResponsesBufferableOutputItem reports whether an announced output item is one the model produces by
// itself and has not started producing, so nothing is running upstream yet. The emptiness checks
// cover message and reasoning text and tool arguments. Encrypted reasoning alone
// carries no visible output. Every other item type
// is released, which covers the server-side operations that may already have been dispatched - a
// web_search_call is announced with status "in_progress" and its searching event follows
// immediately, and failing the attempt over after one would run it again on another credential - and
// errs the same way for anything else this list has not been taught about.
func isResponsesBufferableOutputItem(payload []byte) bool {
	item := ojson.GetBytesNoCopy(payload, "item")
	switch item.Get("type").String() {
	case "message":
		return isResponsesEmptyContentList(item.Get("content"))
	case "reasoning":
		return isResponsesReasoningItemEmpty(item)
	case "function_call":
		return item.Get("arguments").String() == ""
	case "custom_tool_call":
		return item.Get("input").String() == ""
	default:
		return false
	}
}

// isResponsesReasoningItemEmpty ignores provider-private signature and replay
// metadata. Only visible text or refusal content commits a Responses stream.
func isResponsesReasoningItemEmpty(item ojson.Result) bool {
	for _, list := range []ojson.Result{item.Get("summary"), item.Get("content")} {
		for _, part := range list.Array() {
			if text := part.Get("text"); text.Type == ojson.String && text.String() != "" {
				return false
			}
			if refusal := part.Get("refusal"); refusal.Type == ojson.String && refusal.String() != "" {
				return false
			}
		}
	}
	return true
}

// isResponsesEmptyContentList reports whether every entry of an item's content or summary array is a
// textual shape this list knows about and is still empty. An entry whose type is not on the list may
// carry content in a field this check cannot see - an output_audio entry keeps it in "audio" - so it
// is treated as already produced.
func isResponsesEmptyContentList(list ojson.Result) bool {
	for _, entry := range list.Array() {
		switch entry.Get("type").String() {
		case "output_text", "summary_text", "text", "reasoning_text":
			if entry.Get("text").String() != "" {
				return false
			}
		case "refusal":
			if entry.Get("refusal").String() != "" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// isResponsesEmptyPart reports whether an announced part is a textual one that is still empty. The part
// type is matched against a closed list for the same reason the event type is: a part shape this
// list has not been taught about may carry content in a field the emptiness check cannot see, so it
// releases the stream instead.
func isResponsesEmptyPart(payload []byte) bool {
	part := ojson.GetBytesNoCopy(payload, "part")
	switch part.Get("type").String() {
	case "output_text", "summary_text", "text", "reasoning_text":
		return part.Get("text").String() == ""
	case "refusal":
		return part.Get("refusal").String() == ""
	default:
		return false
	}
}
