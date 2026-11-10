package auth

import (
	"context"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	codexclaude "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/codex/claude"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestExecuteStreamIncompleteBootstrapRetriesInsideCPA(t *testing.T) {
	const model = "incomplete-bootstrap-retry-model"
	const authID = "incomplete-bootstrap-retry-auth"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	_, err := manager.Register(context.Background(), &Auth{ID: authID, Provider: "codex", Status: StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
	attempts := 0
	manager.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", streamFn: func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
		attempts++
		if attempts == 1 {
			return nil, incompleteStreamRequestScopedError{msg: "stream error: stream disconnected before completion: stream closed before response.completed"}
		}
		chunks := make(chan cliproxyexecutor.StreamChunk, 1)
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")}
		close(chunks)
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}})
	stream, err := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatalf("incomplete stream leaked to client after %d attempts: %v", attempts, err)
	}
	var payload strings.Builder
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("incomplete stream leaked to client after %d attempts: %v", attempts, chunk.Err)
		}
		payload.Write(chunk.Payload)
	}
	if attempts != 2 || !strings.Contains(payload.String(), "response.completed") {
		t.Fatalf("attempts=%d payload=%q", attempts, payload.String())
	}
}

func TestExecuteStreamIncompleteClaudeSignatureOnlyReasoningRetries(t *testing.T) {
	testClaudeReasoningStreamRetry(t, false)
}

func TestExecuteStreamIncompleteClaudeVisibleOutputIsNotReplayed(t *testing.T) {
	testClaudeReasoningStreamRetry(t, true)
}

func testClaudeReasoningStreamRetry(t *testing.T, visible bool) {
	t.Helper()
	const model = "incomplete-signature-only-model"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.runtimeConfig.Store(&internalconfig.Config{Codex: internalconfig.CodexConfig{StreamBootstrapTimeout: "5m"}})
	for _, id := range []string{"incomplete-signature-a", "incomplete-signature-b"} {
		if _, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	attempts := 0
	manager.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", streamFn: func(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
		attempts++
		var param any
		events := []string{
			`{"type":"response.created","response":{"id":"discarded","model":"gpt-6.1-sol"}}`,
			`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"synthetic-discarded-signature"}}`,
			`{"type":"response.output_item.done","item":{"type":"reasoning","encrypted_content":"synthetic-discarded-signature-2"}}`,
		}
		if visible {
			events = append(events, `{"type":"response.output_text.delta","delta":"already delivered answer"}`)
		}
		if attempts > 1 {
			events = []string{
				`{"type":"response.created","response":{"id":"recovered","model":"gpt-6.1-sol"}}`,
				`{"type":"response.output_text.delta","delta":"recovered answer"}`,
				`{"type":"response.completed","response":{"status":"completed"}}`,
			}
		}
		var chunks []cliproxyexecutor.StreamChunk
		for _, event := range events {
			for _, payload := range codexclaude.ConvertCodexResponseToClaude(ctx, model, []byte(`{"messages":[]}`), nil, []byte("data: "+event), &param) {
				chunks = append(chunks, cliproxyexecutor.StreamChunk{Payload: payload})
			}
		}
		if attempts == 1 {
			chunks = append(chunks, cliproxyexecutor.StreamChunk{Err: incompleteStreamRequestScopedError{msg: "stream error: stream disconnected before completion: stream closed before response.completed"}})
		}
		out := make(chan cliproxyexecutor.StreamChunk, len(chunks))
		for _, chunk := range chunks {
			out <- chunk
		}
		close(out)
		return &cliproxyexecutor.StreamResult{Chunks: out}, nil
	}})
	stream, err := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	var payload strings.Builder
	var streamErr error
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			streamErr = chunk.Err
		}
		payload.Write(chunk.Payload)
	}
	if visible {
		if streamErr == nil || attempts != 1 || !strings.Contains(payload.String(), "already delivered answer") || strings.Contains(payload.String(), "recovered answer") {
			t.Fatalf("committed output must not be duplicated: attempts=%d error=%v payload=%q", attempts, streamErr, payload.String())
		}
		return
	}
	if streamErr != nil {
		t.Fatalf("signature-only reasoning leaked incomplete stream after %d attempts: %v", attempts, streamErr)
	}
	if attempts != 2 || !strings.Contains(payload.String(), "recovered answer") || strings.Contains(payload.String(), "discarded") {
		t.Fatalf("attempts=%d payload=%q", attempts, payload.String())
	}
}

func TestExecuteStreamIncompleteClaudeHandshakeRetriesInsideCPA(t *testing.T) {
	const model = "incomplete-claude-handshake-model"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.SetUpstreamErrorRetryLimit(-1)
	manager.runtimeConfig.Store(&internalconfig.Config{Codex: internalconfig.CodexConfig{StreamBootstrapTimeout: "5m"}})
	for _, id := range []string{"incomplete-claude-a", "incomplete-claude-b"} {
		if _, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	attempts := 0
	manager.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", streamFn: func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
		attempts++
		chunks := make(chan cliproxyexecutor.StreamChunk, 2)
		if attempts == 1 {
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"discarded\",\"content\":[]}}\n\n")}
			chunks <- cliproxyexecutor.StreamChunk{Err: incompleteStreamRequestScopedError{msg: "stream error: stream disconnected before completion: stream closed before response.completed"}}
		} else {
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"recovered\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")}
		}
		close(chunks)
		return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
	}})
	stream, err := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	var payload strings.Builder
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("incomplete stream leaked to Claude after %d attempts: %v", attempts, chunk.Err)
		}
		payload.Write(chunk.Payload)
	}
	if attempts != 2 || !strings.Contains(payload.String(), "recovered") || strings.Contains(payload.String(), "discarded") {
		t.Fatalf("attempts=%d payload=%q", attempts, payload.String())
	}
}

func TestClaudeStreamOutputCommitBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		commits bool
	}{
		{"message envelope", `{"type":"message_start","message":{"content":[]}}`, false},
		{"empty text block", `{"type":"content_block_start","content_block":{"type":"text","text":""}}`, false},
		{"empty thinking block", `{"type":"content_block_start","content_block":{"type":"thinking","thinking":""}}`, false},
		{"encrypted signature", `{"type":"content_block_delta","delta":{"type":"signature_delta","signature":"synthetic-replay-state"}}`, false},
		{"empty thinking delta", `{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":""}}`, false},
		{"empty text delta", `{"type":"content_block_delta","delta":{"type":"text_delta","text":""}}`, false},
		{"block end", `{"type":"content_block_stop","index":0}`, false},
		{"visible thinking", `{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"visible reasoning"}}`, true},
		{"initial text", `{"type":"content_block_start","content_block":{"type":"text","text":"hello"}}`, true},
		{"text delta", `{"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}`, true},
		{"tool call", `{"type":"content_block_start","content_block":{"type":"tool_use","id":"call_1","name":"run","input":{}}}`, true},
		{"completed empty message", `{"type":"message_stop"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamPayloadCommitsOutput([]byte("data: " + tc.payload + "\n\n")); got != tc.commits {
				t.Fatalf("commits output = %v, want %v", got, tc.commits)
			}
		})
	}
}
