package auth

import (
	"context"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
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
