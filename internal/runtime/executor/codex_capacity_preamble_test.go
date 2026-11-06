package executor

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gjson "github.com/MoeForge/moego/ojson"
)

const reportedCapacityError = `{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","headers":{"x-retry-metadata":"NO_MORE_RETRY"},"message":"Our servers are currently overloaded. Please try again later.","param":null},"sequence_number":3}`

func TestCodexCapacityPreamble_NoContentMustNotCommit(t *testing.T) {
	preambles := []string{
		`{"type":"response.output_text.delta","delta":""}`,
		`{"type":"response.reasoning_text.delta","delta":""}`,
		`{"type":"response.reasoning_summary_text.delta","delta":""}`,
		`{"type":"response.function_call_arguments.delta","delta":""}`,
		`{"type":"response.custom_tool_call_input.delta","delta":""}`,
		`{"type":"response.refusal.delta","delta":""}`,
		`{"type":"rate_limits.updated","rate_limits":[]}`,
	}
	for _, preamble := range preambles {
		t.Run(gjson.Get(preamble, "type").String(), func(t *testing.T) {
			for _, transport := range []string{"sse", "websocket"} {
				t.Run(transport, func(t *testing.T) {
					events := []string{codexCreatedEvent, codexInProgressEvent, preamble, reportedCapacityError}
					var resultErr error
					if transport == "sse" {
						server := codexSSEServer(events...)
						defer server.Close()
						req, opts := codexTestRequest()
						result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
						if result != nil {
							drainChunks(result)
							t.Fatal("empty preamble committed downstream stream before capacity rejection")
						}
						resultErr = err
					} else {
						server := codexWebsocketServer(t, events...)
						defer server.Close()
						req, opts := codexWebsocketRequest()
						result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
						if result != nil {
							drainChunks(result)
							t.Fatal("empty preamble committed downstream stream before capacity rejection")
						}
						resultErr = err
					}
					if resultErr == nil {
						t.Fatal("expected retryable capacity rejection")
					}
					status, ok := resultErr.(interface{ StatusCode() int })
					if !ok || status.StatusCode() != http.StatusServiceUnavailable {
						t.Fatalf("capacity status=%v, want503", resultErr)
					}
					if !strings.Contains(resultErr.Error(), "NO_MORE_RETRY") {
						t.Fatalf("upstream error detail lost: %v", resultErr)
					}
				})
			}
		})
	}
}

func TestCodexCapacityPreamble_BareErrorEnvelope(t *testing.T) {
	bare := strings.Replace(reportedCapacityError, `"type":"error",`, "", 1)
	for _, transport := range []string{"sse", "websocket"} {
		t.Run(transport, func(t *testing.T) {
			events := []string{codexCreatedEvent, codexInProgressEvent, bare}
			if transport == "sse" {
				server := codexSSEServer(events...)
				defer server.Close()
				req, opts := codexTestRequest()
				result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
				if result != nil {
					drainChunks(result)
					t.Fatal("bare capacity envelope leaked downstream")
				}
				if err == nil || !strings.Contains(err.Error(), "server_is_overloaded") {
					t.Fatalf("expected capacity error, got %v", err)
				}
			} else {
				server := codexWebsocketServer(t, events...)
				defer server.Close()
				req, opts := codexWebsocketRequest()
				result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
				if result != nil {
					drainChunks(result)
					t.Fatal("bare capacity envelope leaked downstream")
				}
				if err == nil || !strings.Contains(err.Error(), "server_is_overloaded") {
					t.Fatalf("expected capacity error, got %v", err)
				}
			}
		})
	}
}

func TestCodexCapacityPreamble_OnlyKnownEmptyStringDeltasAreBufferable(t *testing.T) {
	for _, payload := range []string{
		`{"type":"response.output_text.delta","delta":" "}`,
		`{"type":"response.function_call_arguments.delta","delta":"{"}`,
		`{"type":"response.custom_tool_call_input.delta","delta":"run"}`,
		`{"type":"response.output_text.delta","delta":{"text":"hidden"}}`,
		`{"type":"response.output_text.delta","delta":null}`,
		`{"type":"response.output_text.delta"}`,
		`{"type":"response.shell_call_command.delta","delta":""}`,
		`{"type":"response.shell_call_output_content.delta","delta":{}}`,
		`{"type":"response.unknown.delta","delta":""}`,
	} {
		if isCodexBootstrapBufferableEvent(gjson.Get(payload, "type").String(), []byte(payload)) {
			t.Errorf("unsafe replay boundary: %s", payload)
		}
	}
	// A nested error on an otherwise typed event is not an untyped error envelope.
	if _, ok := codexTerminalFailureBody([]byte(`{"type":"response.some_future_event","error":{"code":"server_is_overloaded"}}`)); ok {
		t.Fatal("typed event was incorrectly reclassified as bare error")
	}
}
