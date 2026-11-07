package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type upstream499TestError struct{}

func (upstream499TestError) Error() string                { return "context canceled" }
func (upstream499TestError) StatusCode() int              { return clienterror.StatusClientClosedRequest }
func (upstream499TestError) IsUpstreamHTTPResponse() bool { return true }

func TestUpstream499IsRetryableDespiteClientCancellationClass(t *testing.T) {
	err := upstream499TestError{}
	class := clienterror.Classify(err.StatusCode(), err.Error())
	if class != clienterror.FailureClientCanceled {
		t.Fatalf("Classify(499, context canceled) = %v, want client-canceled baseline", class)
	}
	if !isRetryableUpstreamFailure(err, class) {
		t.Fatal("upstream HTTP 499 must remain eligible for provider failover")
	}
	if !isRequestRetryRoundError(err) {
		t.Fatal("upstream HTTP 499 must remain eligible for a retry round")
	}
}

func TestExecuteFallsBackFromTransientOpenAICompat400ToCodexCredential(t *testing.T) {
	model := "gpt-6.1-sol-provider-failover"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(1, 0, 0)

	openAIAuth := &Auth{ID: "openai-api-key", Provider: "openai-compatibility", Status: StatusActive, Attributes: map[string]string{"priority": "200"}}
	codexAuth := &Auth{ID: "OAI-WXH", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "100"}}
	for _, auth := range []*Auth{openAIAuth, codexAuth} {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}

	openAIExecutor := &authFallbackExecutor{
		id: "openai-compatibility",
		executeErrors: map[string]error{
			openAIAuth.ID: &Error{
				HTTPStatus: http.StatusBadRequest,
				Message:    "We’re currently experiencing high demand, which may cause temporary errors.",
			},
		},
	}
	codexExecutor := &authFallbackExecutor{id: "codex"}
	manager.RegisterExecutor(openAIExecutor)
	manager.RegisterExecutor(codexExecutor)

	response, err := manager.Execute(context.Background(), []string{"openai-compatibility", "codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute() error = %v, want Codex fallback", err)
	}
	if got := string(response.Payload); got != codexAuth.ID {
		t.Fatalf("response payload = %q, want %q", got, codexAuth.ID)
	}
	if calls := openAIExecutor.ExecuteCalls(); len(calls) != 1 || calls[0] != openAIAuth.ID {
		t.Fatalf("OpenAI compatibility calls = %v, want one failed attempt", calls)
	}
	if calls := codexExecutor.ExecuteCalls(); len(calls) != 1 || calls[0] != codexAuth.ID {
		t.Fatalf("Codex calls = %v, want one fallback attempt", calls)
	}
}

func TestExecuteFallsBackFromUpstream499ContextCanceledToCodexCredential(t *testing.T) {
	model := "gpt-6.1-sol-provider-499-failover"
	manager := NewManager(nil, &FillFirstSelector{}, nil)
	manager.SetRetryConfig(1, 0, 0)

	openAIAuth := &Auth{ID: "openai-api-key-499", Provider: "openai-compatibility", Status: StatusActive, Attributes: map[string]string{"priority": "200"}}
	codexAuth := &Auth{ID: "OAI-WXH-499", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"priority": "100"}}
	for _, auth := range []*Auth{openAIAuth, codexAuth} {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register %s: %v", auth.ID, err)
		}
	}

	openAIExecutor := &authFallbackExecutor{
		id: "openai-compatibility",
		executeErrors: map[string]error{
			openAIAuth.ID: &Error{
				HTTPStatus: 499,
				Message:    "context canceled",
			},
		},
	}
	codexExecutor := &authFallbackExecutor{id: "codex"}
	manager.RegisterExecutor(openAIExecutor)
	manager.RegisterExecutor(codexExecutor)

	response, err := manager.Execute(context.Background(), []string{"openai-compatibility", "codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute() error = %v, want Codex fallback", err)
	}
	if got := string(response.Payload); got != codexAuth.ID {
		t.Fatalf("response payload = %q, want %q", got, codexAuth.ID)
	}
	if calls := openAIExecutor.ExecuteCalls(); len(calls) != 1 || calls[0] != openAIAuth.ID {
		t.Fatalf("OpenAI compatibility calls = %v, want one failed attempt", calls)
	}
	if calls := codexExecutor.ExecuteCalls(); len(calls) != 1 || calls[0] != codexAuth.ID {
		t.Fatalf("Codex calls = %v, want one fallback attempt", calls)
	}
}
