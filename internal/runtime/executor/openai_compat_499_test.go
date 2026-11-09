package executor

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
)

func TestOpenAICompat499IsMarkedAsUpstreamResponse(t *testing.T) {
	err := newOpenAICompatStatusError(clienterror.StatusClientClosedRequest, nil, []byte("context canceled"))
	if !clienterror.IsUpstreamHTTPResponse(err) {
		t.Fatal("OpenAI-compatible HTTP 499 must retain its upstream-response marker")
	}
	if clienterror.IsClientCancellation(clienterror.StatusClientClosedRequest, err) {
		t.Fatal("OpenAI-compatible HTTP 499 must not be classified as downstream cancellation")
	}
}

func TestOpenAICompatQuotaErrorIsCredentialScoped(t *testing.T) {
	err := newOpenAICompatStatusError(400, nil, []byte(`{"error":{"type":"invalid_request_error","code":"insufficient_quota"}}`))
	if !err.IsCredentialScoped() {
		t.Fatal("OpenAI-compatible quota error must be credential scoped")
	}
}
