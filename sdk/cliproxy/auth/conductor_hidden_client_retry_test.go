package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type hiddenRetryStatusError struct {
	msg    string
	status int
}

func (e hiddenRetryStatusError) Error() string { return e.msg }

func (e hiddenRetryStatusError) StatusCode() int { return e.status }

func TestHiddenCapacityRetryStaysInsideWhenIntervalIsShorterThanCooldown(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	wait := 2 * time.Second
	cause := withTrustedRetryAfter(hiddenRetryStatusError{
		msg:    `{"error":{"message":"Selected model is at capacity. Please try a different model."}}`,
		status: http.StatusBadGateway,
	}, &wait)

	waitGot, retry := manager.shouldRetryAfterErrorWithAttempted(
		context.Background(),
		cliproxyexecutor.Options{},
		cause,
		0,
		nil,
		"gpt-5.1-codex",
		time.Second,
		0,
		10,
		nil,
	)
	if !retry || waitGot != clienterror.HiddenClientRetryGap {
		t.Fatalf("capacity beyond max-retry-interval must stay inside CPA, got wait=%s retry=%t", waitGot, retry)
	}

	_, retry = manager.shouldRetryAfterErrorWithAttempted(
		context.Background(),
		cliproxyexecutor.Options{},
		cause,
		10+clienterror.HiddenClientRetryExtra,
		nil,
		"gpt-5.1-codex",
		time.Second,
		0,
		10,
		nil,
	)
	if retry {
		t.Fatal("hidden capacity retry must stop after the extra budget")
	}
}

func TestOrdinaryUpstreamErrorStillStopsAtMaxRetryInterval(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	wait := 2 * time.Second
	cause := withTrustedRetryAfter(hiddenRetryStatusError{msg: "upstream busy", status: http.StatusBadGateway}, &wait)
	_, retry := manager.shouldRetryAfterErrorWithAttempted(
		context.Background(),
		cliproxyexecutor.Options{},
		cause,
		0,
		nil,
		"gpt-5.1-codex",
		time.Second,
		0,
		10,
		nil,
	)
	if retry {
		t.Fatal("non-capacity error beyond max-retry-interval must still return")
	}
}

type incompleteStreamRequestScopedError struct {
	msg string
}

func (e incompleteStreamRequestScopedError) Error() string { return e.msg }

func (e incompleteStreamRequestScopedError) StatusCode() int { return http.StatusRequestTimeout }

func (incompleteStreamRequestScopedError) IsRequestScoped() bool { return true }

func TestHiddenIncompleteStreamRetryStaysInsideCPA(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cause := incompleteStreamRequestScopedError{
		msg: "stream error: stream disconnected before completion: stream closed before response.completed",
	}
	waitGot, retry := manager.shouldRetryAfterErrorWithAttempted(
		context.Background(),
		cliproxyexecutor.Options{},
		cause,
		0,
		nil,
		"gpt-5.1-codex",
		time.Second,
		0,
		0,
		nil,
	)
	if !retry || waitGot != clienterror.HiddenClientRetryGap {
		t.Fatalf("incomplete stream must stay inside CPA, got wait=%s retry=%t", waitGot, retry)
	}
}
