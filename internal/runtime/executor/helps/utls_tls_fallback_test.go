package helps

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUtlsChatGPTFallbackReplaysBodyAfterTransientTransportFailure(t *testing.T) {
	var primaryCalls atomic.Int32
	var fallbackCalls atomic.Int32
	primary := utlsClientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		primaryCalls.Add(1)
		payload, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("primary body read: %v", errRead)
		}
		if string(payload) != `{"prompt":"hello"}` {
			t.Fatalf("primary body = %q", payload)
		}
		return nil, io.ErrUnexpectedEOF
	})
	fallback := utlsClientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		fallbackCalls.Add(1)
		payload, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatalf("fallback body read: %v", errRead)
		}
		if string(payload) != `{"prompt":"hello"}` {
			t.Fatalf("fallback body = %q, want original request body", payload)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
	})
	req, errRequest := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(`{"prompt":"hello"}`))
	if errRequest != nil {
		t.Fatal(errRequest)
	}

	roundTripper := &utlsChatGPTFallbackRoundTripper{primary: primary, fallback: fallback}
	resp, errRoundTrip := roundTripper.RoundTrip(req)
	if errRoundTrip != nil {
		t.Fatalf("RoundTrip returned error: %v", errRoundTrip)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("response = %#v, want 200 response", resp)
	}
	_ = resp.Body.Close()
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("calls = primary %d fallback %d, want one each", primaryCalls.Load(), fallbackCalls.Load())
	}
}

func TestUtlsChatGPTFallbackDoesNotReplayWithoutBodyFactory(t *testing.T) {
	var fallbackCalls atomic.Int32
	req, errRequest := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", &oneShotBody{Reader: strings.NewReader("payload")})
	if errRequest != nil {
		t.Fatal(errRequest)
	}
	primary := utlsClientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		_, _ = io.ReadAll(req.Body)
		return nil, io.ErrUnexpectedEOF
	})
	fallback := utlsClientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		fallbackCalls.Add(1)
		return nil, errors.New("must not be called")
	})

	_, errRoundTrip := (&utlsChatGPTFallbackRoundTripper{primary: primary, fallback: fallback}).RoundTrip(req)
	if !errors.Is(errRoundTrip, io.ErrUnexpectedEOF) {
		t.Fatalf("RoundTrip error = %v, want primary error", errRoundTrip)
	}
	if fallbackCalls.Load() != 0 {
		t.Fatalf("fallback calls = %d, want zero", fallbackCalls.Load())
	}
}

func TestUtlsChatGPTFallbackAggregatesBothTransportFailuresSafely(t *testing.T) {
	primaryErr := fmt.Errorf(`utls: TLS handshake: EOF; Authorization: Bearer secret-token: %w`, io.EOF)
	fallbackErr := errors.New(`standard tls: connection reset; cookie=session-secret`)
	primary := utlsClientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, primaryErr
	})
	fallback := utlsClientRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, fallbackErr
	})
	req, errRequest := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/codex/responses", nil)
	if errRequest != nil {
		t.Fatal(errRequest)
	}
	_, errRoundTrip := (&utlsChatGPTFallbackRoundTripper{primary: primary, fallback: fallback}).RoundTrip(req)
	if errRoundTrip == nil {
		t.Fatal("RoundTrip error = nil, want aggregate")
	}
	message := errRoundTrip.Error()
	if !strings.Contains(message, "uTLS: eof") || !strings.Contains(message, "standard TLS: connection_reset") {
		t.Fatalf("aggregate message = %q, want safe path categories", message)
	}
	for _, secret := range []string{"secret-token", "session-secret", "Authorization", "cookie"} {
		if strings.Contains(message, secret) {
			t.Fatalf("aggregate message leaked %q: %q", secret, message)
		}
	}
	if !errors.Is(errRoundTrip, io.EOF) {
		t.Fatal("aggregate did not preserve the primary EOF for retry classification")
	}
}

func TestUtlsChatGPTFallbackSkipsResponseAndCancellation(t *testing.T) {
	tests := []struct {
		name        string
		makeRequest func(t *testing.T) *http.Request
		primaryErr  error
	}{
		{
			name: "response returned with error",
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/codex/responses", nil)
				if err != nil {
					t.Fatal(err)
				}
				return req
			},
			primaryErr: errors.New("connection reset"),
		},
		{
			name: "caller canceled",
			makeRequest: func(t *testing.T) *http.Request {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/backend-api/codex/responses", nil)
				if err != nil {
					t.Fatal(err)
				}
				return req
			},
			primaryErr: io.ErrUnexpectedEOF,
		},
		{
			name: "certificate failure",
			makeRequest: func(t *testing.T) *http.Request {
				req, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/codex/responses", nil)
				if err != nil {
					t.Fatal(err)
				}
				return req
			},
			primaryErr: &url.Error{Op: "Post", URL: "https://chatgpt.com", Err: x509.UnknownAuthorityError{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fallbackCalls atomic.Int32
			primary := utlsClientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if tt.name == "response returned with error" {
					return &http.Response{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader("bad")), Request: req}, tt.primaryErr
				}
				return nil, tt.primaryErr
			})
			fallback := utlsClientRoundTripFunc(func(*http.Request) (*http.Response, error) {
				fallbackCalls.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
			})
			resp, errRoundTrip := (&utlsChatGPTFallbackRoundTripper{primary: primary, fallback: fallback}).RoundTrip(tt.makeRequest(t))
			if fallbackCalls.Load() != 0 {
				t.Fatalf("fallback calls = %d, want zero", fallbackCalls.Load())
			}
			if tt.name == "response returned with error" {
				if resp == nil || !errors.Is(errRoundTrip, tt.primaryErr) {
					t.Fatalf("got response=%v error=%v, want original response and error", resp, errRoundTrip)
				}
			} else if !errors.Is(errRoundTrip, tt.primaryErr) {
				t.Fatalf("error = %v, want %v", errRoundTrip, tt.primaryErr)
			}
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
		})
	}
}

type oneShotBody struct{ io.Reader }

func (b *oneShotBody) Close() error { return nil }
