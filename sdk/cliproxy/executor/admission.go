package executor

import (
	"context"
	"errors"
	"net/http"
)

type inferenceAdmissionKey struct{}

// WithInferenceAdmission installs a host-owned decision for each business send.
// It cannot be supplied through a client header or plugin-owned metadata.
func WithInferenceAdmission(ctx context.Context, check func(context.Context) error) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, inferenceAdmissionKey{}, check)
}

// AdmitInference must be called for each new attempt, including internal retries.
// Its permission expires at that attempt; no socket/request-lifetime permit exists.
func AdmitInference(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	check, _ := ctx.Value(inferenceAdmissionKey{}).(func(context.Context) error)

	if check == nil {
		return nil
	}
	if err := check(ctx); err != nil {
		if tracker, ok := ctx.Value(upstreamAttemptTrackerContextKey{}).(*upstreamAttemptTracker); ok && tracker != nil {
			tracker.admissionDenied.Store(true)
		}
		return &InferenceAdmissionError{}
	}
	return nil
}

type InferenceAdmissionError struct{}

func (*InferenceAdmissionError) Error() string {
	return "inference admission unavailable or restricted"
}
func (*InferenceAdmissionError) StatusCode() int { return http.StatusServiceUnavailable }
func IsInferenceAdmissionError(err error) bool {
	var e *InferenceAdmissionError
	return errors.As(err, &e)
}

type admissionTransport struct{ base http.RoundTripper }

func (t admissionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := AdmitInference(r.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

// GateHTTPClient preserves the selected transport, fingerprints, pools and timeouts.
func GateHTTPClient(ctx context.Context, c *http.Client) *http.Client {
	if ctx == nil || c == nil {
		return c
	}
	check, _ := ctx.Value(inferenceAdmissionKey{}).(func(context.Context) error)

	if check == nil {
		return c
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	clone := *c
	clone.Transport = admissionTransport{base: base}
	return &clone
}

// InferenceAdmissionDenied retains host classification across a plugin RPC error.
func InferenceAdmissionDenied(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	t, ok := ctx.Value(upstreamAttemptTrackerContextKey{}).(*upstreamAttemptTracker)
	return ok && t != nil && t.admissionDenied.Load()
}
