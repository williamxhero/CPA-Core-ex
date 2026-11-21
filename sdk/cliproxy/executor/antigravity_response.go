package executor

import "time"

// AntigravityResourceExhausted is classified by the live Antigravity HTTP
// adapter, not by the router or by decoding an error from another executor.
type AntigravityResourceExhausted struct {
	Cause       error
	ObservedAt  time.Time
	RetryAt     time.Time
	RetrySource string
}

func (e *AntigravityResourceExhausted) Error() string { return e.Cause.Error() }
func (e *AntigravityResourceExhausted) Unwrap() error { return e.Cause }
