package executor

import (
	"testing"
	"time"
)

func TestCodexPilotFailureKeepsLaterRetryAfter(t *testing.T) {
	short, long := 12*time.Second, 42*time.Second
	tests := []struct {
		name          string
		current, hint *time.Duration
		want          *time.Duration
	}{
		{name: "keeps the constructed delay without a usable hint", current: &long, want: &long},
		{name: "uses the hint when nothing was resolved", hint: &long, want: &long},
		{name: "extends to a later hint", current: &short, hint: &long, want: &long},
		{name: "never shortens the constructed delay", current: &long, hint: &short, want: &long},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := laterRetryAfter(tc.current, tc.hint)
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Fatalf("laterRetryAfter(%v, %v) = %v, want %v", tc.current, tc.hint, got, tc.want)
			}
		})
	}
}
