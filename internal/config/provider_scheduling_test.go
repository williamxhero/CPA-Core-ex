package config

import (
	"testing"
	"time"
)

func TestProviderSchedulingRollout(t *testing.T) {
	cfg := &Config{}
	if got := cfg.ProviderSchedulingMode("shared", "alice"); got != ProviderSchedulingOff {
		t.Fatalf("default mode = %q", got)
	}
	if got := cfg.ProviderSchedulingWait(); got != 3*time.Second {
		t.Fatalf("default active wait = %s", got)
	}

	defaulted, err := ParseConfigBytes([]byte("config-version: 8\nrouting:\n  provider-scheduling:\n    mode: enforce\n    models: ['shared']\n    callers: ['Alice']\n    max-active-wait: '0s'\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ model, caller, want string }{
		{"shared", "Alice", ProviderSchedulingEnforce},
		{"shared", "alice", ProviderSchedulingOff},
		{"elsewhere", "Alice", ProviderSchedulingOff},
		{"shared", "", ProviderSchedulingOff},
	} {
		if got := defaulted.ProviderSchedulingMode(tc.model, tc.caller); got != tc.want {
			t.Errorf("effective mode for %q/%q = %q; want %q", tc.model, tc.caller, got, tc.want)
		}
	}
	if got := defaulted.ProviderSchedulingWait(); got != 0 {
		t.Errorf("explicit zero waits %s", got)
	}
	defaulted.Routing.ProviderScheduling.Mode = "shadow"
	if got := defaulted.ProviderSchedulingMode("shared", "Alice"); got != ProviderSchedulingShadow {
		t.Errorf("shadow mode = %q", got)
	}
	defaulted.Routing.ProviderScheduling.Mode = "typo"
	if got := defaulted.ProviderSchedulingMode("shared", "Alice"); got != ProviderSchedulingOff {
		t.Errorf("unknown mode = %q", got)
	}
}
