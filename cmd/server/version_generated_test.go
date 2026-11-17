package main

import (
	"strconv"
	"strings"
	"testing"
)

// The fork ships {source}+{ex}. Forgetting to re-run
// ops/update-ex-versions.ps1 after a source merge must fail here instead of
// leaking a stale or hand-edited identity.
func TestGeneratedVersionShape(t *testing.T) {
	parts := strings.Split(generatedVersion, "+")
	if len(parts) != 2 {
		t.Fatalf("generatedVersion = %q, want {source}+{ex}", generatedVersion)
	}
	for _, part := range parts {
		if !isSemverTriple(part) {
			t.Fatalf("generatedVersion = %q, part %q is not major.minor.patch", generatedVersion, part)
		}
	}
}

func isSemverTriple(value string) bool {
	segments := strings.Split(value, ".")
	if len(segments) != 3 {
		return false
	}
	for _, segment := range segments {
		if segment == "" || strings.HasPrefix(segment, "-") || (len(segment) > 1 && segment[0] == '0') {
			return false
		}
		if _, err := strconv.Atoi(segment); err != nil {
			return false
		}
	}
	return true
}
