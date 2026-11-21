package credentialquota

import (
	"math/big"
	"strconv"
	"strings"

	"github.com/MoeForge/moego/regexp"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

var codexPercentDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// ParseCodexUsedPercent validates the wire decimal and determines exhaustion
// before rounding the values that will be displayed. Unknown means the input
// is malformed or outside the bounded quota percentage domain.
func ParseCodexUsedPercent(raw string) (resource.CodexWindowUsage, float64, float64) {
	// Bound the size of integers constructed by Rat, including the power of
	// ten encoded by a short scientific-notation literal.
	if len(raw) > 512 || !codexPercentDecimal.MatchString(raw) {
		return resource.CodexWindowUsageUnknown, 0, 0
	}
	if i := strings.IndexAny(raw, "eE"); i >= 0 {
		exponent, err := strconv.ParseInt(raw[i+1:], 10, 16)
		if err != nil || exponent < -1024 || exponent > 1024 {
			return resource.CodexWindowUsageUnknown, 0, 0
		}
	}

	used, ok := new(big.Rat).SetString(raw)
	if !ok || used.Sign() < 0 {
		return resource.CodexWindowUsageUnknown, 0, 0
	}
	limit := big.NewRat(100, 1)
	switch used.Cmp(limit) {
	case 1:
		return resource.CodexWindowUsageUnknown, 0, 0
	case 0:
		return resource.CodexWindowUsageAtLimit, 100, 0
	default:
		display, _ := used.Float64()
		fraction := new(big.Rat).Sub(limit, used)
		remaining, _ := fraction.Quo(fraction, limit).Float64()
		return resource.CodexWindowUsageBelowLimit, display, remaining
	}
}
