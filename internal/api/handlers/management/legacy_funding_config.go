package management

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func nativeFundingConflict(c *gin.Context) {
	c.JSON(409, gin.H{"error": "native_funding_owns_auto_hold"})
}

// A missing historical marker in a whole-list document is also a mutation.
// Use the issued ID whenever available; pre-enrollment legacy clients may send
// no marker, in which case same name is an additional fail-closed match only.
func changesNativeFundingMarker(old, next *config.Config) bool {
	if old == nil || next == nil {
		return false
	}
	for _, updated := range next.OpenAICompatibility {
		matched := false
		for _, current := range old.OpenAICompatibility {
			if updated.ResourceID != "" && current.ResourceID != "" {
				if updated.ResourceID != current.ResourceID {
					continue
				}
			} else if !strings.EqualFold(strings.TrimSpace(updated.Name), strings.TrimSpace(current.Name)) {
				continue
			}
			if matched {
				return true
			}
			matched = true
			if (old.NativeFundingAdapter(&current) != "" || next.NativeFundingAdapter(&updated) != "") && current.AutoHeld != updated.AutoHeld {
				return true
			}
		}
		if !matched && updated.AutoHeld && next.NativeFundingAdapter(&updated) != "" {
			return true
		}
	}
	return false
}
