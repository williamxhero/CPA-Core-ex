package management

import (
	"errors"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

var errNativeFundingOwnership = errors.New("native_funding_owns_auto_hold")

// Decode the persisted management document without hashing passwords or
// performing I/O unrelated to this one configuration authority field.
func readFundingConfig(raw []byte) (*config.Config, error) {
	var cfg config.Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	cfg.SanitizeOpenAICompatibility()
	return &cfg, nil
}

func nativeFundingBytesGuard(before, after []byte) error {
	old, err := readFundingConfig(before)
	if err != nil {
		return err
	}
	next, err := readFundingConfig(after)
	if err != nil {
		return err
	}
	if changesNativeFundingMarker(old, next) {
		return errNativeFundingOwnership
	}
	return nil
}

// A legacy handler may update its in-memory list before calling the common
// saver. Restore the existing list on rejection; that request must not leak
// to a subsequent write or misleading config read.
func (h *Handler) checkPersistedFundingOwnership() error {
	if h.cfg == nil || h.configFilePath == "" {
		return nil
	}
	raw, err := os.ReadFile(h.configFilePath)
	if err != nil {
		return err
	}
	old, err := readFundingConfig(raw)
	if err != nil {
		return err
	}
	if changesNativeFundingMarker(old, h.cfg) {
		h.cfg.OpenAICompatibility = old.OpenAICompatibility
		return errNativeFundingOwnership
	}
	return nil
}

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
