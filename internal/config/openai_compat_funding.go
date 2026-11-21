package config

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/providerkeymatch"
)

// NativeFundingAdapter is the config half of exact host-native funding
// coverage. Headers, empty keys and nonofficial origins stay on legacy rules.
func (c *Config) NativeFundingAdapter(p *OpenAICompatibility) string {
	if c == nil || !c.ResourceCatalog.Enabled || c.Home.Enabled || p == nil ||
		len(p.Headers) != 0 || len(p.APIKeyEntries) == 0 {
		return ""
	}
	for _, entry := range p.APIKeyEntries {
		key := strings.TrimSpace(entry.APIKey)
		if key == "" || strings.ContainsAny(key, "\r\n") {
			return ""
		}
	}
	return providerkeymatch.FundingAdapter(p.BaseURL)
}
