package helps

import "strings"

// AppendInferencePath preserves native literal path construction. It deliberately
// does not resolve, normalize or erase tenant/deployment prefixes.
func AppendInferencePath(base, path string) string { return strings.TrimSuffix(base, "/") + path }

// ClaudeMessagesURL preserves the native messages path and beta query exactly.
func ClaudeMessagesURL(base string) string { return base + "/v1/messages?beta=true" }
