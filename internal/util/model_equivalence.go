package util

import "strings"

// modelEquivalenceGroups lists interchangeable bare model IDs. Clients may
// request any member; routing resolves to whichever member is currently
// registered by a live provider (OpenCode Go, Qwen, etc.).
var modelEquivalenceGroups = [][]string{
	{"deepseek-v4.1-flash", "deepseek-v4.1-flash-1017"},
}

// StripContextBracket removes a trailing "[...]" context-window marker
// (for example "[1m]") from a model ID. Thinking suffixes like "(high)"
// must already have been stripped by the caller.
func StripContextBracket(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	i := strings.IndexByte(model, '[')
	if i <= 0 || !strings.HasSuffix(model, "]") {
		return model
	}
	return model[:i]
}

// ContextBracket returns the trailing "[...]" marker when present.
func ContextBracket(model string) string {
	model = strings.TrimSpace(model)
	i := strings.IndexByte(model, '[')
	if i <= 0 || !strings.HasSuffix(model, "]") {
		return ""
	}
	return model[i:]
}

func equivalencePeers(bare string) []string {
	bare = strings.TrimSpace(bare)
	if bare == "" {
		return nil
	}
	for _, group := range modelEquivalenceGroups {
		for _, member := range group {
			if strings.EqualFold(member, bare) {
				out := make([]string, 0, len(group))
				for _, peer := range group {
					out = append(out, peer)
				}
				return out
			}
		}
	}
	return []string{bare}
}

// EquivalentModelCandidates returns lookup IDs to try for a bare model name
// (no thinking suffix). Exact ID first, then bracket-stripped form, then
// equivalence peers and their bracketed variants when the request carried a
// context marker.
func EquivalentModelCandidates(model string) []string {
	model = strings.TrimSpace(model)
	if model == "" {
		return nil
	}
	bracket := ContextBracket(model)
	bare := StripContextBracket(model)

	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		key := strings.ToLower(id)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, id)
	}

	add(model)
	add(bare)
	for _, peer := range equivalencePeers(bare) {
		add(peer)
		if bracket != "" {
			add(peer + bracket)
		}
	}
	return out
}

// ResolveRegisteredModel finds a registered equivalent for a bare model ID
// (no thinking suffix). It returns the registered ID and its providers.
// When nothing is registered, providers is nil and resolved is the input.
func ResolveRegisteredModel(model string) (resolved string, providers []string) {
	model = strings.TrimSpace(model)
	if model == "" {
		return "", nil
	}
	for _, candidate := range EquivalentModelCandidates(model) {
		providers = GetProviderName(candidate)
		if len(providers) > 0 {
			return candidate, providers
		}
		if lower := strings.ToLower(candidate); lower != candidate {
			providers = GetProviderName(lower)
			if len(providers) > 0 {
				return candidate, providers
			}
		}
	}
	return model, nil
}
