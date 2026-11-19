package registry

import "slices"

// AntigravityArgon is the client-facing family name. Antigravity inference uses a tier ID.
const AntigravityArgon = "gemini-4-argon"

var argonLevels = [...]string{"low", "medium", "high"}

// AntigravityArgonCatalog supplements the curated catalog only with tier IDs actually
// returned by this account's discovery response. Prefer real definitions on refresh.
func AntigravityArgonCatalog(models []*ModelInfo, discovered map[string]struct{}) []*ModelInfo {
	var template *ModelInfo
	for _, m := range models {
		if m != nil && m.ID == AntigravityArgon+"-high" {
			template = m
			break
		}
	}
	if template == nil {
		return models
	}
	for _, level := range argonLevels {
		id := AntigravityArgon + "-" + level
		if _, ok := discovered[id]; !ok || slices.ContainsFunc(models, func(m *ModelInfo) bool { return m != nil && m.ID == id }) {
			continue
		}
		m := cloneModelInfo(template)
		m.ID = id
		m.Name = id
		m.DisplayName = "Gemini 4 Argon (" + level + ")"
		m.Description = m.DisplayName
		models = append(models, m)
	}
	return models
}

// WithAntigravityArgonFamily publishes a selectable family only if every advertised
// tier survived per-account discovery and exclusions. Do not turn partial access into entitlement.
func WithAntigravityArgonFamily(models []*ModelInfo) []*ModelInfo {
	var template *ModelInfo
	for _, level := range argonLevels {
		i := slices.IndexFunc(models, func(m *ModelInfo) bool { return m != nil && m.ID == AntigravityArgon+"-"+level })
		if i < 0 {
			return models
		}
		template = models[i]
	}
	if slices.ContainsFunc(models, func(m *ModelInfo) bool { return m != nil && m.ID == AntigravityArgon }) {
		return models
	}
	m := cloneModelInfo(template)
	m.ID = AntigravityArgon
	m.Name = m.ID
	m.DisplayName = "Gemini 4 Argon"
	m.Description = "Gemini 4 Argon with selectable reasoning effort (low, medium, high)"
	return append(models, m)
}
