package auth

import (
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type schedulingRequirements struct {
	tools, image, reasoning bool
}

const schedulingRequirementsMetadata = "_cpa_scheduling_requirements"

func (m *Manager) scheduleRequestOptions(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if _, ok := opts.Metadata[schedulingRequirementsMetadata]; ok {
		return opts
	}
	r := schedulingRequirements{}
	r.readPayload(req.Payload)
	r.readPayload(opts.OriginalRequest)
	// Selection may use a different public alias than the execution model.
	r.reasoning = r.reasoning || thinking.ParseSuffix(req.Model).HasSuffix
	opts.Metadata = cloneRequestMetadata(opts.Metadata)
	opts.Metadata[schedulingRequirementsMetadata] = r
	return opts
}

func (r *schedulingRequirements) readPayload(raw []byte) {
	if len(raw) == 0 {
		return
	}
	checkPart := func(p ojson.Result) {
		switch p.Get("type").String() {
		case "image", "image_url", "input_image":
			r.image = true
		case "tool_use", "tool_result", "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output":
			r.tools = true
		}
		if strings.HasPrefix(p.Get("inlineData.mimeType").String(), "image/") ||
			strings.HasPrefix(p.Get("fileData.mimeType").String(), "image/") ||
			strings.HasPrefix(p.Get("inline_data.mime_type").String(), "image/") {
			r.image = true
		}
		r.tools = r.tools || p.Get("functionCall").Exists() || p.Get("functionResponse").Exists()
	}
	r.tools = r.tools || len(ojson.GetBytes(raw, "tools").Array()) > 0 || len(ojson.GetBytes(raw, "functions").Array()) > 0
	for _, key := range []string{"messages", "input", "contents"} {
		for _, value := range ojson.GetBytes(raw, key).Array() {
			checkPart(value)
			r.tools = r.tools || len(value.Get("tool_calls").Array()) > 0 || value.Get("role").String() == "tool" || value.Get("function_call").Exists()
			for _, parts := range []string{"content", "parts"} {
				for _, part := range value.Get(parts).Array() {
					checkPart(part)
				}
			}
		}
	}
	for _, path := range []string{"reasoning.effort", "reasoning_effort", "thinking.type", "generationConfig.thinkingConfig", "thinking_level"} {
		v := ojson.GetBytes(raw, path)
		if v.Exists() && v.String() != "" && v.String() != "none" && v.String() != "disabled" {
			r.reasoning = true
		}
	}
}

func knownSchedulingFormat(a *Auth) sdktranslator.Format {
	if isConfiguredOpenAICompatAuth(a) || a.Provider == "kimi" {
		return sdktranslator.FormatOpenAI
	}
	switch a.Provider {
	case "codex":
		return sdktranslator.FormatCodex
	case "claude":
		return sdktranslator.FormatClaude
	case "gemini", "gemini-cli", "gemini-vertex", "vertex", "aistudio":
		return sdktranslator.FormatGemini
	case "antigravity":
		return sdktranslator.FormatAntigravity
	case "interactions":
		return sdktranslator.FormatInteractions
	default:
		return ""
	}
}

func schedulingProtocolReasons(a *Auth, opts cliproxyexecutor.Options) []string {
	to, from := knownSchedulingFormat(a), opts.SourceFormat
	// Other executors retain their own protocol validation; no translation
	// matrix is inferred from a plugin name.
	if from == "" || to == "" {
		return nil
	}
	if from != to && !sdktranslator.HasRequestTransformer(from, to) {
		return []string{"protocol_incompatible"}
	}
	target := cliproxyexecutor.ResponseFormatOrSource(opts)
	if to == target {
		return nil
	}
	// The translation registry keys response transforms by the direction of
	// the corresponding request transform, i.e. client schema -> upstream.
	if opts.Stream {
		if !sdktranslator.HasStreamResponseTransformer(target, to) {
			return []string{"streaming_incompatible"}
		}
	} else if !sdktranslator.HasNonStreamResponseTransformer(target, to) {
		return []string{"protocol_incompatible"}
	}
	return nil
}

func schedulingModelInfo(infos []*registry.ModelInfo, model string) *registry.ModelInfo {
	key := canonicalModelLookupKey(model)
	for _, info := range infos {
		if info != nil && canonicalModelLookupKey(info.ID) == key {
			return info
		}
	}
	return nil
}

func (r schedulingRequirements) unsupported(info *registry.ModelInfo, opts cliproxyexecutor.Options) []string {
	if info == nil {
		return nil
	}
	contains := func(values []string, choices ...string) bool {
		for _, value := range values {
			for _, choice := range choices {
				if strings.EqualFold(value, choice) {
					return true
				}
			}
		}
		return false
	}
	var reasons []string
	if r.tools && info.SupportedParameters != nil &&
		!contains(info.SupportedParameters, "tools", "tool_choice", "functions", "function_call", "function_calling") {
		reasons = append(reasons, "tools_incompatible")
	}
	if r.image && (info.SupportedInputModalities != nil || info.ExplicitInputModalities) && !contains(info.SupportedInputModalities, "image", "vision") {
		reasons = append(reasons, "image_incompatible")
	}
	if r.reasoning && info.Thinking == nil && (info.ExplicitThinking || info.SupportedParameters != nil &&
		!contains(info.SupportedParameters, "reasoning", "reasoning_effort", "thinking")) {
		reasons = append(reasons, "reasoning_incompatible")
	}
	if opts.Stream && len(info.SupportedGenerationMethods) > 0 && opts.SourceFormat == sdktranslator.FormatGemini &&
		!contains(info.SupportedGenerationMethods, "streamGenerateContent", "generateContent") {
		reasons = append(reasons, "streaming_incompatible")
	}
	return reasons
}

func (m *Manager) scheduledModelCapabilityReasons(a *Auth, model string, opts cliproxyexecutor.Options, infos []*registry.ModelInfo) []string {
	req, _ := opts.Metadata[schedulingRequirementsMetadata].(schedulingRequirements)
	candidates, _, _, routing := m.executionModelCandidatesWithAliasOrdered(a, model, false)
	publicInfo := schedulingModelInfo(infos, model)
	if publicInfo == nil {
		publicInfo = schedulingModelInfo(infos, m.selectionModelForAuth(a, model))
	}
	reasons := req.unsupported(publicInfo, opts)
	for _, upstream := range candidates {
		info, _ := lookupAPIKeyModelCapability(routing, a, model, upstream)
		if info == nil {
			info = schedulingModelInfo(infos, upstream)
		}
		for _, reason := range req.unsupported(info, opts) {
			seen := false
			for _, v := range reasons {
				seen = seen || v == reason
			}
			if !seen {
				reasons = append(reasons, reason)
			}
		}
	}
	return reasons
}
