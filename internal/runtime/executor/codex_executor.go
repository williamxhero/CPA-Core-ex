package executor

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// CodexExecutor is a stateless executor for Codex (OpenAI Responses API entrypoint).
// If api_key is unavailable on auth, it falls back to legacy via ClientAdapter.
type CodexExecutor struct {
	cfg *config.Config
}

func NewCodexExecutor(cfg *config.Config) *CodexExecutor { return &CodexExecutor{cfg: cfg} }

func (e *CodexExecutor) Identifier() string { return "codex" }

func (e *CodexExecutor) modelLevelCooling() bool {
	return e != nil && e.cfg != nil && e.cfg.Codex.ModelLevelCooling
}

// SupportsApplyPatch reports the actual executor contract, independent of its provider name.
func (e *CodexExecutor) SupportsApplyPatch() bool { return e != nil }

// CredentialAssociation reads the same configured native credential and literal
// business URL as Execute. It never acquires credentials or changes a payload.
func (e *CodexExecutor) CredentialAssociation(a *cliproxyauth.Auth, q credentialassociation.Request) (bool, string) {
	if e == nil || e.cfg != nil && e.cfg.Home.Enabled || !helps.AssociationCandidateAllowed(a) || codexUseSIWC(a) {
		return false, "association_unsupported"
	}
	key, base := codexCreds(a)
	return helps.MatchCredentialAssociation(key, helps.AppendInferencePath(base, "/responses"), "/v1/responses", q)
}
