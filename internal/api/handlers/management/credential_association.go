package management

import (
	"io"
	"net/http"
	"net/url"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// CredentialAssociation is an authenticated, bounded read, not a quota query or
// a gate mutation. It cannot attest Manager's local job, intent or secret CAS.
func (h *Handler) CredentialAssociation(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, credentialassociation.MaxBytes)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_association"})
		return
	}
	q, err := credentialassociation.Decode(raw)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_association"})
		return
	}
	a, group, status := h.associationCurrent(c, q)
	if status != 0 {
		associationError(c, status)
		return
	}
	associated, reason := false, "source_group_mismatch"
	if group {
		reason = "association_unsupported"
		if associationTokenContract(q) {
			officialOrigin, _ := credentialassociation.HTTPSOrigin(q.Official.Endpoint)
			if officialOrigin != q.Origin {
				reason = "origin_mismatch"
			} else if e, ok := h.authManager.Executor(a.Provider); ok {
				associated, reason = nativeCredentialAssociation(e, a, q)
			}
		}
	}
	result, err := credentialassociation.Result(q, associated, reason)
	if err != nil {
		associationError(c, 503)
		return
	}
	// A proof is linearized only after re-resolving current runtime credentials,
	// full source binding, official closure, descriptor AND registered executor.
	// No lock is held across an upstream response; this operation sends none.
	current, currentGroup, status := h.associationCurrent(c, q)
	if status != 0 {
		associationError(c, status)
		return
	}
	if currentGroup != group {
		associationError(c, 409)
		return
	}
	if associated {
		e, ok := h.authManager.Executor(current.Provider)
		if !ok {
			associationError(c, 503)
			return
		}
		if match, why := nativeCredentialAssociation(e, current, q); !match || why != reason {
			associationError(c, 409)
			return
		}
	}
	c.JSON(200, result)
}
func associationError(c *gin.Context, status int) {
	code := "association_unavailable"
	if status == 409 {
		code = "association_conflict"
	}
	c.JSON(status, gin.H{"error": code})
}
func associationTokenContract(q credentialassociation.Request) bool {
	cfg := q.Official
	if cfg.Adapter != "newapi-token-usage-v1" || cfg.NewAPI == nil || !cfg.NewAPI.ProtocolConfirmed || cfg.NewAPI.InstanceVersion == "" || cfg.NewAPI.Auth != "inference-key-readonly-v1" || cfg.NewAPI.UserID != "" {
		return false
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Path != "/api/usage/token/" {
		return false
	}
	_, ok := credentialassociation.HTTPSOrigin(cfg.Endpoint)
	return ok
}
func (h *Handler) associationCurrent(c *gin.Context, q credentialassociation.Request) (*coreauth.Auth, bool, int) {
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		return nil, false, 503
	}
	a, ok := h.selectedQuota(resource.QuotaQuery{Binding: q.Selected, AuthIndex: q.AuthIndex})
	if !ok || h.quotaSource(c.Request.Context(), a).SourceVersion != q.SourceVersion {
		return nil, false, 409
	}
	snapshot, err := h.resourceCatalog.Snapshot()
	if err != nil || !snapshot.Complete {
		return nil, false, 503
	}
	if snapshot.Version != q.Selected.Scope || snapshot.Version != q.Official.Scope {
		return nil, false, 409
	}
	rows := map[string]resource.Row{}
	for _, r := range snapshot.Resources {
		rows[r.ResourceID] = r
	}
	seen := map[string]bool{}
	seed := q.Official.Targets[0].ResourceID
	providers := 0
	for _, target := range q.Official.Targets {
		row, exists := rows[target.ResourceID]
		if !exists || row.Target != target || row.Identity != "valid" || row.Readiness != "ready" {
			return nil, false, 409
		}
		seen[target.ResourceID] = true
		if row.Kind == "provider" {
			seed = target.ResourceID
			providers++
		}
	}
	if providers > 1 {
		return a, false, 0
	}
	required := map[string]bool{}
	queue := []string{seed}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if required[id] {
			continue
		}
		required[id] = true
		row, exists := rows[id]
		if !exists || !seen[id] {
			return a, false, 0
		}
		for _, related := range row.SourceBindings {
			if r, exists := rows[related.ResourceID]; !exists || !reflect.DeepEqual(r.Target, related) {
				return nil, false, 409
			}
			queue = append(queue, related.ResourceID)
		}
		if row.Kind == "provider" {
			queue = append(queue, row.Members...)
		}
	}
	if len(required) != len(seen) {
		return a, false, 0
	}
	for _, target := range q.Selected.Targets {
		if !required[target.ResourceID] {
			return a, false, 0
		}
	}
	return a, true, 0
}

// nativeAssociationExecutor is a private additive seam, not a plugin SDK promise.
type nativeAssociationExecutor interface {
	CredentialAssociation(*coreauth.Auth, credentialassociation.Request) (bool, string)
}

// Only the actual known native executors may attest this contract. An unknown
// plugin implementing the same structural method does not gain proof authority.
func nativeCredentialAssociation(e coreauth.ProviderExecutor, a *coreauth.Auth, q credentialassociation.Request) (bool, string) {
	switch e.(type) {
	case *runtimeexecutor.CodexExecutor, *runtimeexecutor.CodexAutoExecutor, *runtimeexecutor.ClaudeExecutor, *runtimeexecutor.OpenAICompatExecutor:
		return e.(nativeAssociationExecutor).CredentialAssociation(a, q)
	default:
		return false, "association_unsupported"
	}
}
