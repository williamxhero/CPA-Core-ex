package management

import (
	"errors"
	"io"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/providerkeymatch"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ProviderKeyMatch is an admin-only local read. It consumes a complete issued
// provider routing proof but makes only a selected runtime-key equality claim.
func (h *Handler) ProviderKeyMatch(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, providerkeymatch.MaxBytes)
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_query"})
		return
	}
	q, err := providerkeymatch.Decode(raw)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_query"})
		return
	}
	a, e, status := h.providerKeyMatchCurrent(c, q)
	if status != 0 {
		providerKeyMatchError(c, status)
		return
	}
	matched, supported := e.ProviderKeyMatch(a, q)
	if !supported {
		providerKeyMatchError(c, 422)
		return
	}
	// Close over the complete group, actual Binding, source and native executor
	// again before issuing either a positive or a negative credential receipt.
	current, executor, status := h.providerKeyMatchCurrent(c, q)
	if status != 0 {
		providerKeyMatchError(c, status)
		return
	}
	closingMatch, closingSupport := executor.ProviderKeyMatch(current, q)
	if current.ID != a.ID || executor != e || !closingSupport || closingMatch != matched {
		providerKeyMatchError(c, 409)
		return
	}
	c.JSON(200, providerkeymatch.Response{Binding: q.Binding, Version: 1,
		SourceVersion: q.SourceVersion, AuthIndex: q.AuthIndex, Adapter: q.Adapter,
		Nonce: q.Nonce, Authority: "runtime_key_match_only", Matched: matched})
}

func providerKeyMatchError(c *gin.Context, status int) {
	code := "gate_unavailable"
	if status == 409 {
		code = "gate_conflict"
	} else if status == 422 {
		code = "key_match_unsupported"
	}
	c.JSON(status, gin.H{"error": code})
}

func (h *Handler) providerKeyMatchCurrent(c *gin.Context, q providerkeymatch.Request) (*coreauth.Auth, *runtimeexecutor.OpenAICompatExecutor, int) {
	view, err := h.currentProviderGate(c.Request.Context(), q.Binding)
	if err != nil {
		if errors.Is(err, resourcecatalog.ErrConflict) {
			return nil, nil, 409
		}
		return nil, nil, 503
	}
	// Require the exact issued parent-first proof, not just an equivalent set.
	if !reflect.DeepEqual(view.Binding, q.Binding) || view.SourceVersion != q.SourceVersion {
		return nil, nil, 409
	}
	if !view.Ready || !view.Supported {
		return nil, nil, 503
	}
	var selected *coreauth.Auth
	for _, member := range view.Members {
		a := h.authByIndex(member.AuthIndex)
		if a == nil {
			return nil, nil, 409
		}
		// A copied Binding is not source provenance. Force the current catalog
		// binder to issue this runtime credential's Binding from scratch.
		a = a.Clone()
		a.ResourceIdentity = nil
		a = h.currentRuntimeSource(a)
		if a == nil || a.Index != member.AuthIndex || !reflect.DeepEqual(*a.ResourceIdentity, member.Binding) || h.quotaSource(c.Request.Context(), a).SourceVersion != member.SourceVersion {
			return nil, nil, 409
		}
		if a.Index == q.AuthIndex {
			selected = a
		}
	}
	if selected == nil {
		return nil, nil, 409
	}
	executor, ok := h.authManager.Executor(selected.Provider)
	if !ok {
		return nil, nil, 503
	}
	e, native := executor.(*runtimeexecutor.OpenAICompatExecutor)
	if !native || selected.SourcePluginID != "" {
		return nil, nil, 422
	}
	return selected, e, 0
}
