package management

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	log "github.com/sirupsen/logrus"
)

func (h *Handler) QuotaAutoStop(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	var p resourcecatalog.QuotaAutoStop
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		c.JSON(400, gin.H{"error": "invalid_policy"})
		return
	}
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	if p.Enabled && !h.credentialGateOperationReady(c, resource.GateOperation{Binding: p.Binding, AuthIndex: p.AuthIndex, SourceVersion: p.SourceVersion}) {
		return
	}
	if c.FullPath() == "/v8/management/inference-gates/quota-auto-stop/status" {
		synced, err := h.resourceCatalog.QuotaAutoStopSynced(p)
		if err != nil {
			c.JSON(409, gin.H{"error": "gate_conflict"})
			return
		}
		c.JSON(200, gin.H{"version": 1, "synced": synced})
		return
	}
	err := h.resourceCatalog.SetQuotaAutoStop(p)
	if errors.Is(err, resourcecatalog.ErrConflict) {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	c.JSON(200, p)
}

func (h *Handler) observeQuotaExhaustion(ctx context.Context, a *coreauth.Auth, _ coreauth.Result) {
	if h.resourceCatalog == nil {
		return
	}
	current := h.currentRuntimeSource(a)
	if current == nil {
		return
	}
	src := h.quotaSource(ctx, current)
	if err := h.resourceCatalog.ObserveQuotaExhaustion(*current.ResourceIdentity, current.Index, src.SourceVersion); err != nil {
		log.Warn("automatic quota stop could not publish; inference admission remains guarded")
	}
}

func (h *Handler) observePluginQuotaRejection(ctx context.Context, a *coreauth.Auth) bool {
	current := h.currentRuntimeSource(a)
	if current == nil || a.ResourceIdentity == nil || !reflect.DeepEqual(a.ResourceIdentity.Targets, current.ResourceIdentity.Targets) {
		return false
	}
	src := h.quotaSource(ctx, current)
	if src.State != "ready" || (src.Protocol != "opencode-go-usage" && src.Protocol != "qwen-coding-plan-cli") {
		return false
	}
	if err := h.resourceCatalog.PluginQuotaRejected(src, time.Now()); err != nil {
		log.Warn("Could not persist subscription quota rejection")
		return false
	}
	return true
}
