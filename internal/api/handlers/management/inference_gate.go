package management

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func (h *Handler) InferenceGateCapabilities(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	durable := false
	revision := uint64(0)
	reason := "gate_unavailable"
	if h.resourceCatalog != nil && h.resourceModeReason() == "" {
		if state, err := h.resourceCatalog.GateState(); err == nil {
			durable = true
			revision = state.Revision
			reason = "route_verification_pending"
			if !state.Ready {
				reason = "identity_reconciliation_required"
			}
		}
	}
	c.JSON(200, gin.H{"version": 1, "ready": false, "durable": durable, "applied": false, "gateRevision": revision, "reason": reason, "mode": "standalone", "subjects": []string{"credential"}, "modelScoped": false, "routes": []gin.H{{"route": "all-current", "supported": false, "reason": reason}}})
}
func (h *Handler) InferenceGates(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	state, err := h.resourceCatalog.GateState()
	if err != nil {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	c.JSON(200, state)
}
func (h *Handler) InferenceGateOperation(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	_, result, err := h.resourceCatalog.GateOperation(c.Param("opId"))
	if errors.Is(err, os.ErrNotExist) {
		c.JSON(404, gin.H{"error": "operation_not_found"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	c.JSON(200, result)
}
func (h *Handler) ApplyInferenceGate(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	var op resource.GateOperation
	if d.Decode(&op) != nil || d.Decode(new(any)) != io.EOF || !resourcecatalog.ValidGateOperation(op) {
		c.JSON(400, gin.H{"error": "invalid_operation"})
		return
	}
	if op.Model != "" {
		c.JSON(422, gin.H{"error": "model_scope_unsupported"})
		return
	}
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	saved, result, err := h.resourceCatalog.GateOperation(op.OpID)
	if err == nil {
		if !reflect.DeepEqual(saved, op) {
			c.JSON(409, gin.H{"error": "operation_conflict"})
			return
		}
		c.JSON(200, result)
		return
	}
	if !errors.Is(err, os.ErrNotExist) {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	a, ok := h.selectedQuota(resource.QuotaQuery{Binding: op.Binding, AuthIndex: op.AuthIndex})
	if !ok || h.quotaSource(c.Request.Context(), a).SourceVersion != op.SourceVersion {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return
	}

	supported, _, routes := h.gateSourceCoverage(c.Request.Context(), a)
	for _, route := range routes {
		if route["supported"] != true {
			supported = false
		}
	}
	if !supported {
		c.JSON(503, gin.H{"error": "gate_route_unavailable"})
		return
	}
	if h.resourceCatalog.GateBindingReady(a.ResourceIdentity) != nil {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return
	}
	result, err = h.resourceCatalog.ApplyGate(op)
	if errors.Is(err, resourcecatalog.ErrConflict) {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return
	}
	if errors.Is(err, resourcecatalog.ErrOperationConflict) {
		c.JSON(409, gin.H{"error": "operation_conflict"})
		return
	}
	if err != nil {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	c.JSON(200, result)
}

// InferenceGateEligibility reads current source authority without changing intent.
func (h *Handler) InferenceGateEligibility(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var q struct {
		Version int `json:"version"`
		resource.Binding
		AuthIndex     string `json:"auth_index"`
		SourceVersion string `json:"sourceVersion"`
		Route         string `json:"route"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || q.Version != 1 || q.Route != "all-current-source" {
		c.JSON(400, gin.H{"error": "invalid_query"})
		return
	}
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	if _, err := h.resourceCatalog.GateState(); err != nil {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	a, ok := h.selectedQuota(resource.QuotaQuery{Binding: q.Binding, AuthIndex: q.AuthIndex})
	if !ok || q.SourceVersion == "" || h.quotaSource(c.Request.Context(), a).SourceVersion != q.SourceVersion {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return
	}

	supported, reason, routes := h.gateSourceCoverage(c.Request.Context(), a)
	if h.resourceCatalog.GateBindingReady(a.ResourceIdentity) != nil {
		supported = false
		reason = "identity_reconciliation_required"
		routes = []gin.H{{"route": "all-current-source", "supported": false, "reason": reason}}
	}
	// A partial route list cannot authorize an all-current-source ON.
	for _, route := range routes {
		if route["supported"] != true {
			supported = false
			reason = "route_verification_pending"
		}
	}
	c.JSON(200, gin.H{"version": 1, "scope": q.Scope, "targets": q.Targets, "auth_index": q.AuthIndex, "sourceVersion": q.SourceVersion, "ready": supported, "supported": supported, "modelScoped": false, "reason": reason, "routes": routes})
}
