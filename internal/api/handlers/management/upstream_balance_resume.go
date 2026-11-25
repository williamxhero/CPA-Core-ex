package management

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// UpstreamBalanceResult adds the decision reason to the shared gate ACK shape.
// A non-applied answer is still a complete, durable-aware read of the ledger.
type UpstreamBalanceResult struct {
	resource.GateResult
	Reason string `json:"reason,omitempty"`
}

type upstreamBalanceBindingRequest struct {
	Version   int              `json:"version"`
	OpID      string           `json:"opId"`
	Binding   resource.Binding `json:"binding"`
	AuthIndex string           `json:"authIndex"`
}

// UpstreamBalanceResume is the explicit operator override of one automatic
// balance pause. Manual disablement, held state, authentication status and every
// other gate owner are out of scope and stay untouched.
func (h *Handler) UpstreamBalanceResume(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var request struct {
		upstreamBalanceBindingRequest
		Reason string `json:"reason"`
	}
	if !decodeUpstreamBalanceRequest(c, &request) || !validUpstreamBalanceBinding(request.upstreamBalanceBindingRequest) {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	if request.Reason != "" && request.Reason != resourcecatalog.UpstreamBalanceManualResumeReason {
		c.JSON(422, gin.H{"error": "invalid_reason"})
		return
	}
	if !h.upstreamBalanceAuthorityCurrent(c, request.Binding, request.AuthIndex) {
		return
	}
	result, reason, err := h.resourceCatalog.ResumeUpstreamBalance(request.OpID, request.Binding, request.AuthIndex, request.Reason, time.Now())
	writeUpstreamBalanceResult(c, result, reason, err)
}

// UpstreamBalanceObserve retires the pause only for a positive reading that is
// newer than the recorded exhaustion. Every other outcome is a durable no-op
// with an explicit reason, never a silent clear.
func (h *Handler) UpstreamBalanceObserve(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var request struct {
		upstreamBalanceBindingRequest
		Reading *struct {
			ObservedAtMS int64  `json:"observedAtMs"`
			Available    bool   `json:"available"`
			SourceID     string `json:"sourceId"`
		} `json:"reading"`
	}
	if !decodeUpstreamBalanceRequest(c, &request) || !validUpstreamBalanceBinding(request.upstreamBalanceBindingRequest) || request.Reading == nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	now := time.Now()
	if request.Reading.ObservedAtMS <= 0 || request.Reading.ObservedAtMS > now.UnixMilli() || !resourcecatalog.ValidUpstreamBalanceSourceID(request.Reading.SourceID) {
		c.JSON(422, gin.H{"error": "invalid_reading"})
		return
	}
	if !h.upstreamBalanceAuthorityCurrent(c, request.Binding, request.AuthIndex) {
		return
	}
	reading := resourcecatalog.UpstreamBalanceReading{ObservedAtMS: request.Reading.ObservedAtMS, Available: request.Reading.Available, SourceID: request.Reading.SourceID}
	result, reason, err := h.resourceCatalog.ObserveUpstreamBalanceReading(request.OpID, request.Binding, request.AuthIndex, reading, now)
	writeUpstreamBalanceResult(c, result, reason, err)
}

func decodeUpstreamBalanceRequest(c *gin.Context, out any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}

func validUpstreamBalanceBinding(request upstreamBalanceBindingRequest) bool {
	return request.Version == 1 && uuid.Validate(request.OpID) == nil && request.AuthIndex != "" &&
		len(request.AuthIndex) <= 256 && validHistoricalGateBinding(request.Binding)
}

// upstreamBalanceAuthorityCurrent verifies the request still describes the live
// runtime identity. It reads no provider quota: openai-compatible credentials
// have no quota source at all, and an exhausted one would fail such a read.
func (h *Handler) upstreamBalanceAuthorityCurrent(c *gin.Context, b resource.Binding, authIndex string) bool {
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return false
	}
	if _, ok := h.selectedQuota(resource.QuotaQuery{Binding: b, AuthIndex: authIndex}); !ok {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return false
	}
	return true
}

func writeUpstreamBalanceResult(c *gin.Context, result resource.GateResult, reason string, err error) {
	switch {
	case err == nil:
		c.JSON(200, UpstreamBalanceResult{GateResult: result, Reason: reason})
	case errors.Is(err, resourcecatalog.ErrOperationConflict):
		c.JSON(409, gin.H{"error": "operation_conflict"})
	case errors.Is(err, resourcecatalog.ErrGateRevisionConflict):
		c.JSON(409, gin.H{"error": "gate_conflict", "conflict": "gate_revision"})
	case errors.Is(err, resourcecatalog.ErrConflict):
		c.JSON(409, gin.H{"error": "gate_conflict"})
	default:
		c.JSON(503, gin.H{"error": "gate_unavailable"})
	}
}
