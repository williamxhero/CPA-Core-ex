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
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	log "github.com/sirupsen/logrus"
)

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
	h.retireUpstreamBalance(c, resourcecatalog.UpstreamBalanceRetirement{
		OpID: request.OpID, Binding: request.Binding, AuthIndex: request.AuthIndex, Reason: request.Reason,
	})
}

// UpstreamBalanceObserve retires the pause only for a positive reading that is
// newer than the recorded exhaustion. Every other outcome is a durable no-op
// with an explicit reason, never a silent clear.
func (h *Handler) UpstreamBalanceObserve(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var request struct {
		upstreamBalanceBindingRequest
		Reading *resourcecatalog.UpstreamBalanceReading `json:"reading"`
	}
	if !decodeUpstreamBalanceRequest(c, &request) || !validUpstreamBalanceBinding(request.upstreamBalanceBindingRequest) || request.Reading == nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	h.retireUpstreamBalance(c, resourcecatalog.UpstreamBalanceRetirement{
		OpID: request.OpID, Binding: request.Binding, AuthIndex: request.AuthIndex, Reading: request.Reading,
	})
}

func decodeUpstreamBalanceRequest(c *gin.Context, out any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF
}

func validUpstreamBalanceBinding(request upstreamBalanceBindingRequest) bool {
	return request.Version == 1 && uuid.Validate(request.OpID) == nil && request.AuthIndex != "" &&
		len(request.AuthIndex) <= resourcecatalog.MaxUpstreamBalanceAuthIndex && validHistoricalGateBinding(request.Binding)
}

// Only a newly committed clear can release routing cooldown. A historical
// applied receipt must not touch cooldown (or a newer pause) on replay.
func (h *Handler) retireUpstreamBalance(c *gin.Context, request resourcecatalog.UpstreamBalanceRetirement) {
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	now := time.Now()
	var selected *coreauth.Auth
	result, cleared, err := h.resourceCatalog.RetireUpstreamBalance(request, now, func() bool {
		var ok bool
		selected, ok = h.selectedQuota(resource.QuotaQuery{Binding: request.Binding, AuthIndex: request.AuthIndex})
		return ok
	})
	if cleared {
		if errReset := h.authManager.ResetUpstreamBalanceCooldown(c.Request.Context(), selected, now); errReset != nil {
			log.Warn("Upstream balance pause cleared but routing cooldown could not be persisted")
		}
	}
	writeUpstreamBalanceResult(c, result, err)
}

func writeUpstreamBalanceResult(c *gin.Context, result resource.GateResult, err error) {
	switch {
	case err == nil:
		c.JSON(200, result)
	case errors.Is(err, resourcecatalog.ErrInvalidBalanceResumeReason):
		c.JSON(422, gin.H{"error": "invalid_reason"})
	case errors.Is(err, resourcecatalog.ErrInvalidBalanceReading):
		c.JSON(422, gin.H{"error": "invalid_reading"})
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
