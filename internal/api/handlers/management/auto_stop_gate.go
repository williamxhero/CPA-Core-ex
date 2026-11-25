package management

import (
	"github.com/gin-gonic/gin"
)

// InferenceGateAutoStop publishes the read-only automatic-pause projection per
// provider group. It never writes a gate, so an unreadable ledger is reported
// as unavailable instead of an empty provider list.
func (h *Handler) InferenceGateAutoStop(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	projection, err := h.resourceCatalog.AutoStopProjection()
	if err != nil {
		c.JSON(503, gin.H{"error": "gate_unavailable"})
		return
	}
	c.JSON(200, projection)
}
