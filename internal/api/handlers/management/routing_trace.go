package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h *Handler) GetRoutingTrace(c *gin.Context) {
	h.mu.Lock()
	manager := h.authManager
	h.mu.Unlock()
	if result, ok := manager.RoutingTrace(c.Param("id")); ok {
		c.JSON(http.StatusOK, result)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "routing diagnosis not found"})
}
