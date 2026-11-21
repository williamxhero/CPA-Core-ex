package management

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/providerkeymatch"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// ObserveDeepSeekFunding is reached only through the authenticated v8
// management route. An evidence-bound challenge cannot be transplanted from
// the read-only key-match API, another route, or a different observation.
func (h *Handler) ObserveDeepSeekFunding(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, providerkeymatch.MaxBytes)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	var input struct {
		Proof   json.RawMessage         `json:"proof"`
		Reading resource.FundingReading `json:"reading"`
	}
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		c.JSON(400, gin.H{"error": "invalid_observation"})
		return
	}
	q, err := providerkeymatch.Decode(input.Proof)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_observation"})
		return
	}
	a, e, status := h.providerKeyMatchCurrent(c, q)
	if status != 0 {
		providerKeyMatchError(c, status)
		return
	}
	matched, supported := e.ProviderFundingKeyMatch(a, q, input.Reading)
	if !supported {
		providerKeyMatchError(c, 422)
		return
	}
	if !matched {
		c.JSON(200, gin.H{"accepted": false})
		return
	}
	current, executor, status := h.providerKeyMatchCurrent(c, q)
	if status != 0 {
		providerKeyMatchError(c, status)
		return
	}
	closingMatch, closingSupport := executor.ProviderFundingKeyMatch(current, q, input.Reading)
	if c.Request.Context().Err() != nil || current.ID != a.ID || executor != e || !reflect.DeepEqual(a.ResourceIdentity, current.ResourceIdentity) || !closingSupport || !closingMatch {
		providerKeyMatchError(c, 409)
		return
	}
	source := h.quotaSource(c.Request.Context(), current)
	err = h.resourceCatalog.ObserveDeepSeekFunding(source.Binding, source.AuthIndex, source.SourceVersion, input.Reading, time.Now())
	switch {
	case errors.Is(err, resourcecatalog.ErrConflict):
		providerKeyMatchError(c, 409)
	case err != nil:
		providerKeyMatchError(c, 503)
	default:
		c.JSON(200, gin.H{"accepted": true})
	}
}
