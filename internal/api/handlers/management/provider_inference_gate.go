package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

type providerGateMember struct {
	resource.Binding
	AuthIndex     string  `json:"auth_index"`
	SourceVersion string  `json:"sourceVersion"`
	Routes        []gin.H `json:"routes"`
}

// This receipt proves current routing coverage, NOT balance, wallet ownership,
// currency, or funding coverage. Monetary policy requires separate evidence.
type providerGateView struct {
	resource.Binding
	Version       int                  `json:"version"`
	SourceVersion string               `json:"sourceVersion"`
	Ready         bool                 `json:"ready"`
	Supported     bool                 `json:"supported"`
	Reason        string               `json:"reason"`
	Authority     string               `json:"authority"`
	Members       []providerGateMember `json:"members"`
}

// ProviderInferenceGateEligibility is read-only and never queries money APIs.
func (h *Handler) ProviderInferenceGateEligibility(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var q struct {
		resource.Binding
		Version int    `json:"version"`
		Route   string `json:"route"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32<<10)
	d := json.NewDecoder(c.Request.Body)
	d.DisallowUnknownFields()
	if d.Decode(&q) != nil || d.Decode(new(any)) != io.EOF || q.Version != 1 || q.Route != "all-current-provider" {
		c.JSON(400, gin.H{"error": "invalid_query"})
		return
	}
	view, err := h.currentProviderGate(c.Request.Context(), q.Binding)
	if err != nil {
		providerGateError(c, err)
		return
	}
	c.JSON(200, view)
}

func providerGateError(c *gin.Context, err error) {
	if errors.Is(err, resourcecatalog.ErrConflict) {
		c.JSON(409, gin.H{"error": "gate_conflict"})
		return
	}
	c.JSON(503, gin.H{"error": "gate_unavailable"})
}

// Check a closing complete view as well as the catalog scope. The hash includes
// each member's actual binding, locator, source revision and route receipts;
// reordering the submitted complete group does not change its authority.
func (h *Handler) currentProviderGate(ctx context.Context, b resource.Binding) (providerGateView, error) {
	first, err := h.providerGateCoverage(ctx, b)
	if err != nil {
		return providerGateView{}, err
	}
	last, err := h.providerGateCoverage(ctx, first.Binding)
	if err != nil {
		return providerGateView{}, err
	}
	if first.SourceVersion != last.SourceVersion {
		return providerGateView{}, resourcecatalog.ErrConflict
	}
	return last, nil
}

func (h *Handler) providerGateCoverage(ctx context.Context, b resource.Binding) (providerGateView, error) {
	if h.resourceCatalog == nil || h.authManager == nil || h.resourceModeReason() != "" {
		return providerGateView{}, resourcecatalog.ErrUnavailable
	}
	canonical, err := h.resourceCatalog.ProviderGateBinding(b)
	if err != nil {
		return providerGateView{}, err
	}
	view := providerGateView{Binding: canonical, Version: 1, Ready: true, Supported: true,
		Reason: "verified_provider_routes", Authority: "routing_only", Members: []providerGateMember{}}
	byChild := make(map[string][]providerGateMember, len(canonical.Targets)-1)
	for _, a := range h.authManager.List() {
		a = h.currentRuntimeSource(a)
		if a == nil {
			continue
		}
		childID := ""
		for _, t := range a.ResourceIdentity.Targets {
			for _, child := range canonical.Targets[1:] {
				if t.ResourceID == child.ResourceID {
					if t != child || childID != "" || a.ResourceIdentity.Scope != canonical.Scope {
						return providerGateView{}, resourcecatalog.ErrConflict
					}
					childID = child.ResourceID
				}
			}
		}
		if childID == "" {
			continue
		}
		if a.Index == "" {
			return providerGateView{}, resourcecatalog.ErrUnavailable
		}
		source := h.quotaSource(ctx, a)
		if source.SourceVersion == "" {
			return providerGateView{}, resourcecatalog.ErrUnavailable
		}
		supported, _, routes := h.gateSourceCoverage(ctx, a)
		if len(routes) == 0 {
			supported = false
		}
		for _, route := range routes {
			if route["supported"] != true {
				supported = false
			}
		}
		if !supported {
			view.Ready, view.Supported, view.Reason = false, false, "route_verification_pending"
		}
		byChild[childID] = append(byChild[childID], providerGateMember{Binding: *a.ResourceIdentity,
			AuthIndex: a.Index, SourceVersion: source.SourceVersion, Routes: routes})
	}
	locators := make(map[string]bool, len(canonical.Targets)-1)
	for _, child := range canonical.Targets[1:] {
		members := byChild[child.ResourceID]
		// Missing or ambiguous actual runtime authority cannot authorize a group.
		if len(members) != 1 || locators[members[0].AuthIndex] {
			return providerGateView{}, resourcecatalog.ErrUnavailable
		}
		locators[members[0].AuthIndex] = true
		view.Members = append(view.Members, members[0])
	}
	closing, err := h.resourceCatalog.ProviderGateBinding(canonical)
	if err != nil {
		return providerGateView{}, err
	}
	if !reflect.DeepEqual(closing, canonical) {
		return providerGateView{}, resourcecatalog.ErrConflict
	}
	raw, err := json.Marshal(view)
	if err != nil {
		return providerGateView{}, resourcecatalog.ErrUnavailable
	}
	digest := sha256.Sum256(raw)
	view.SourceVersion = hex.EncodeToString(digest[:])
	return view, nil
}
