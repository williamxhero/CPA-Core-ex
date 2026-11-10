package management

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func (h *Handler) initializeResourceCatalog() {
	if h.authManager != nil && h.cfg != nil && (h.cfg.ResourceCatalog.Enabled || resourcecatalog.GateFloorRequired(h.configFilePath, h.cfg.ResourceCatalog.StateDir)) {
		h.authManager.SetInferenceAdmission(func(ctx context.Context, a *coreauth.Auth, model string) error {
			if h.resourceCatalog == nil || a == nil {
				return resourcecatalog.ErrUnavailable
			}
			current := h.currentRuntimeSource(a)
			if current == nil {
				return h.resourceCatalog.AdmitInference(nil, model)
			}
			return h.resourceCatalog.AdmitInference(current.ResourceIdentity, model)
		})
	}
	h.resourceCatalogReason = h.resourceModeReason()
	if h.resourceCatalogReason != "" {
		return
	}
	h.resourceCatalogReason = "not_ready"
	catalog, err := resourcecatalog.Open(h.configFilePath, h.cfg.AuthDir, h.cfg.ResourceCatalog.StateDir)
	if err != nil {
		if errors.Is(err, resourcecatalog.ErrUnsupported) {
			h.resourceCatalogReason = "unsupported_filesystem"
		}
		return
	}
	h.resourceCatalog = catalog
	h.authManager.SetQuotaExhaustionObserver(h.observeQuotaExhaustion)
	h.authManager.SetSourceIdentityOwnedSave(catalog)
	if store, ok := h.authManager.Storage().(*sdkAuth.FileTokenStore); ok {
		store.SetSourceIdentityBinder(catalog)
	}
	// Opening an opted-in catalog can enroll markers in the source. Bind only
	// that writer receipt after migration, without replacing runtime settings.
	if data, errRead := os.ReadFile(h.configFilePath); errRead == nil {
		if loaded, errParse := config.ParseConfigBytes(data); errParse == nil {
			if _, errSnapshot := catalog.Snapshot(); errSnapshot == nil {
				h.cfg.ResourceCatalog = loaded.ResourceCatalog
				h.cfg.Plugins.Configs = loaded.Plugins.Configs
			}
		}
	}
	h.resourceCatalogReason = "available"
	h.bindRuntimeIdentities()
}

// CloseResourceCatalog releases instance-local catalog resources at shutdown.
func (h *Handler) CloseResourceCatalog() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resourceCatalog == nil || h.resourceCatalogClosed {
		return nil
	}
	h.resourceCatalogClosed = true
	if h.authManager != nil {
		if store, ok := h.authManager.Storage().(*sdkAuth.FileTokenStore); ok {
			store.SetSourceIdentityBinder(nil)
		}
	}
	if h.pluginHost != nil {
		h.pluginHost.SetSourceIdentityBinder(nil)
	}
	return h.resourceCatalog.Close()
}

// ResourceCapabilities reports only capabilities established by this instance.
func (h *Handler) ResourceCapabilities(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	reason := h.resourceModeReason()
	caps := resource.Capabilities{Version: 1, PolicyLocked: true, Reason: h.resourceCatalogReason}
	if h.resourceCatalog != nil && reason == "" {
		snapshot, err := h.resourceCatalog.Snapshot()
		caps.Inventory = err == nil
		caps.Durable = err == nil
		if err == nil {
			scope := snapshot.Version
			caps.CredentialQuery = &resource.CredentialQueryCapability{Version: 1, Sources: true, ScopedQuery: true}
			caps.Scope = &scope
		}
		if err != nil {
			caps.Reason = "not_ready"
		}
	}
	if reason != "" {
		caps.Reason = reason
	}
	view := resourceCapabilitiesView{Capabilities: caps}
	if caps.CredentialQuery != nil {
		view.CredentialQuery = &credentialQueryCapabilityView{CredentialQueryCapability: *caps.CredentialQuery, SourceBindings: true}
	}
	c.JSON(http.StatusOK, view)
}

// Resources never migrates sources or contacts providers as a side effect of a read.
func (h *Handler) Resources(c *gin.Context) {
	reason := h.resourceModeReason()
	c.Header("Cache-Control", "no-store")
	if h.resourceCatalog != nil && reason == "" {
		if snapshot, err := h.resourceCatalog.Snapshot(); err == nil {
			c.JSON(http.StatusOK, snapshot)
			return
		}
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "resource_inventory_unavailable"})
}

// ReconcileResourceInventory is a local source-write hook, not a management action API.
func (h *Handler) ReconcileResourceInventory() error {
	if h.resourceCatalog != nil && h.resourceModeReason() != "" {
		return resourcecatalog.ErrUnavailable
	}
	if h.resourceCatalog == nil {
		return nil
	}
	if err := h.resourceCatalog.Reconcile(h.resourceCatalog.Version()); err != nil {
		return err
	}
	h.bindRuntimeIdentities()
	return nil
}

// resourceModeReason takes no upstream action and does not infer manual ownership.
func (h *Handler) resourceModeReason() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cfg == nil || !h.cfg.ResourceCatalog.Enabled {
		return "not_enabled"
	}
	if h.cfg.Home.Enabled {
		return "unsupported_mode"
	}
	if h.authManager == nil {
		return "unsupported_storage"
	}
	store, ok := h.authManager.Storage().(*sdkAuth.FileTokenStore)
	if !ok || store == nil {
		return "unsupported_storage"
	}
	actual, err := util.ResolveAuthDir(store.BaseDir())
	if err != nil || actual == "" {
		return "unsupported_storage"
	}
	expected, err := util.ResolveAuthDir(h.cfg.AuthDir)
	if err != nil || expected == "" {
		return "unsupported_storage"
	}
	actual, err = filepath.EvalSymlinks(actual)
	if err != nil {
		return "unsupported_storage"
	}
	expected, err = filepath.EvalSymlinks(expected)
	if err != nil || actual != expected {
		return "unsupported_storage"
	}
	return ""
}

// ResourceBindings exposes only current host-owned identity evidence, not auth IDs.
func (h *Handler) ResourceBindings(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	if h.resourceCatalog == nil || h.resourceModeReason() != "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "resource_inventory_unavailable"})
		return
	}
	if _, err := h.resourceCatalog.Snapshot(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "resource_inventory_unavailable"})
		return
	}
	bindings := []runtimeSourceBinding{}
	for _, a := range h.authManager.List() {
		a = h.currentRuntimeSource(a)
		if a != nil {
			bindings = append(bindings, bindingFromCurrentAuth(a))
		}
	}
	c.JSON(http.StatusOK, gin.H{"bindings": bindings})
}

// SourceIdentityBinder connects the instance catalog to host synthesis paths.
func (h *Handler) SourceIdentityBinder() coreauth.SourceIdentityBinder {
	if h.resourceCatalog == nil {
		return nil
	}
	return h.resourceCatalog
}

// Source enrollment precedes identity publication, including pre-catalog boot
// auths. This establishes identity only; it never changes manual/gate state.
func (h *Handler) bindRuntimeIdentities() {
	if h.resourceCatalog == nil || h.authManager == nil {
		return
	}
	auths := h.authManager.List()
	if err := h.resourceCatalog.BindConfiguredAuths(auths); err != nil {
		return
	}
	for _, a := range auths {
		if a.ResourceIdentity != nil && a.Attributes[coreauth.AttributePath] == "" {
			_, _ = h.authManager.Update(coreauth.WithSkipPersist(context.Background()), a)
			continue
		}
		path := a.Attributes[coreauth.AttributePath]
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err = h.resourceCatalog.BindAuths(path, raw, []*coreauth.Auth{a}); err != nil {
			continue
		}
		_, _ = h.authManager.Update(coreauth.WithSkipPersist(context.Background()), a)
	}
}

// currentRuntimeSource revalidates a clone against the published source snapshot.
// It performs no source writes or enrollment and cannot adopt changed credentials.
// Metadata-only source publication must not leave unrelated runtime bindings at
// an obsolete global snapshot revision until an asynchronous watcher catches up.
func (h *Handler) currentRuntimeSource(a *coreauth.Auth) *coreauth.Auth {
	if a == nil || h.resourceCatalog == nil {
		return nil
	}
	a = a.Clone()
	path := a.Attributes[coreauth.AttributePath]
	if path == "" {
		if err := h.resourceCatalog.BindConfiguredAuths([]*coreauth.Auth{a}); err != nil {
			return nil
		}
	} else {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if err = h.resourceCatalog.BindAuths(path, raw, []*coreauth.Auth{a}); err != nil {
			return nil
		}
	}
	if !h.resourceCatalog.BindingCurrent(a.ResourceIdentity) {
		return nil
	}
	return a
}
