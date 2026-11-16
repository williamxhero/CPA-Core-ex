package cliproxy

import (
	"context"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// needsModelRegistrationRepair reports whether an enabled plugin-backed
// credential is present in the auth manager but invisible to the scheduler
// because it has no registered models.
//
// Native providers are excluded: their catalogs are reconciled by config
// reloads and provider model sources. Plugin-backed credentials rely on
// per-auth model discovery (plugin model.for_auth), and losing that publication
// makes every model of the provider fail with auth_not_found even though the
// credential stays active in the panel.
func needsModelRegistrationRepair(auth *coreauth.Auth, pluginModelProvider bool, registeredModelCount int) bool {
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return false
	}
	if auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return false
	}
	if !pluginModelProvider {
		return false
	}
	return registeredModelCount == 0
}

// authsMissingModelRegistrations returns enabled plugin-backed credentials that
// have no registered models. The result is empty for healthy runtimes.
func (s *Service) authsMissingModelRegistrations() []*coreauth.Auth {
	if s == nil || s.coreManager == nil || s.pluginHost == nil {
		return nil
	}
	auths := s.coreManager.List()
	if len(auths) == 0 {
		return nil
	}
	reg := GlobalModelRegistry()
	providerCache := make(map[string]bool, 4)
	missing := make([]*coreauth.Auth, 0, 1)
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		provider := strings.ToLower(strings.TrimSpace(auth.Provider))
		pluginProvider, cached := providerCache[provider]
		if !cached {
			pluginProvider = pluginHostHasAuthModelProvider(s.pluginHost, provider)
			providerCache[provider] = pluginProvider
		}
		if needsModelRegistrationRepair(auth, pluginProvider, len(reg.GetModelsForClient(auth.ID))) {
			missing = append(missing, auth)
		}
	}
	return missing
}

// repairMissingAuthModelRegistrations republishes models for enabled
// plugin-backed credentials that lost their registration.
//
// Auth file updates can be dropped as stale by the generation or watcher
// revision fences (for example after a panel edit rewrites a credential file).
// When that happens the credential remains in the manager but no scheduler model
// shard references it, so every request for the provider's models reports
// "auth_not_found: no auth available" until the process restarts. This
// reconcile is idempotent and only touches credentials whose model set is
// actually empty.
func (s *Service) repairMissingAuthModelRegistrations(ctx context.Context) {
	if ctx != nil && ctx.Err() != nil {
		return
	}
	for _, auth := range s.authsMissingModelRegistrations() {
		log.WithFields(log.Fields{"auth_id": auth.ID, "provider": auth.Provider}).
			Warnf("repairing missing model registration for credential %s", auth.ID)
		s.completeModelRegistrationForAuthWithCache(ctx, auth, nil)
	}
}

const authModelRepairInterval = time.Minute

// startMissingAuthModelRepairLoop periodically reconciles plugin credentials
// whose model registration was lost to a dropped auth update.
func (s *Service) startMissingAuthModelRepairLoop(ctx context.Context) {
	if s == nil || ctx == nil || s.coreManager == nil || s.pluginHost == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(authModelRepairInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.repairMissingAuthModelRegistrations(ctx)
			}
		}
	}()
}
