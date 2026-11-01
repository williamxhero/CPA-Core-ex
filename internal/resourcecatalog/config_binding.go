package resourcecatalog

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// BindConfiguredAuths bridges actual runtime locators to the current source
// synthesis. Locators and keyed equality proofs are NOT durable identities.
// Ambiguous duplicate effective credentials never acquire an ordinal identity.
func (c *Catalog) BindConfiguredAuths(auths []*coreauth.Auth) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() {
		return ErrUnavailable
	}
	projected, err := c.configuredAuthsLocked()
	if err != nil {
		return err
	}
	proof := func(a *coreauth.Auth) string {
		credentials := map[string]string{"api_key": a.Attributes["api_key"], "base_url": a.Attributes["base_url"]}
		for name, value := range a.Attributes {
			if strings.HasPrefix(name, "header:") {
				credentials[name] = value
			}
		}
		return sealValue(c.key, []any{a.Provider, a.ProxyURL, a.Prefix, credentials})
	}
	counts := map[string]int{}
	for _, a := range projected {
		counts[proof(a)]++
	}
	for _, a := range auths {
		if a == nil || a.SourcePluginID != "" || a.Attributes[coreauth.AttributePath] != "" || !strings.HasPrefix(a.Attributes[coreauth.AttributeSource], "config:") {
			continue
		}
		a.ResourceIdentity = nil
		for _, expected := range projected {
			if a.ID != expected.ID || proof(a) != proof(expected) || counts[proof(expected)] != 1 {
				continue
			}
			marker := expected.Attributes[coreauth.AttributeResourceID]
			parent := expected.Attributes[coreauth.AttributeProviderResourceID]
			for _, row := range c.snapshot.Resources {
				if marker == "" || row.ResourceID != marker || row.Kind != "credential" || row.ParentID != parent || row.Identity != "valid" || row.Readiness != "ready" {
					continue
				}
				a.Attributes[coreauth.AttributeResourceID] = marker
				a.Attributes[coreauth.AttributeProviderResourceID] = parent
				a.ResourceIdentity = &resource.Binding{Scope: c.snapshot.Version, Targets: []resource.Target{row.Target}}
			}
		}
	}
	return nil
}

// Repeated final-send admission must not reparse and bcrypt-hash the same
// management password. The sealed current source/version is checked BEFORE
// consulting this immutable invocation-independent synthesis projection.
type configuredSourceProjection struct {
	version resource.Version
	auths   []*coreauth.Auth
}

func (c *Catalog) configuredAuthsLocked() ([]*coreauth.Auth, error) {
	version := c.versionLocked()
	if p := c.configuredProjection; p != nil && p.version == version {
		return p.auths, nil
	}
	source, err := readSource(c.configPath, false)
	if err != nil {
		return nil, err
	}
	cfg, err := config.ParseConfigBytes(source.original)
	if err != nil {
		return nil, ErrUnavailable
	}
	auths, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{Config: cfg, IDGenerator: synthesizer.NewStableIDGenerator()})
	if err != nil {
		return nil, ErrUnavailable
	}
	c.configuredProjection = &configuredSourceProjection{version: version, auths: auths}
	return auths, nil
}
