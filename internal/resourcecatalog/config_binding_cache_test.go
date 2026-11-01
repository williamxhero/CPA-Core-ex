package resourcecatalog

import (
	"os"
	"strings"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestResourceIdentityConfiguredProjectionRequiresCurrentSealedSource(t *testing.T) {
	c, path, _, before := publicationFixture(t)
	if err := c.BindConfiguredAuths(nil); err != nil {
		t.Fatal(err)
	}
	cached := c.configuredProjection
	if cached == nil {
		t.Fatal("missing immutable projection")
	}
	if err := c.BindConfiguredAuths(nil); err != nil || cached != c.configuredProjection {
		t.Fatal("unchanged source unnecessarily reparsed")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(string(raw), "synthetic-A", "synthetic-B", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if c.BindConfiguredAuths(nil) == nil {
		t.Fatal("cached projection bypassed changed source seal")
	}
	if err = c.Reconcile(before.Version); err != nil {
		t.Fatal(err)
	}
	if err = c.BindConfiguredAuths(nil); err != nil {
		t.Fatal(err)
	}
	if cached == c.configuredProjection || cached.version == c.configuredProjection.version {
		t.Fatal("new source reused stale projection")
	}
}

// A cached source projection never certifies an edited in-memory credential.
func TestResourceIdentityConfiguredProjectionRechecksRuntimeCredentials(t *testing.T) {
	c, _, _, _ := publicationFixture(t)
	if err := c.BindConfiguredAuths(nil); err != nil {
		t.Fatal(err)
	}
	if len(c.configuredProjection.auths) != 1 {
		t.Fatal("expected one configured credential")
	}
	original := c.configuredProjection.auths[0].Clone()
	if err := c.BindConfiguredAuths([]*coreauth.Auth{original}); err != nil || original.ResourceIdentity == nil {
		t.Fatal("current credential did not bind", err)
	}
	cached := c.configuredProjection
	for _, field := range []string{"api_key", "base_url", "header:Authorization"} {
		t.Run(field, func(t *testing.T) {
			edited := original.Clone()
			edited.Attributes[field] = "different-synthetic-value"
			if err := c.BindConfiguredAuths([]*coreauth.Auth{edited}); err != nil {
				t.Fatal(err)
			}
			if edited.ResourceIdentity != nil {
				t.Fatal("cached projection certified changed runtime credential")
			}
			if c.configuredProjection != cached {
				t.Fatal("runtime comparison unnecessarily rebuilt sealed source projection")
			}
		})
	}
	if c.configuredProjection.auths[0].Attributes["api_key"] != original.Attributes["api_key"] {
		t.Fatal("runtime mutation escaped into immutable projection")
	}
}
