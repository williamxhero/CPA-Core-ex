package resourcecatalog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A markerless leftover auth file that reuses an identified id can never be
// registered by the runtime (one record per id). Minting a second identity for
// it turns a healthy credential into an ambiguous projection, so the copy must
// stay markerless and must never block its twin.
func TestLegacyDuplicateAuthFileIsNeverMinted(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	config := fmt.Sprintf(`oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys: {}
plugins:
  enabled: true
  configs:
    cpa-credential-opencode:
      enabled: true
      base-url: https://opencode.ai/inference/go/v1
      api-keys:
        - value: oc_sk_synthetic
`, filepath.ToSlash(authDir))
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(authDir, "opencode-go-key-owner.json")
	if err := os.WriteFile(owner, []byte(`{"type":"opencode-go","id":"shared-runtime-id","api_key":"oc_sk_synthetic"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(configPath, authDir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	before, err := c.Snapshot()
	if err != nil || len(before.Resources) != 3 {
		t.Fatalf("baseline snapshot rows=%d err=%v, want provider plus two verified projections", len(before.Resources), err)
	}
	ownerID := before.Resources[1].ResourceID
	if before.Resources[1].Kind != "credential" || before.Resources[1].Identity != "valid" || before.Resources[1].Readiness != "ready" {
		t.Fatalf("baseline credential is not ready: %+v", before.Resources[1])
	}

	const copyJSON = `{"api_key":"oc_sk_synthetic","id":"shared-runtime-id","label":"masked","type":"opencode-go"}`
	copyPath := filepath.Join(authDir, "OpenCode-Go.json")
	if err := os.WriteFile(copyPath, []byte(copyJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}

	after, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Resources) != len(before.Resources) {
		t.Fatalf("reconcile published %d rows, want %d (no identity minted for the copy)", len(after.Resources), len(before.Resources))
	}
	for _, row := range after.Resources {
		if row.Identity != "valid" || row.Readiness != "ready" || (row.Kind == "credential" && row.BindingState != "verified_projection") {
			t.Fatalf("copy blocked the identified source: %+v", row)
		}
	}
	kept := false
	for _, row := range after.Resources {
		if row.ResourceID == ownerID {
			kept = true
		}
	}
	if !kept {
		t.Fatal("identified source lost its resource identity")
	}
	raw, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != copyJSON {
		t.Fatalf("duplicate copy was rewritten: %s", string(raw))
	}

	// Republishing must not drift into minting the copy later.
	if err := c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
	again, err := c.Snapshot()
	if err != nil || len(again.Resources) != len(before.Resources) {
		t.Fatalf("second reconcile rows=%d err=%v", len(again.Resources), err)
	}
}
