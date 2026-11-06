package resourcecatalog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func publicationFixture(t *testing.T) (*Catalog, string, string, resource.Snapshot) {
	t.Helper()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	text := fmt.Sprintf("oauth: {auth-dir: %q}\nresource-catalog: {enabled: true}\napi-keys:\n  codex: [{name: initial, base-url: 'https://synthetic.invalid', keys: [{api-key: synthetic-A}]}]\n", filepath.ToSlash(authDir))
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(authDir, "synthetic.json")
	if err := os.WriteFile(authPath, []byte(`{"type":"codex","access_token":"synthetic-token"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path, authDir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	before, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return c, path, authPath, before
}

func replaceWithCopy(t *testing.T, path string) {
	t.Helper()
	beforeID, err := sourceFileID(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := path + ".synthetic-copy"
	if err = os.WriteFile(replacement, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	afterID, err := sourceFileID(path)
	if err != nil || beforeID == afterID {
		t.Fatal("fixture did not replace the physical source")
	}
}

func assertOldAuthNotReady(t *testing.T, c *Catalog, target resource.Target) {
	t.Helper()
	snapshot, err := c.Snapshot()
	if err != nil {
		return
	}
	if c.Check(snapshot.Version, target) == nil {
		t.Error("copied auth envelope retained its ready observation target")
	}
	for _, row := range snapshot.Resources {
		if row.ResourceID == target.ResourceID && (row.Identity == "valid" || row.Readiness == "ready") {
			t.Error("unauthorized physical replacement was published as ready")
		}
	}
}

func TestZeroWriteJournalYieldsWhenSourcesMove(t *testing.T) {
	c, path, _, _ := publicationFixture(t)
	files, _, err := sources(c.configPath, c.authDir)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	seals := map[string]string{}
	for _, f := range files {
		values[f.path] = seal(c.key, f.original)
		seals[f.path] = seal(c.key, []byte(f.fileID))
	}
	p := publication{ID: uuid.NewString(), Format: 2, Next: *c.state, Sources: values, FileSeals: seals}
	if err = c.writePublication(&p); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(string(data), "synthetic-A", "synthetic-B", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(c.stateDir, "journal.json")); !os.IsNotExist(err) {
		t.Fatal("unapplied journal remained and would disable the catalog")
	}
	if err = c.Reconcile(c.Version()); err != nil {
		t.Fatal(err)
	}
}

func TestResourceIdentityPublicationRejectsPhysicalReplacement(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%v", recovery), func(t *testing.T) {
			c, path, authPath, before := publicationFixture(t)
			var target resource.Target
			for _, row := range before.Resources {
				if row.Kind == "credential" && row.ParentID == "" {
					target = row.Target
				}
			}
			if target.ResourceID == "" {
				t.Fatal("missing file source fixture")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, []byte(strings.Replace(string(data), "initial", "renamed", 1)), 0600); err != nil {
				t.Fatal(err)
			}
			intercepted := false
			c.writeFile = func(destination string, data []byte) error {
				if err := atomicWrite(destination, data); err != nil {
					return err
				}
				if filepath.Base(destination) == "journal.json" && !intercepted {
					intercepted = true
					if recovery {
						return ErrUnavailable
					}
					replaceWithCopy(t, authPath)
				}
				return nil
			}
			err = c.Reconcile(before.Version)
			if !intercepted {
				t.Fatal("fixture did not cross the durable filesystem boundary")
			}
			if err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
			if !recovery {
				assertOldAuthNotReady(t, c, target)
			}
			if err = c.Close(); err != nil {
				t.Fatal(err)
			}
			if recovery {
				replaceWithCopy(t, authPath)
			}
			reopened, err := Open(path, filepath.Dir(authPath), "")
			if err == nil {
				defer func() {
					if err := reopened.Close(); err != nil {
						t.Error(err)
					}
				}()
				assertOldAuthNotReady(t, reopened, target)
			} else if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrUnavailable) {
				t.Fatal(err)
			}
		})
	}
}
