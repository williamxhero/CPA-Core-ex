package resourcecatalog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestUpstreamBalanceEvidenceIsOrderedAndIdempotent(t *testing.T) {
	c, configPath, authPath, snapshot := publicationFixture(t)
	binding := func(s resource.Snapshot) resource.Binding {
		t.Helper()
		for _, r := range s.Resources {
			if r.Kind == "credential" && r.ParentID != "" {
				return resource.Binding{Scope: s.Version, Targets: []resource.Target{r.Target}}
			}
		}
		t.Fatal("no configured credential")
		return resource.Binding{}
	}
	b := binding(snapshot)
	state := func(c *Catalog) resource.GateState {
		t.Helper()
		s, err := c.GateState()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	now := time.Now()
	first := now.Add(-3 * time.Second)
	latest := now.Add(-time.Second)
	if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", now.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("future observation: %v; want conflict", err)
	}
	if got := state(c); len(got.Gates) != 0 || got.Revision != 0 {
		t.Fatalf("invalid observation mutated gates: %+v", got)
	}
	const workers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wg.Go(func() {
			<-start
			if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", first); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	for _, observed := range []time.Time{first.Add(-time.Second), latest, latest} {
		if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", observed); err != nil {
			t.Fatal(err)
		}
	}
	got := state(c)
	if len(got.Gates) != 1 || got.Revision != 1 || BalanceGateObservedAtMS(got.Gates[0].Owner, got.Gates[0].EvidenceID) != first.UnixMilli() {
		t.Fatalf("repeated, late and later evidence must preserve the first pause: %+v", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(strings.Replace(string(data), "synthetic-A", "synthetic-B", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = Open(configPath, filepath.Dir(authPath), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	snapshot, err = c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	current := binding(snapshot)
	if current.Targets[0].ResourceID != b.Targets[0].ResourceID || current.Targets[0].CredentialVersion == b.Targets[0].CredentialVersion {
		t.Fatal("fixture did not replace the credential on the same stable slot")
	}
	if err := c.ObserveUpstreamBalanceExhaustion(b, "synthetic", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("old binding: %v; want conflict", err)
	}
	for _, observed := range []time.Time{first.Add(time.Second), latest} {
		if err := c.ObserveUpstreamBalanceExhaustion(current, "synthetic", observed); err != nil {
			t.Fatal(err)
		}
	}
	if got := state(c); got.Revision != 1 || c.AdmitInference(&current, "any-model") != nil {
		t.Fatalf("restart forgot the latest observation and replay paused the replacement: %+v", got)
	}
	if err := c.ObserveUpstreamBalanceExhaustion(current, "synthetic", now); err != nil {
		t.Fatal(err)
	}
	if got := state(c); len(got.Gates) != 1 || got.Revision != 2 || !errors.Is(c.AdmitInference(&current, "any-model"), ErrGateDenied) {
		t.Fatalf("fresh evidence did not pause the replacement: %+v", got)
	}
}
