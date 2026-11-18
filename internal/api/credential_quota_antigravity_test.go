package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

func TestCredentialQuotaAntigravitySelectedOAuth(t *testing.T) {
	calls := 0
	_, network := quotaTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1internal:retrieveUserQuotaSummary" || r.Header.Get("Authorization") != "Bearer AG-SECRET-CANARY" {
			t.Error("wrong selected Antigravity quota request")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["project"] != "selected-project" || len(body) != 1 {
			t.Error("wrong selected project")
		}
		fmt.Fprintf(w, `{"groups":[{"displayName":"Gemini Models","buckets":[{"bucketId":"gemini-weekly","window":"weekly","remainingFraction":0.75,"resetTime":%q}]}]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "auth"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "auth", "antigravity.json"), []byte(`{"type":"antigravity","email":"user@example.test","project_id":"selected-project","access_token":"AG-SECRET-CANARY","refresh_token":"AG-REFRESH-CANARY"}`), 0600); err != nil {
		t.Fatal(err)
	}
	f := newInventoryHarness(t, dir)
	f.handler.SetQuotaNetwork(network)
	source := quotaSourceFor(t, f, "antigravity-oauth-quota-summary")
	if source.State != "ready" || calls != 0 {
		t.Fatal("Antigravity source unavailable or inventory contacted upstream")
	}
	query := resource.QuotaQuery{Binding: source.Binding, AuthIndex: source.AuthIndex, SourceID: source.SourceID, SubjectID: source.SubjectID, SourceVersion: source.SourceVersion}
	observation := queryQuota(t, f, query, 200)
	if observation.QueryStatus != "success" || len(observation.Windows) != 1 || observation.Windows[0].RemainingFraction != 0.75 || observation.Complete || observation.RecoveryEligible {
		t.Fatalf("wrong Antigravity observation: %+v", observation)
	}
	query.Targets[0].CredentialVersion++
	queryQuota(t, f, query, 409)
	if calls != 1 {
		t.Fatal("stale credential binding contacted Antigravity")
	}
}
