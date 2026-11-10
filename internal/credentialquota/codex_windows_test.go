package credentialquota

import (
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"testing"
	"time"
)

func TestCodexQuotaPreservesActualWindowDurations(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		seconds    []int64
	}{
		{"single_weekly_primary", `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":4,"reset_at":2000000000,"limit_window_seconds":604800}}}`, []int64{604800}},
		{"five_hour_and_weekly", `{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":34,"reset_at":2000000000,"limit_window_seconds":18000},"secondary_window":{"used_percent":5,"reset_at":2000000000,"limit_window_seconds":604800}}}`, []int64{18000, 604800}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codexUsageWindows(resource.QuotaObservation{QueryStatus: "success", Protocol: "codex-oauth-wham", ObservedAtMS: time.Now().UnixMilli()}, []byte(tc.body))
			if got.QueryStatus != "success" || len(got.Windows) != len(tc.seconds) {
				t.Fatalf("unexpected windows: %+v", got)
			}
			doc := ojson.NewDocString(`{}`)
			if err := doc.Set("windows", got.Windows); err != nil {
				t.Fatal(err)
			}
			windows := doc.Get("windows").Array()
			for i, w := range windows {
				if w.Get("limitWindowSeconds").Int() != tc.seconds[i] {
					t.Errorf("window %d duration=%d want=%d", i, w.Get("limitWindowSeconds").Int(), tc.seconds[i])
				}
			}
		})
	}
}
