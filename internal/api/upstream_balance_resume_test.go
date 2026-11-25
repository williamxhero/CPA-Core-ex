package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/resourcecatalog"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
	"gopkg.in/yaml.v3"
)

const (
	balanceResumeKeyA       = "RESUME-A-CANARY"
	balanceResumeKeySibling = "RESUME-SIBLING-CANARY"
	balanceResumeKeyOther   = "RESUME-OTHER-CANARY"
	balanceResumeOwner      = "core.upstream-balance.v1"
)

// Every assertion below runs against the real management route, the real
// catalog ledger and a real inference dispatch. The fixture is a controlled TLS
// upstream that denies the first request on key A with an explicit balance code.
type balanceResumeRig struct {
	dir      string
	path     string
	upstream *httptest.Server
	mu       sync.Mutex
	sends    map[string]int
}

func newBalanceResumeRig(t *testing.T) *balanceResumeRig {
	t.Helper()
	rig := &balanceResumeRig{sends: map[string]int{}}
	rig.dir = t.TempDir()
	rig.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		rig.mu.Lock()
		rig.sends[key]++
		first := rig.sends[key] == 1
		rig.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if key == balanceResumeKeyA && first {
			w.WriteHeader(402)
			fmt.Fprint(w, `{"error":{"code":"INSUFFICIENT_BALANCE","message":"Request rejected"}}`)
			return
		}
		fmt.Fprint(w, `{"id":"ok","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	}))
	t.Cleanup(rig.upstream.Close)
	rig.path = filepath.Join(rig.dir, "config.yaml")
	cfg := fmt.Sprintf(`server: {port: 0}
management: {secret-key: test-password}
oauth: {auth-dir: %q}
resource-catalog: {enabled: true}
api-keys:
  openai-compatibility:
    - name: resume-pool
      base-url: %q
      disable-cooling: false
      models: [{name: resume-primary}, {name: resume-secondary}]
      keys: [{api-key: %s}, {api-key: %s}]
    - name: resume-other
      base-url: %q
      disable-cooling: true
      models: [{name: resume-other}]
      keys: [{api-key: %s}]
`, filepath.ToSlash(filepath.Join(rig.dir, "auth")), rig.upstream.URL+"/v1", balanceResumeKeyA, balanceResumeKeySibling, rig.upstream.URL+"/v1", balanceResumeKeyOther)
	if err := os.WriteFile(rig.path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return rig
}

func (rig *balanceResumeRig) open(t *testing.T) *inventoryHarness {
	t.Helper()
	f := newInventoryHarness(t, rig.dir)
	f.manager.SetConfig(f.server.cfg)
	f.manager.SetRoundTripperProvider(scopedQuotaTransport{rig.upstream.Client().Transport})
	f.manager.SetSelector(&gatePreferASelector{key: balanceResumeKeyA})
	for _, auth := range f.manager.List() {
		f.manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(auth.Provider, f.server.cfg))
		models := []*registry.ModelInfo{{ID: "resume-primary"}, {ID: "resume-secondary"}}
		if auth.Attributes["api_key"] == balanceResumeKeyOther {
			models = []*registry.ModelInfo{{ID: "resume-other"}}
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, models)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}
	h := openai.NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&f.server.cfg.SDKConfig, f.manager))
	f.server.engine.POST("/v1/chat/completions", h.ChatCompletions)
	if err := f.handler.ReconcileResourceInventory(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (rig *balanceResumeRig) count(key string) int {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	return rig.sends[key]
}

// binding returns the live identity authority for one configured credential.
func (rig *balanceResumeRig) binding(t *testing.T, f *inventoryHarness, key string) (resource.Binding, string) {
	t.Helper()
	for _, a := range f.manager.List() {
		if a.Attributes["api_key"] != key || a.ResourceIdentity == nil {
			continue
		}
		a.EnsureIndex()
		return *a.ResourceIdentity, a.Index
	}
	t.Fatalf("no live runtime binding for %s", key)
	return resource.Binding{}, ""
}

func (rig *balanceResumeRig) postRaw(t *testing.T, f *inventoryHarness, action string, body any, token string) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v8/management/inference-gates/upstream-balance/"+action, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func (rig *balanceResumeRig) post(t *testing.T, f *inventoryHarness, action string, body any, want int) []byte {
	t.Helper()
	code, raw, _ := rig.postFull(t, f, action, body, "test-password")
	if code != want {
		t.Fatalf("%s status=%d want=%d body=%s", action, code, want, raw)
	}
	return raw
}

func (rig *balanceResumeRig) postFull(t *testing.T, f *inventoryHarness, action string, body any, token string) (int, []byte, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v8/management/inference-gates/upstream-balance/"+action, bytes.NewReader(raw))
	req.RemoteAddr = "127.0.0.1:1234"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes(), w.Header().Get("Cache-Control")
}

type balanceResumeResponse struct {
	resource.GateResult
	Reason string `json:"reason"`
}

func decodeBalanceResume(t *testing.T, raw []byte) balanceResumeResponse {
	t.Helper()
	var out balanceResumeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func resumeRequest(t *testing.T, b resource.Binding, authIndex, opID, reason string) map[string]any {
	t.Helper()
	return map[string]any{"version": 1, "opId": opID, "binding": b, "authIndex": authIndex, "reason": reason}
}

func observeRequest(t *testing.T, b resource.Binding, authIndex, opID string, observedAtMS int64, available bool, sourceID string) map[string]any {
	t.Helper()
	return map[string]any{"version": 1, "opId": opID, "binding": b, "authIndex": authIndex,
		"reading": map[string]any{"observedAtMs": observedAtMS, "available": available, "sourceId": sourceID}}
}

// freshObservation returns a server timestamp strictly later than the fence it
// must beat, without ever exceeding the request's own "now".
func freshObservation(t *testing.T, strictlyAfter int64) int64 {
	t.Helper()
	for i := 0; i < 500; i++ {
		if now := time.Now().UnixMilli(); now > strictlyAfter {
			return now
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("clock did not advance past the pause fence")
	return 0
}

func balancePauseFence(t *testing.T, state resource.GateState) int64 {
	t.Helper()
	if len(state.Gates) != 1 || state.Gates[0].Owner != balanceResumeOwner {
		t.Fatalf("want exactly the automatic balance pause, got %+v", state.Gates)
	}
	fence := resourcecatalog.BalanceGateObservedAtMS(state.Gates[0].Owner, state.Gates[0].EvidenceID)
	if fence <= 0 {
		t.Fatalf("pause carries no observation fence: %+v", state.Gates[0])
	}
	return fence
}

func TestUpstreamBalanceManualResumeRestoresDispatch(t *testing.T) {
	rig := newBalanceResumeRig(t)
	f := rig.open(t)
	if w := balanceInference(f, "resume-primary"); rig.count(balanceResumeKeyA) != 1 || w.Code == 200 && !strings.Contains(w.Body.String(), `"content":"ok"`) {
		t.Fatalf("fixture did not exercise a real balance denial: status=%d sends=%d body=%s", w.Code, rig.count(balanceResumeKeyA), w.Body)
	}
	paused := readBalanceGates(t, f)
	balancePauseFence(t, paused)
	if paused.Gates[0].Reason != "upstream_balance_exhausted" || paused.Gates[0].Applicability != "current" {
		t.Fatalf("wrong pause: %+v", paused.Gates[0])
	}
	binding, authIndex := rig.binding(t, f, balanceResumeKeyA)
	otherBinding, otherIndex := rig.binding(t, f, balanceResumeKeyOther)
	opID := uuid.NewString()
	body := resumeRequest(t, binding, authIndex, opID, "manual_resume")

	first := rig.post(t, f, "resume", body, 200)
	result := decodeBalanceResume(t, first)
	if !result.Applied || !result.Durable || result.Status != "applied" || result.OpID != opID || result.Revision != paused.Revision+1 {
		t.Fatalf("manual resume was not a durable applied ACK: %+v", result)
	}
	if repeat := rig.post(t, f, "resume", body, 200); !bytes.Equal(first, repeat) {
		t.Fatalf("replay changed the receipt:\n%s\n%s", first, repeat)
	}
	conflict := resumeRequest(t, otherBinding, otherIndex, opID, "manual_resume")
	if code, raw := rig.postRaw(t, f, "resume", conflict, "test-password"); code != 409 || !bytes.Contains(raw, []byte("operation_conflict")) {
		t.Fatalf("opId reuse with different content: status=%d body=%s", code, raw)
	}
	cleared := readBalanceGates(t, f)
	if len(cleared.Gates) != 0 || cleared.Revision != result.Revision {
		t.Fatalf("resume did not clear only its own pause: %+v", cleared)
	}
	// The next request must dispatch to the credential that was paused.
	if w := balanceInference(f, "resume-primary"); w.Code != 200 || !strings.Contains(w.Body.String(), `"content":"ok"`) || rig.count(balanceResumeKeyA) != 2 {
		t.Fatalf("resume did not restore dispatch: status=%d sends=%d body=%s", w.Code, rig.count(balanceResumeKeyA), w.Body)
	}
	// The recorded operation is readable through the existing operation route.
	readback := decodeBalanceResume(t, f.request("inference-gates/operations/"+opID, 200))
	if !readback.Applied || readback.Revision != result.Revision || readback.OpID != opID {
		t.Fatalf("readback disagreed with the ACK: %+v", readback)
	}
	// A second explicit resume converges instead of churning the ledger.
	second := decodeBalanceResume(t, rig.post(t, f, "resume", resumeRequest(t, binding, authIndex, uuid.NewString(), "manual_resume"), 200))
	if second.Applied || second.Reason != "no_pause" || second.Revision != result.Revision {
		t.Fatalf("resume without a pause rewrote the ledger: %+v", second)
	}
	if w := balanceInference(f, "resume-primary"); w.Code != 200 || rig.count(balanceResumeKeyA) != 3 {
		t.Fatalf("idempotent resume broke dispatch: status=%d sends=%d", w.Code, rig.count(balanceResumeKeyA))
	}
}

func TestUpstreamBalanceNoPauseReceiptCannotClearNewPause(t *testing.T) {
	rig := newBalanceResumeRig(t)
	f := rig.open(t)
	binding, authIndex := rig.binding(t, f, balanceResumeKeyA)
	opID := uuid.NewString()
	body := resumeRequest(t, binding, authIndex, opID, "manual_resume")
	first := rig.post(t, f, "resume", body, 200)
	if result := decodeBalanceResume(t, first); result.Applied || result.Reason != "no_pause" || !result.Durable {
		t.Fatalf("want durable no_pause: %+v", result)
	}
	balanceInference(f, "resume-primary")
	paused := readBalanceGates(t, f)
	balancePauseFence(t, paused)
	if repeat := rig.post(t, f, "resume", body, 200); !bytes.Equal(first, repeat) {
		t.Fatalf("no_pause replay changed after newer rejection:\n%s\n%s", first, repeat)
	}
	if after := readBalanceGates(t, f); after.Revision != paused.Revision || balancePauseFence(t, after) != balancePauseFence(t, paused) {
		t.Fatalf("replay touched the newer pause: %+v", after)
	}
	f.close()
	f = rig.open(t)
	if repeat := rig.post(t, f, "resume", body, 200); !bytes.Equal(first, repeat) {
		t.Fatalf("restart changed the historical receipt:\n%s\n%s", first, repeat)
	}
	if readback := f.request("inference-gates/operations/"+opID, 200); !bytes.Equal(first, readback) {
		t.Fatalf("operation readback changed the original response:\n%s\n%s", first, readback)
	}
	other, otherIndex := rig.binding(t, f, balanceResumeKeyOther)
	if code, raw := rig.postRaw(t, f, "resume", resumeRequest(t, other, otherIndex, opID, "manual_resume"), "test-password"); code != 409 || !bytes.Contains(raw, []byte("operation_conflict")) {
		t.Fatalf("no_pause opId reuse with different content: status=%d body=%s", code, raw)
	}
	if w := balanceInference(f, "resume-primary"); w.Code != 200 || rig.count(balanceResumeKeyA) != 1 {
		t.Fatalf("newer pause no longer blocked the rejected credential: status=%d sends=%d", w.Code, rig.count(balanceResumeKeyA))
	}
}

func TestUpstreamBalanceManualResumeConcurrentDuplicatesApplyOnce(t *testing.T) {
	rig := newBalanceResumeRig(t)
	f := rig.open(t)
	balanceInference(f, "resume-primary")
	paused := readBalanceGates(t, f)
	balancePauseFence(t, paused)
	binding, authIndex := rig.binding(t, f, balanceResumeKeyA)
	shared := uuid.NewString()
	const workers = 12
	codes := make([]int, workers)
	bodies := make([][]byte, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			opID := shared
			if i%2 == 1 {
				opID = uuid.NewString()
			}
			codes[i], bodies[i] = rig.postRaw(t, f, "resume", resumeRequest(t, binding, authIndex, opID, "manual_resume"), "test-password")
		}(i)
	}
	close(start)
	wg.Wait()
	applied := 0
	sharedBodies := [][]byte{}
	for i := range codes {
		if codes[i] != 200 {
			t.Fatalf("concurrent resume %d: status=%d body=%s", i, codes[i], bodies[i])
		}
		if i%2 == 1 {
			if decodeBalanceResume(t, bodies[i]).Applied {
				applied++
			}
			continue
		}
		sharedBodies = append(sharedBodies, bodies[i])
	}
	if applied > 1 {
		t.Fatalf("independent concurrent resumes cleared %d times; want at most one", applied)
	}
	for _, body := range sharedBodies {
		if !bytes.Equal(sharedBodies[0], body) {
			t.Fatal("duplicate opId replays disagreed under concurrency")
		}
	}
	settled := readBalanceGates(t, f)
	if len(settled.Gates) != 0 || settled.Revision != paused.Revision+1 {
		t.Fatalf("concurrent resumes flapped the ledger: %+v", settled)
	}
	if w := balanceInference(f, "resume-primary"); w.Code != 200 || rig.count(balanceResumeKeyA) != 2 {
		t.Fatalf("concurrent resume did not restore dispatch: status=%d sends=%d", w.Code, rig.count(balanceResumeKeyA))
	}
}

func TestUpstreamBalanceManualResumeKeepsManualDisable(t *testing.T) {
	rig := newBalanceResumeRig(t)
	f := rig.open(t)
	balanceInference(f, "resume-primary")
	balancePauseFence(t, readBalanceGates(t, f))
	binding, authIndex := rig.binding(t, f, balanceResumeKeyA)
	if result := decodeBalanceResume(t, rig.post(t, f, "resume", resumeRequest(t, binding, authIndex, uuid.NewString(), "manual_resume"), 200)); !result.Applied {
		t.Fatalf("manual resume did not clear the automatic pause: %+v", result)
	}
	if w := balanceInference(f, "resume-primary"); w.Code != 200 || rig.count(balanceResumeKeyA) != 2 {
		t.Fatalf("automatic pause was not lifted: status=%d sends=%d", w.Code, rig.count(balanceResumeKeyA))
	}
	// Manually stop the credential through the real config route.
	f.close()
	editInventoryConfig(t, rig.path, func(root *yaml.Node) {
		groups := testField(testField(root, "api-keys"), "openai-compatibility")
		group := groups.Content[0]
		group.Content = append(group.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "disabled"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	})
	f = rig.open(t)
	stopped := false
	for _, row := range f.snapshot().Resources {
		if row.ResourceID == binding.Targets[0].ResourceID {
			stopped = row.Manual.Disabled
		}
	}
	if !stopped {
		t.Fatal("manual stop was not recorded on the resumed credential")
	}
	if states := readBalanceGates(t, f); len(states.Gates) != 0 {
		t.Fatalf("manual stop resurrected an automatic pause: %+v", states.Gates)
	}
	// The manually stopped credential still receives no traffic.
	siblingBefore := rig.count(balanceResumeKeySibling)
	if w := balanceInference(f, "resume-primary"); w.Code == 200 {
		t.Fatalf("manually stopped pool served traffic: status=%d body=%s", w.Code, w.Body)
	}
	if rig.count(balanceResumeKeyA) != 2 || rig.count(balanceResumeKeySibling) != siblingBefore {
		t.Fatalf("manual stop did not hold: A=%d sibling delta=%d", rig.count(balanceResumeKeyA), rig.count(balanceResumeKeySibling)-siblingBefore)
	}
}

func TestUpstreamBalanceFreshPositiveReadingLiftsPause(t *testing.T) {
	rig := newBalanceResumeRig(t)
	f := rig.open(t)
	balanceInference(f, "resume-primary")
	paused := readBalanceGates(t, f)
	fence := balancePauseFence(t, paused)
	binding, authIndex := rig.binding(t, f, balanceResumeKeyA)
	otherBinding, otherIndex := rig.binding(t, f, balanceResumeKeyOther)

	negativeID := uuid.NewString()
	negativeAt := freshObservation(t, fence)
	negative := observeRequest(t, binding, authIndex, negativeID, negativeAt, false, "billing-api")
	firstNegative := rig.post(t, f, "observe", negative, 200)
	failed := decodeBalanceResume(t, firstNegative)
	if failed.Applied || failed.Reason != "not_positive" {
		t.Fatalf("a failed reading lifted the pause: %+v", failed)
	}
	type staleReceipt struct {
		request  map[string]any
		response []byte
	}
	staleReceipts := map[string]staleReceipt{}
	for name, ms := range map[string]int64{"equal": fence, "earlier": fence - 60_000} {
		request := observeRequest(t, binding, authIndex, uuid.NewString(), ms, true, "billing-api")
		raw := rig.post(t, f, "observe", request, 200)
		staleReceipts[name] = staleReceipt{request, raw}
		stale := decodeBalanceResume(t, raw)
		if stale.Applied || stale.Reason != "stale" {
			t.Fatalf("%s reading lifted the pause: %+v", name, stale)
		}
	}
	foreign := decodeBalanceResume(t, rig.post(t, f, "observe", observeRequest(t, otherBinding, otherIndex, uuid.NewString(), freshObservation(t, fence), true, "billing-api"), 200))
	if foreign.Applied || foreign.Reason != "no_pause" {
		t.Fatalf("another credential's reading touched this pause: %+v", foreign)
	}
	if still := readBalanceGates(t, f); len(still.Gates) != 1 {
		t.Fatalf("non-lifting readings changed the ledger: %+v", still)
	}
	if w := balanceInference(f, "resume-primary"); rig.count(balanceResumeKeyA) != 1 {
		t.Fatalf("stale readings admitted traffic early: status=%d sends=%d", w.Code, rig.count(balanceResumeKeyA))
	}

	opID := uuid.NewString()
	reading := observeRequest(t, binding, authIndex, opID, freshObservation(t, fence), true, "billing-api")
	firstReading := rig.post(t, f, "observe", reading, 200)
	fresh := decodeBalanceResume(t, firstReading)
	if !fresh.Applied || !fresh.Durable || fresh.Revision != paused.Revision+1 {
		t.Fatalf("a fresh positive reading did not lift the pause: %+v", fresh)
	}
	for name, receipt := range staleReceipts {
		if repeat := rig.post(t, f, "observe", receipt.request, 200); !bytes.Equal(repeat, receipt.response) {
			t.Fatalf("%s stale reading changed after recovery: %s", name, repeat)
		}
	}
	if repeat := rig.post(t, f, "observe", negative, 200); !bytes.Equal(repeat, firstNegative) {
		t.Fatalf("negative reading changed after recovery: %s", repeat)
	}
	if code, raw := rig.postRaw(t, f, "observe", observeRequest(t, binding, authIndex, negativeID, negativeAt, true, "billing-api"), "test-password"); code != 409 || !bytes.Contains(raw, []byte("operation_conflict")) {
		t.Fatalf("changing only the available flag: status=%d body=%s", code, raw)
	}
	replay := rig.post(t, f, "observe", reading, 200)
	if !bytes.Equal(replay, firstReading) {
		t.Fatalf("observation replay was not idempotent:\n%s\n%s", firstReading, replay)
	}
	if replayed := decodeBalanceResume(t, replay); replayed != fresh {
		t.Fatalf("observation replay changed the gate result: %+v want %+v", replayed, fresh)
	}
	if code, raw := rig.postRaw(t, f, "observe", observeRequest(t, binding, authIndex, opID, fence, true, "billing-api"), "test-password"); code != 409 || !bytes.Contains(raw, []byte("operation_conflict")) {
		t.Fatalf("observation opId reuse with different content: status=%d body=%s", code, raw)
	}
	if w := balanceInference(f, "resume-primary"); w.Code != 200 || rig.count(balanceResumeKeyA) != 2 {
		t.Fatalf("fresh reading did not restore dispatch: status=%d sends=%d body=%s", w.Code, rig.count(balanceResumeKeyA), w.Body)
	}
	settled := decodeBalanceResume(t, rig.post(t, f, "observe", observeRequest(t, binding, authIndex, uuid.NewString(), freshObservation(t, fence), true, "billing-api"), 200))
	if settled.Applied || settled.Reason != "no_pause" || settled.Revision != fresh.Revision {
		t.Fatalf("repeated observation flapped the ledger: %+v", settled)
	}
}

func TestUpstreamBalanceResumeValidationAndErrors(t *testing.T) {
	rig := newBalanceResumeRig(t)
	f := rig.open(t)
	binding, authIndex := rig.binding(t, f, balanceResumeKeyA)
	otherBinding, _ := rig.binding(t, f, balanceResumeKeyOther)
	valid := resumeRequest(t, binding, authIndex, uuid.NewString(), "manual_resume")

	if code, _ := rig.postRaw(t, f, "resume", valid, ""); code != 401 {
		t.Fatalf("resume without the management password: status=%d", code)
	}
	if code, _ := rig.postRaw(t, f, "observe", observeRequest(t, binding, authIndex, uuid.NewString(), 1, true, "billing-api"), ""); code != 401 {
		t.Fatalf("observe without the management password: status=%d", code)
	}
	for name, body := range map[string]string{
		"empty":         `{}`,
		"wrong-version": `{"version":2,"opId":"4d413194-faca-4b73-826e-a55a0b5da304","binding":{},"authIndex":"a","reason":"manual_resume"}`,
		"bad-op":        `{"version":1,"opId":"not-a-uuid","binding":{},"authIndex":"a","reason":"manual_resume"}`,
		"unknown":       `{"version":1,"secret":"SECRET-CANARY-NOT-RETURNED"}`,
	} {
		code, raw := rig.postRawRaw(t, f, "resume", body)
		if code != 400 || bytes.Contains(raw, []byte("SECRET-CANARY")) {
			t.Fatalf("%s: status=%d body=%s", name, code, raw)
		}
	}
	// A binding that no longer describes the live credential cannot authorize a clear.
	code, raw := rig.postRaw(t, f, "resume", resumeRequest(t, otherBinding, authIndex, uuid.NewString(), "manual_resume"), "test-password")
	if code != 409 || !bytes.Contains(raw, []byte("gate_conflict")) {
		t.Fatalf("mismatched binding: status=%d body=%s", code, raw)
	}
	for name, body := range map[string]map[string]any{
		"future":   observeRequest(t, binding, authIndex, uuid.NewString(), time.Now().Add(time.Hour).UnixMilli(), true, "billing-api"),
		"zero":     observeRequest(t, binding, authIndex, uuid.NewString(), 0, true, "billing-api"),
		"negative": observeRequest(t, binding, authIndex, uuid.NewString(), -1, true, "billing-api"),
		"no-reader": func() map[string]any {
			body := observeRequest(t, binding, authIndex, uuid.NewString(), time.Now().UnixMilli(), true, "billing-api")
			body["reading"].(map[string]any)["sourceId"] = ""
			return body
		}(),
	} {
		code, raw := rig.postRaw(t, f, "observe", body, "test-password")
		if code != 422 || !bytes.Contains(raw, []byte("invalid_reading")) {
			t.Fatalf("%s reading: status=%d body=%s", name, code, raw)
		}
	}
	if code, raw := rig.postRaw(t, f, "resume", resumeRequest(t, binding, authIndex, uuid.NewString(), "operator_override"), "test-password"); code != 422 || !bytes.Contains(raw, []byte("invalid_reason")) {
		t.Fatalf("unknown manual reason: status=%d body=%s", code, raw)
	}
	if code, _, header := rig.postFull(t, f, "resume", valid, "test-password"); code != 200 || header != "no-store" {
		t.Fatalf("non-cacheable result required: status=%d cache=%q", code, header)
	}
	if got := readBalanceGates(t, f); len(got.Gates) != 0 || got.Revision != 0 {
		t.Fatalf("rejected requests left half-written state: %+v", got)
	}
}

func (rig *balanceResumeRig) postRawRaw(t *testing.T, f *inventoryHarness, action, body string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v8/management/inference-gates/upstream-balance/"+action, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.engine.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}
