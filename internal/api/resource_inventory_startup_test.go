package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

// This exercises the CLI startup order, not the handler-only inventory harness.
// All files/accounts/upstreams are synthetic; external updater traffic is denied.
func TestResourceIdentityRealBinaryStartup(t *testing.T) {
	binary := os.Getenv("CORE_IDENTITY_STARTUP_BINARY")
	if binary == "" {
		t.Skip("set CORE_IDENTITY_STARTUP_BINARY to the built cmd/server binary")
	}
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer deny.Close()
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDir, "startup-disabled.json"), []byte(`{"type":"codex","access_token":"synthetic-startup-token","disabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	source := fmt.Sprintf("config-version: 8\nserver: {host: 127.0.0.1, port: %d}\nmanagement: {secret-key: synthetic-startup-key, disable-control-panel: true, disable-auto-update-panel: true}\noauth: {auth-dir: %q}\nresource-catalog: {enabled: true, state-dir: catalog}\nplugins: {enabled: false}\napi-keys:\n  codex: [{name: synthetic, base-url: %q, keys: [{api-key: synthetic-key, disabled: true}]}]\n", port, filepath.ToSlash(authDir), deny.URL)
	if err = os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-config", path, "-local-model")
	cmd.Dir = dir
	var logs bytes.Buffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	for _, name := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP", "COMSPEC"} {
		if value := os.Getenv(name); value != "" {
			cmd.Env = append(cmd.Env, name+"="+value)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+dir, "USERPROFILE="+dir, "APPDATA="+dir, "LOCALAPPDATA="+dir, "HTTP_PROXY="+deny.URL, "HTTPS_PROXY="+deny.URL, "NO_PROXY=127.0.0.1,localhost")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log("isolated startup log:\n" + logs.String())
		}
	}()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	get := func(route string) (int, []byte, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("http://127.0.0.1:%d/v8/management/%s", port, route), nil)
		req.Header.Set("Authorization", "Bearer synthetic-startup-key")
		res, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		return res.StatusCode, data, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var data []byte
	for {
		status, body, err := get("resource-capabilities")
		if err == nil {
			if status != 200 {
				t.Fatalf("capability HTTP status=%d", status)
			}
			data = body
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("isolated server never listened")
		case <-ticker.C:
		}
	}
	var caps resource.Capabilities
	if err = json.Unmarshal(data, &caps); err != nil {
		t.Fatal(err)
	}
	// A 200 negative capability is NOT startup readiness. Do not poll it to green.
	if !caps.Inventory || !caps.Durable || caps.Query || caps.Gate {
		t.Fatalf("first successful HTTP capability was not enrolled: %s", data)
	}
	status, body, err := get("resources")
	if err != nil || status != 200 {
		t.Fatalf("resources immediately after listener readiness: status=%d err=%v", status, err)
	}
	var snapshot resource.Snapshot
	if err = json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.Complete || len(snapshot.Resources) != 3 {
		t.Fatal("startup inventory lost a source")
	}
	status, body, err = get("resource-bindings")
	if err != nil || status != 200 {
		t.Fatalf("bindings immediately after listener readiness: status=%d err=%v", status, err)
	}
	var view struct{ Bindings []resource.Binding }
	if err = json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Bindings) == 0 {
		t.Fatal("boot file binding missing")
	}
}
