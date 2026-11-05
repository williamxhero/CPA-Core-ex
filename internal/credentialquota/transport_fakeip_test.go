package credentialquota

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"testing"
)

func TestBenchmarkFakeIPUsesRecoveredAddress(t *testing.T) {
	var dialed string
	client := secureClient(QueryTarget{EndpointURL: "https://chatgpt.com/backend-api/wham/usage"}, NetworkOptions{
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("198.18.0.16")}}, nil
		},
		RecoverLookup: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("104.18.32.47")}}, nil
		},
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, errors.New("stop")
		},
	})
	req, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Do(req); err == nil {
		t.Fatal("expected dial stop")
	}
	if dialed != "104.18.32.47:443" {
		t.Fatalf("dialed %q", dialed)
	}
}

func TestMixedForbiddenAnswerDoesNotRecover(t *testing.T) {
	called := false
	client := secureClient(QueryTarget{EndpointURL: "https://chatgpt.com/backend-api/wham/usage"}, NetworkOptions{
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("198.18.0.16")}, {IP: net.ParseIP("203.0.113.8")}}, nil
		},
		RecoverLookup: func(context.Context, string) ([]net.IPAddr, error) {
			called = true
			return []net.IPAddr{{IP: net.ParseIP("104.18.32.47")}}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dialed a mixed forbidden answer")
			return nil, nil
		},
	})
	req, _ := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected refusal")
	}
	if called {
		t.Fatal("recovery ran for a mixed answer")
	}
}

func TestRecoveredFakeIPStaysRefused(t *testing.T) {
	client := secureClient(QueryTarget{EndpointURL: "https://chatgpt.com/backend-api/wham/usage"}, NetworkOptions{
		LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("198.18.0.16")}}, nil
		},
		RecoverLookup: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("198.18.0.29")}}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dialed a recovered fake address")
			return nil, nil
		},
	})
	req, _ := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestLiveSystemFakeIPReachesQuotaHost(t *testing.T) {
	if os.Getenv("CPA_QUOTA_LIVE") == "" {
		t.Skip()
	}
	client := secureClient(QueryTarget{EndpointURL: "https://chatgpt.com/backend-api/wham/usage"}, NetworkOptions{})
	req, err := http.NewRequest(http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
}
