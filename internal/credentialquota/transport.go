package credentialquota

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func secureClient(target QueryTarget, n NetworkOptions) *http.Client {
	u, _ := url.Parse(target.EndpointURL)
	lookup := n.LookupIP
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	recoverLookup := n.RecoverLookup
	if recoverLookup == nil {
		recoverLookup = lookupViaDoH
	}
	dial := n.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	permitted := map[netip.Addr]bool{}
	for _, s := range target.PrivateTargets {
		ip, err := netip.ParseAddr(s)
		if err == nil {
			permitted[ip.Unmap()] = true
		}
	}
	transport := &http.Transport{
		Proxy:             nil, // Environment proxies cannot bypass resolution/pinning or receive credentials.
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: n.RootCAs},
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, u.Hostname()) || strings.EqualFold(host, "metadata.google.internal") || strings.EqualFold(host, "metadata") {
				return nil, errors.New("target refused")
			}
			ips, err := lookup(ctx, host)
			if err != nil || len(ips) == 0 {
				return nil, errors.New("resolution failed")
			}
			if onlyBenchmarkFakeIP(ips) {
				recovered, recErr := recoverLookup(ctx, host)
				if recErr != nil || len(recovered) == 0 || onlyBenchmarkFakeIP(recovered) {
					return nil, errors.New("target refused")
				}
				ips = recovered
			}
			// Validate the ENTIRE answer before sending authorization to any member.
			pinned := make([]string, 0, len(ips))
			for _, v := range ips {
				ip, err := netip.ParseAddr(v.IP.String())
				ip = ip.Unmap()
				if err != nil || v.Zone != "" || forbiddenIP(ip) || (ip.IsPrivate() || ip.IsLoopback()) && !permitted[ip] {
					return nil, errors.New("target refused")
				}
				pinned = append(pinned, net.JoinHostPort(ip.String(), port))
			}
			// Dial only validated numeric IPs: DNS is never resolved again by the dialer.
			for _, addr := range pinned {
				conn, e := dial(ctx, network, addr)
				if e == nil {
					return conn, nil
				}
			}
			return nil, errors.New("connection failed")
		},
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

func onlyBenchmarkFakeIP(ips []net.IPAddr) bool {
	if len(ips) == 0 {
		return false
	}
	for _, v := range ips {
		ip, err := netip.ParseAddr(v.IP.String())
		if err != nil || v.Zone != "" || !fakeIPPrefix.Contains(ip.Unmap()) {
			return false
		}
	}
	return true
}

func lookupViaDoH(ctx context.Context, host string) ([]net.IPAddr, error) {
	if host == "" || strings.Contains(host, "/") || net.ParseIP(host) != nil {
		return nil, errors.New("resolution failed")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused")
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, "1.1.1.1:443")
			},
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "cloudflare-dns.com"},
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://cloudflare-dns.com/dns-query?name="+url.QueryEscape(host)+"&type=A", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errors.New("resolution failed")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Status != 0 {
		return nil, errors.New("resolution failed")
	}
	out := make([]net.IPAddr, 0, len(parsed.Answer))
	for _, answer := range parsed.Answer {
		if answer.Type != 1 {
			continue
		}
		ip := net.ParseIP(answer.Data)
		if ip == nil {
			return nil, errors.New("resolution failed")
		}
		out = append(out, net.IPAddr{IP: ip})
	}
	if len(out) == 0 {
		return nil, errors.New("resolution failed")
	}
	return out, nil
}
