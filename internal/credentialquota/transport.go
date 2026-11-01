package credentialquota

import (
	"context"
	"crypto/tls"
	"errors"
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
