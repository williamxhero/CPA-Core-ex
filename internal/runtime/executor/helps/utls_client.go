package helps

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v8/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/httptransport"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsRoundTripper implements http.RoundTripper using a Chrome fingerprint for
// providers that require browser-like TLS. The HTTP version follows ALPN. Each
// request gets a dedicated connection that is closed with the response body.
type utlsRoundTripper struct {
	dialer proxy.Dialer
}

type closeConnectionBody struct {
	io.ReadCloser
	closeConnection func() error
	once            sync.Once
	err             error
}

func (b *closeConnectionBody) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		var errConnection error
		if b.closeConnection != nil {
			errConnection = b.closeConnection()
		}
		var errBody error
		if b.ReadCloser != nil {
			errBody = b.ReadCloser.Close()
		}
		b.err = errors.Join(errBody, errConnection)
	})
	return b.err
}

func newUtlsRoundTripper(proxyURL string) *utlsRoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("utls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return &utlsRoundTripper{dialer: dialer}
}

func (t *utlsRoundTripper) createConnection(ctx context.Context, host, addr string) (*tls.UConn, error) {
	contextDialer, ok := t.dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("utls: dialer does not support context cancellation")
	}
	conn, errDial := contextDialer.DialContext(ctx, "tcp", addr)
	if errDial != nil {
		return nil, fmt.Errorf("utls: dial upstream: %w", errDial)
	}

	tlsConfig := &tls.Config{ServerName: host}
	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloChrome_Auto)

	handshakeCtx, cancelHandshake := handshakeContext(ctx)
	defer cancelHandshake()
	if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
		errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
		if errors.Is(errHandshake, context.Canceled) || errors.Is(errHandshake, context.DeadlineExceeded) {
			return nil, fmt.Errorf("utls: TLS handshake: %w", errHandshake)
		}
		if errClose := conn.Close(); errClose != nil {
			return nil, fmt.Errorf("utls: TLS handshake: %w; close connection: %v", errHandshake, errClose)
		}
		return nil, fmt.Errorf("utls: TLS handshake: %w", errHandshake)
	}

	return tlsConn, nil
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(hostname, port)

	tlsConn, err := t.createConnection(req.Context(), hostname, addr)
	if err != nil {
		return nil, err
	}
	return roundTripUtlsConnection(req, tlsConn)
}

// roundTripUtlsConnection selects the HTTP protocol before sending the request.
// Empty ALPN is HTTP/1.1, including when a TLS-inspecting proxy omits ALPN.
func roundTripUtlsConnection(req *http.Request, tlsConn *tls.UConn) (*http.Response, error) {
	closeConnection := func() error {
		// The HTTP/1.1 transport may already have closed its non-pooled
		// connection after reading the response or canceling the request.
		if errClose := tlsConn.Close(); errClose != nil && !errors.Is(errClose, net.ErrClosed) {
			return errClose
		}
		return nil
	}
	var resp *http.Response
	var err error
	switch protocol := tlsConn.ConnectionState().NegotiatedProtocol; protocol {
	case "h2":
		h2Conn, errClientConn := (&http2.Transport{}).NewClientConn(tlsConn)
		if errClientConn != nil {
			err = fmt.Errorf("utls: initialize HTTP/2 connection: %w", errClientConn)
			break
		}
		closeConnection = h2Conn.Close
		resp, err = h2Conn.RoundTrip(req)
	case "", "http/1.1":
		// Reuse the already-handshaken uTLS connection. A fresh, non-pooling
		// transport retains net/http's cancellation and request-body handling
		// without changing the TLS fingerprint or redialing through another path.
		transport := &http.Transport{
			DisableKeepAlives: true,
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return tlsConn, nil
			},
		}
		resp, err = transport.RoundTrip(req)
		transport.CloseIdleConnections()
	default:
		err = fmt.Errorf("utls: unsupported negotiated protocol %q", protocol)
	}
	if err != nil {
		if errClose := closeConnection(); errClose != nil {
			log.Debugf("utls: close connection after round trip failure: %v", errClose)
		}
		return nil, err
	}
	if resp == nil {
		if errClose := closeConnection(); errClose != nil {
			log.Debugf("utls: close connection after empty response: %v", errClose)
		}
		return nil, fmt.Errorf("utls: upstream returned an empty response")
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	resp.Body = &closeConnectionBody{
		ReadCloser:      resp.Body,
		closeConnection: closeConnection,
	}
	return resp, nil
}

// claudeCodeSessionCacheCapacity bounds the per-transport TLS session cache for
// the Anthropic inference plane.
const claudeCodeSessionCacheCapacity = 32

// newClaudeCodeTLSConfig builds the uTLS config for one inference-plane dial.
//
// OmitEmptyPsk keeps the pre_shared_key extension silent until a session is
// cached, so an unresumed ClientHello stays byte-identical to the captured
// native handshake. PreferSkipResumptionOnNilExtension turns uTLS's HelloCustom
// "resume without the matching extension" panic into a skipped resumption.
func newClaudeCodeTLSConfig(host string, sessionCache tls.ClientSessionCache) *tls.Config {
	return newClaudeCodeTLSConfigWithRoots(host, sessionCache, nil)
}

func newClaudeCodeTLSConfigWithRoots(host string, sessionCache tls.ClientSessionCache, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName:                         host,
		RootCAs:                            roots,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}
}

// claudeCodeTLSClientHelloSpec reproduces the deterministic Node/OpenSSL
// ClientHello emitted by Claude Code 2.1.220 on macOS arm64. Keep this spec in
// sync with a fresh native capture whenever the advertised Claude Code version
// changes.
func claudeCodeTLSClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA1,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{{Group: tls.X25519}}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			// pre_shared_key MUST be the final extension (RFC 8446 4.2.11), after
			// padding. It contributes zero bytes until a cached session exists.
			&tls.UtlsPreSharedKeyExtension{},
		},
	}
}

const claudeCodeRoundTripperCacheCapacity = 64

var claudeCodeRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	claudeCodeRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

var claudeCodeMessagesHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"X-Stainless-Timeout",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

var claudeCodeCountTokensHeaderOrder = []string{
	"Accept",
	"Authorization",
	"Content-Type",
	"User-Agent",
	"X-Claude-Code-Session-Id",
	"X-Stainless-Arch",
	"X-Stainless-Lang",
	"X-Stainless-OS",
	"X-Stainless-Package-Version",
	"X-Stainless-Retry-Count",
	"X-Stainless-Runtime",
	"X-Stainless-Runtime-Version",
	"anthropic-beta",
	"anthropic-dangerous-direct-browser-access",
	"anthropic-version",
	"x-app",
	"x-client-request-id",
	"Connection",
	"Host",
	"Accept-Encoding",
	"Content-Length",
}

func claudeCodeRequestHeaderOrder(_, requestTarget string) []string {
	if strings.HasPrefix(requestTarget, "/v1/messages/count_tokens") {
		return claudeCodeCountTokensHeaderOrder
	}
	return claudeCodeMessagesHeaderOrder
}

func cachedClaudeCodeRoundTripper(proxyURL string) http.RoundTripper {
	return claudeCodeRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newClaudeCodeRoundTripper(proxyURL)
	})
}

func newClaudeCodeRoundTripper(proxyURL string) http.RoundTripper {
	return newClaudeCodeRoundTripperForDialer(claudeCodeDialer(proxyURL))
}

// claudeCodeDialer resolves the dialer the Claude Code transport uses for one proxy
// setting. It is shared by the cached transport and the per-credential pooled one so
// both keep the same proxy semantics.
func claudeCodeDialer(proxyURL string) proxy.Dialer {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("claude tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}
	return dialer
}

// pooledClaudeCodeTransport returns the credential-scoped Claude Code uTLS transport
// when the credential opted into pooling, or nil so the caller keeps the historical
// shared per-proxy transport. Per credential pooling matters here because this
// transport is otherwise shared by every key that uses the same proxy, which mixes
// distinct identities on one connection and ignores the key's pool settings.
func pooledClaudeCodeTransport(proxyURL string, cfg *config.Config, auth *cliproxyauth.Auth) *http.Transport {
	tr, pooled := pooledTransport(proxyPoolKindClaudeCode, proxyURL, cfg, auth, func() (*http.Transport, error) {
		return newClaudeCodeRoundTripperForDialer(claudeCodeDialer(proxyURL)), nil
	})
	if !pooled {
		return nil
	}
	return tr
}

// newClaudeCodeRoundTripperForDialer builds the Claude Code transport on top
// of an already-resolved dialer. It is split out from
// newClaudeCodeRoundTripper so tests can inject in-memory connections.
func newClaudeCodeRoundTripperForDialer(dialer proxy.Dialer) *http.Transport {
	return newClaudeCodeRoundTripperForDialerAndRoots(dialer, nil)
}

func newClaudeCodeRoundTripperForDialerAndRoots(dialer proxy.Dialer, roots *x509.CertPool) *http.Transport {
	// The cache is scoped to this round tripper, which is already keyed by proxy,
	// so resumption never crosses proxy boundaries.
	sessionCache := tls.NewLRUClientSessionCache(claudeCodeSessionCacheCapacity)

	transport := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var (
				conn net.Conn
				err  error
			)
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				conn, err = contextDialer.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
			if err != nil {
				return nil, fmt.Errorf("claude tls: dial upstream: %w", err)
			}
			conn = stampProxyKeepAlive(conn)

			host, _, errSplit := net.SplitHostPort(addr)
			if errSplit != nil {
				if errClose := conn.Close(); errClose != nil {
					log.Debugf("claude tls: close failed connection: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: split upstream address: %w", errSplit)
			}
			tlsConn := tls.UClient(conn, newClaudeCodeTLSConfigWithRoots(host, sessionCache, roots), tls.HelloCustom)
			if errPreset := tlsConn.ApplyPreset(claudeCodeTLSClientHelloSpec()); errPreset != nil {
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("claude tls: close connection after preset failure: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: apply Claude Code ClientHello: %w", errPreset)
			}
			handshakeCtx, cancelHandshake := handshakeContext(ctx)
			defer cancelHandshake()
			if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
				errHandshake = classifyHandshakeError(ctx, handshakeCtx, errHandshake)
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("claude tls: close connection after handshake failure: %v", errClose)
				}
				return nil, fmt.Errorf("claude tls: handshake upstream: %w", errHandshake)
			}
			return httpwire.NewOrderedRequestConn(tlsConn, claudeCodeRequestHeaderOrder), nil
		},
	}
	return transport
}

// utlsChatGPTFallbackRoundTripper keeps the Chrome uTLS transport as the
// primary ChatGPT/Codex route and permits one replay on the standard Go
// transport when the primary fails before an HTTP response exists. The
// fallback is deliberately a separate round tripper so it cannot recurse back
// into this wrapper.
type utlsChatGPTFallbackRoundTripper struct {
	mu         sync.Mutex
	primary    http.RoundTripper
	fallback   http.RoundTripper
	fallbackFn func() http.RoundTripper
}

func (t *utlsChatGPTFallbackRoundTripper) fallbackRoundTripper() http.RoundTripper {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fallback == nil && t.fallbackFn != nil {
		t.fallback = t.fallbackFn()
		t.fallbackFn = nil
	}
	return t.fallback
}

func (t *utlsChatGPTFallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	replay, replayable := cloneRequestForUtlsFallback(req)
	resp, errPrimary := t.primary.RoundTrip(req)
	if resp != nil || !isTransientUtlsTransportError(errPrimary) || req == nil || req.Context().Err() != nil {
		return resp, errPrimary
	}
	if !replayable {
		return nil, errPrimary
	}
	fallback := t.fallbackRoundTripper()
	if fallback == nil {
		return nil, errPrimary
	}
	resp, errFallback := fallback.RoundTrip(replay)
	if resp != nil || errFallback == nil {
		log.Debugf("codex TLS fallback succeeded via standard TLS")
		return resp, errFallback
	}
	if req.Context().Err() != nil {
		return nil, errFallback
	}
	// Keep the client-facing error safe while retaining both underlying errors
	// for the conductor's transient transport classifier. The aggregate never
	// includes URLs, headers, credentials, or request content.
	return nil, newUtlsTLSFallbackError(errPrimary, errFallback)
}

// utlsTLSFallbackError is the terminal error after both protected transports
// fail before an HTTP response. Its Error string is deliberately a redacted
// diagnostic summary; Unwrap preserves the original causes for retry and
// credential rotation decisions.
type utlsTLSFallbackError struct {
	primary  error
	fallback error
}

func newUtlsTLSFallbackError(primary, fallback error) error {
	return &utlsTLSFallbackError{primary: primary, fallback: fallback}
}

func (e *utlsTLSFallbackError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("codex upstream transport unavailable after TLS fallback (uTLS: %s; standard TLS: %s)",
		safeUtlsTransportCategory(e.primary), safeUtlsTransportCategory(e.fallback))
}

func (e *utlsTLSFallbackError) Unwrap() []error {
	if e == nil {
		return nil
	}
	return []error{e.primary, e.fallback}
}

func safeUtlsTransportCategory(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || isConfiguredTLSHandshakeTimeoutErrorForDiagnostics(err) {
		return "timeout"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return "eof"
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "tls handshake") && strings.Contains(lower, "eof") {
		return "eof"
	}
	switch {
	case strings.Contains(lower, "connection reset"), strings.Contains(lower, "connection aborted"), strings.Contains(lower, "broken pipe"):
		return "connection_reset"
	case strings.Contains(lower, "connection refused"):
		return "connection_refused"
	case strings.Contains(lower, "stream closed"), strings.Contains(lower, "stream error"), strings.Contains(lower, "client conn is closed"):
		return "remote_close"
	default:
		return "transport"
	}
}

func isConfiguredTLSHandshakeTimeoutErrorForDiagnostics(err error) bool {
	return cliproxyexecutor.IsConfiguredTLSHandshakeTimeoutError(err)
}

// cloneRequestForUtlsFallback makes a fresh request body before the primary
// transport is allowed to consume it. A non-replayable body cannot safely be
// sent a second time, so the primary error is returned unchanged.
func cloneRequestForUtlsFallback(req *http.Request) (*http.Request, bool) {
	if req == nil {
		return nil, false
	}
	clone := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return clone, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, errGetBody := req.GetBody()
	if errGetBody != nil || body == nil {
		return nil, false
	}
	clone.Body = body
	clone.GetBody = req.GetBody
	return clone, true
}

// isTransientUtlsTransportError accepts only failures that happen before a
// response is available and are safe to retry on another TLS implementation.
// Caller cancellation and ordinary certificate/authentication failures stay on
// the uTLS path so the fallback does not hide a request decision.
func isTransientUtlsTransportError(err error) bool {
	if err == nil || cliproxyexecutor.IsConfiguredTLSHandshakeTimeoutError(err) {
		return err != nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr != nil && (dnsErr.IsTimeout || dnsErr.IsTemporary || dnsErr.Timeout()) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr != nil && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr != nil {
		return true
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "tls handshake") && (strings.Contains(lower, "eof") || strings.Contains(lower, "closed") || strings.Contains(lower, "reset") || strings.Contains(lower, "timeout")) {
		return true
	}
	for _, phrase := range []string{
		"connection reset", "connection refused", "connection aborted", "broken pipe",
		"stream error", "stream closed", "client conn is closed", "force closed",
		"unexpected eof", "temporary failure", "temporarily unavailable",
	} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// fallbackRoundTripper uses provider-specific TLS fingerprints for protected
// HTTPS hosts and falls back to the standard transport for all other requests.
//
// Each pooled branch may be resolved lazily on first use: a single request only
// ever takes one branch, and building both pools up front would spend two cache
// slots per key (evicting live standard pools with unused Anthropic pools).
type fallbackRoundTripper struct {
	mu          sync.Mutex
	anthropic   http.RoundTripper
	anthropicFn func() http.RoundTripper
	chrome      http.RoundTripper
	fallback    http.RoundTripper
	fallbackFn  func() http.RoundTripper
}

func (f *fallbackRoundTripper) anthropicRoundTripper() http.RoundTripper {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.anthropicFn != nil {
		if rt := f.anthropicFn(); rt != nil {
			f.anthropic = rt
		}
		f.anthropicFn = nil
	}
	return f.anthropic
}

func (f *fallbackRoundTripper) fallbackRoundTripper() http.RoundTripper {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fallbackFn != nil {
		if rt := f.fallbackFn(); rt != nil {
			f.fallback = rt
		}
		f.fallbackFn = nil
	}
	return f.fallback
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if IsAnthropicUpstreamURL(req.URL) {
		return f.anthropicRoundTripper().RoundTrip(req)
	}
	if req.URL.Scheme == "https" && strings.EqualFold(req.URL.Hostname(), "chatgpt.com") {
		return f.chrome.RoundTrip(req)
	}
	return f.fallbackRoundTripper().RoundTrip(req)
}

// NewUtlsHTTPClient creates an HTTP client using provider-specific TLS
// fingerprints for protected hosts. It uses Claude Code's Node/OpenSSL profile
// for Anthropic and a Chrome profile for ChatGPT, with a standard-transport
// fallback for other hosts.
func NewUtlsHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) (clientOut *http.Client) {
	// Carry the opt-in TLS establishment bound (requests
	// tls-handshake-timeout-seconds) on a request-scoped wrapper. This
	// client is shared, so the bound intentionally reaches both the Claude
	// Code Anthropic dial path and the Chrome ChatGPT/Codex dial path; the
	// standard fallback transport ignores the context value. The uTLS dial
	// paths read it per dial, so cached per-proxy transports need no rebuild
	// when the value changes. A disabled bound (0) leaves requests untouched.
	var handshakeTimeout time.Duration
	if cfg != nil {
		handshakeTimeout = cfg.TLSHandshakeTimeout()
	}
	defer func() {
		clientOut = cliproxyexecutor.GateHTTPClient(ctx, httptransport.Decorate(ctx, clientOut))
		if clientOut != nil && handshakeTimeout > 0 {
			clientOut.Transport = &tlsHandshakeTimeoutRoundTripper{base: clientOut.Transport, timeout: handshakeTimeout}
		}
	}()
	proxyURL := effectiveProxyURL(ctx, cfg, auth)

	var ctxRoundTripper http.RoundTripper
	if ctx != nil {
		ctxRoundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}

	var chromeRT http.RoundTripper = newUtlsRoundTripper(proxyURL)
	var anthropicRT http.RoundTripper = cachedClaudeCodeRoundTripper(proxyURL)
	var standardTransport http.RoundTripper = http.DefaultTransport
	var anthropicFn, fallbackFn func() http.RoundTripper
	if proxyURL != "" {
		fallbackFn = func() http.RoundTripper {
			if transport := pooledProxyTransport(proxyURL, cfg, auth); transport != nil {
				return transport
			}
			return standardTransport
		}
		// The Anthropic path has its own TLS fingerprint, so it needs its own pool kind.
		anthropicFn = func() http.RoundTripper {
			if transport := pooledClaudeCodeTransport(proxyURL, cfg, auth); transport != nil {
				return transport
			}
			return anthropicRT
		}
	} else if ctxRoundTripper != nil {
		chromeRT = ctxRoundTripper
		anthropicRT = ctxRoundTripper
		standardTransport = ctxRoundTripper
	} else {
		// A credential opt-in applies here too; an injected RoundTripper keeps priority.
		fallbackFn = func() http.RoundTripper {
			if transport := pooledProxyTransport("", cfg, auth); transport != nil {
				return transport
			}
			return standardTransport
		}
		anthropicFn = func() http.RoundTripper {
			if transport := pooledClaudeCodeTransport("", cfg, auth); transport != nil {
				return transport
			}
			return anthropicRT
		}
	}

	routes := &fallbackRoundTripper{
		anthropic:   anthropicRT,
		anthropicFn: anthropicFn,
		chrome:      chromeRT,
		fallback:    standardTransport,
		fallbackFn:  fallbackFn,
	}
	// ChatGPT/Codex keeps the uTLS Chrome fingerprint first. Its standard
	// transport is resolved lazily through the same proxy/direct route used by
	// all other fallback traffic.
	routes.chrome = &utlsChatGPTFallbackRoundTripper{
		primary:    chromeRT,
		fallbackFn: routes.fallbackRoundTripper,
	}
	client := &http.Client{
		Transport: routes,
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
