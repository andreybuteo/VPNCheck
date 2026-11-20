package probe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// BulkTransport returns an HTTP/1.1 transport for the speed test. It dials
// through the same route and address guard as the probes (system route with
// Happy Eyeballs, or the configured HTTP CONNECT / SOCKS5 proxy), verifies
// certificates against the same roots, keeps connections alive between the
// requests of one phase and never follows proxies from the environment.
// HTTP/2 is off on purpose: parallel streams over one connection would hide
// what several TCP connections can carry.
func (p *Prober) BulkTransport(parallel int) *http.Transport {
	if parallel <= 0 {
		parallel = 1
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return p.dial(ctx, h, port, &dialInfo{start: time.Now()})
		},
		TLSClientConfig:        &tls.Config{RootCAs: p.o.RootCAs, MinVersion: tls.VersionTLS12},
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           parallel * 2,
		MaxIdleConnsPerHost:    parallel,
		MaxConnsPerHost:        parallel + 1,
		IdleConnTimeout:        15 * time.Second,
		TLSHandshakeTimeout:    p.o.TLSTimeout,
		ResponseHeaderTimeout:  p.o.Timeout,
		MaxResponseHeaderBytes: int64(p.o.MaxHeader),
	}
}

// UserAgentString is the honest client name sent with every request.
func (p *Prober) UserAgentString() string { return p.o.UserAgent }

// RetryAfter parses both forms of the Retry-After header.
func RetryAfter(v string, now time.Time) (time.Time, bool) { return parseRetryAfter(v, now) }
