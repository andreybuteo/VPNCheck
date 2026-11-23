package probe

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"vpncheck/internal/guard"
	"vpncheck/internal/model"
)

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok"))
}

func TestTLSProbeSuccess(t *testing.T) {
	s := newTLSServer(t, okHandler)
	p := New(testOptions(s, loopbackResolver("example.com")))
	// TLS probes always use 443; point the endpoint at the test port by using a
	// resolver trick is impossible, so we exercise the TLS path through dial+handshake
	// with the server port via an https endpoint's host:port instead.
	ep := model.Endpoint{ID: "tls1", GroupID: "g", Host: "example.com", Kind: model.KindTLS}
	// Redirect port 443 to the test port for this test only.
	p.o.tlsPortOverride = s.port
	r := p.Probe(context.Background(), ep)
	if !r.Transport.OK {
		t.Fatalf("expected OK, got %+v", r.Transport)
	}
	if r.HTTP != nil {
		t.Fatal("tls probe must not produce an HTTP result")
	}
	if ms(r.Timings.DNSMs) < 0 || ms(r.Timings.TCPMs) < 0 || ms(r.Timings.TLSMs) < 0 || ms(r.Timings.TLSReadyMs) < 0 {
		t.Fatalf("timings missing: %+v", r.Timings)
	}
	if r.Timings.TTFBMs != nil || r.Timings.ProxyMs != nil {
		t.Fatalf("ttfb/proxy must be null for tls probe: %+v", r.Timings)
	}
	if r.Transport.PeerFamily != "ipv4" || !r.Transport.FamilyProven || !strings.HasPrefix(r.Transport.PeerAddr, "127.0.0.1:") {
		t.Fatalf("peer info wrong: %+v", r.Transport)
	}
	if !r.Transport.CertVerified || r.Transport.TLSVersion == "" || r.Transport.CertNotAfter == "" {
		t.Fatalf("tls info missing: %+v", r.Transport)
	}
	if s.reqs.Load() != 0 {
		t.Fatal("tls probe must not send an HTTP request")
	}
}

func TestHTTPSProbeSuccessTimingsAndSingleConnection(t *testing.T) {
	s := newTLSServer(t, okHandler)
	p := New(testOptions(s, loopbackResolver("example.com")))
	r := p.Probe(context.Background(), httpsEndpoint(s, "/ping"))
	if !r.Transport.OK || r.HTTP == nil || r.HTTP.Status != 200 {
		t.Fatalf("unexpected result: %+v http=%+v", r.Transport, r.HTTP)
	}
	tm := r.Timings
	for name, v := range map[string]*float64{"dns": tm.DNSMs, "tcp": tm.TCPMs, "tls": tm.TLSMs, "tlsReady": tm.TLSReadyMs, "ttfb": tm.TTFBMs, "total": tm.TotalMs} {
		if v == nil {
			t.Errorf("%s must be measured", name)
		}
	}
	if tm.ProxyMs != nil {
		t.Error("proxy time must be null in direct mode")
	}
	if ms(tm.TLSReadyMs) < ms(tm.TLSMs) || ms(tm.TTFBMs) < ms(tm.TLSReadyMs) || ms(tm.TotalMs) < ms(tm.TTFBMs) {
		t.Errorf("timing order violated: %+v", tm)
	}
	if r.HTTP.BytesRead != 2 || r.HTTP.BodyLimit {
		t.Errorf("body accounting wrong: %+v", r.HTTP)
	}
	if r.HTTP.Proto != "HTTP/2.0" || r.Transport.ALPN != "h2" {
		t.Errorf("expected h2, got proto=%s alpn=%s", r.HTTP.Proto, r.Transport.ALPN)
	}
	if s.conns.Load() != 1 || s.reqs.Load() != 1 {
		t.Errorf("want exactly 1 connection and 1 request, got %d/%d", s.conns.Load(), s.reqs.Load())
	}
}

func TestRedirectIsNotFollowedAndLocationIsSanitised(t *testing.T) {
	s := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "https://example.com/next?token=SECRET#frag")
			w.WriteHeader(301)
			return
		}
		w.WriteHeader(200)
	})
	p := New(testOptions(s, loopbackResolver("example.com")))
	r := p.Probe(context.Background(), httpsEndpoint(s, "/start"))
	if r.HTTP == nil || r.HTTP.Status != 301 {
		t.Fatalf("want 301, got %+v", r.HTTP)
	}
	if strings.Contains(r.HTTP.Location, "SECRET") || r.HTTP.Location != "https://example.com/next…" {
		t.Fatalf("location not sanitised: %q", r.HTTP.Location)
	}
	if s.reqs.Load() != 1 {
		t.Fatalf("redirect must not be followed: %d requests", s.reqs.Load())
	}
}

func TestBodyLimit(t *testing.T) {
	big := strings.Repeat("x", 50_000)
	s := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(big)) })
	o := testOptions(s, loopbackResolver("example.com"))
	o.MaxBody = 4096
	p := New(o)
	r := p.Probe(context.Background(), httpsEndpoint(s, "/big"))
	if r.HTTP == nil || !r.HTTP.BodyLimit || r.HTTP.BytesRead != 4096 {
		t.Fatalf("body limit not applied: %+v", r.HTTP)
	}
}

func TestHungBodyHonoursDeadline(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-release
	})
	o := testOptions(s, loopbackResolver("example.com"))
	o.Timeout = 600 * time.Millisecond
	p := New(o)
	t0 := time.Now()
	r := p.Probe(context.Background(), httpsEndpoint(s, "/hang"))
	el := time.Since(t0)
	if el > 3*time.Second {
		t.Fatalf("probe did not stop at deadline: %v", el)
	}
	if r.HTTP == nil || r.HTTP.Status != 200 || r.HTTP.BodyError == "" {
		t.Fatalf("want 200 with body error, got %+v", r.HTTP)
	}
	if r.Timings.TTFBMs == nil {
		t.Fatal("ttfb must be measured even if the body hangs")
	}
}

func TestSlowHeadersTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { <-release })
	o := testOptions(s, loopbackResolver("example.com"))
	o.Timeout = 500 * time.Millisecond
	p := New(o)
	r := p.Probe(context.Background(), httpsEndpoint(s, "/slow"))
	if r.Transport.OK || r.Transport.FailedStage != model.StageHTTP || r.Transport.ErrorKind != model.ErrTimeout {
		t.Fatalf("want http timeout, got %+v", r.Transport)
	}
	if r.Timings.TLSReadyMs == nil || r.Timings.TTFBMs != nil {
		t.Fatalf("tls should be measured, ttfb null: %+v", r.Timings)
	}
}

func TestCancellation(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { <-release })
	p := New(testOptions(s, loopbackResolver("example.com")))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	t0 := time.Now()
	r := p.Probe(ctx, httpsEndpoint(s, "/slow"))
	if time.Since(t0) > 2*time.Second {
		t.Fatal("cancel did not stop the probe promptly")
	}
	if r.Transport.ErrorKind != model.ErrCancelled {
		t.Fatalf("want cancelled, got %+v", r.Transport)
	}
}

func TestDNSFailures(t *testing.T) {
	s := newTLSServer(t, okHandler)
	// not found
	p := New(testOptions(s, loopbackResolver("other.example.com")))
	r := p.Probe(context.Background(), httpsEndpoint(s, "/"))
	if r.Transport.FailedStage != model.StageDNS || r.Transport.ErrorKind != model.ErrDNS {
		t.Fatalf("want dns not-found, got %+v", r.Transport)
	}
	if r.Timings.DNSMs == nil || r.Timings.TCPMs != nil {
		t.Fatalf("dns measured, tcp null expected: %+v", r.Timings)
	}
	// timeout
	o := testOptions(s, &staticResolver{block: true})
	o.Timeout = 300 * time.Millisecond
	p = New(o)
	r = p.Probe(context.Background(), httpsEndpoint(s, "/"))
	if r.Transport.FailedStage != model.StageDNS || r.Transport.ErrorKind != model.ErrTimeout {
		t.Fatalf("want dns timeout, got %+v", r.Transport)
	}
}

func TestTCPRefused(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	s := newTLSServer(t, okHandler)
	p := New(testOptions(s, loopbackResolver("example.com")))
	ep := httpsEndpoint(s, "/")
	ep.URL = "https://example.com:" + port + "/"
	r := p.Probe(context.Background(), ep)
	if r.Transport.FailedStage != model.StageTCP || r.Transport.ErrorKind != model.ErrRefused {
		t.Fatalf("want tcp refused, got %+v", r.Transport)
	}
	if r.Timings.TCPMs == nil || r.Timings.TLSMs != nil {
		t.Fatalf("tcp measured, tls null expected: %+v", r.Timings)
	}
}

func TestGuardBlocksLoopbackAndPrivateBeforeConnect(t *testing.T) {
	s := newTLSServer(t, okHandler)
	o := testOptions(s, &staticResolver{m: map[string][]net.IPAddr{
		"example.com": {{IP: net.IPv4(10, 0, 0, 1)}, {IP: net.IPv4(127, 0, 0, 1)}},
	}})
	o.Policy = guard.Default() // production policy
	p := New(o)
	r := p.Probe(context.Background(), httpsEndpoint(s, "/"))
	if r.Transport.ErrorKind != model.ErrBlockedAddr {
		t.Fatalf("want blocked address, got %+v", r.Transport)
	}
	if s.conns.Load() != 0 {
		t.Fatal("no connection may be attempted to a blocked address")
	}
	// Even when the resolver hands out a permitted address, the Control hook
	// re-checks the exact IP being dialed (rebinding defence).
	if err := guard.Default().Control("tcp", "127.0.0.1:443", nil); err == nil {
		t.Fatal("Control must block loopback")
	}
}

func TestFamilyFilter(t *testing.T) {
	s := newTLSServer(t, okHandler)
	o := testOptions(s, loopbackResolver("example.com"))
	o.Family = model.FamilyV6
	p := New(o)
	r := p.Probe(context.Background(), httpsEndpoint(s, "/"))
	if r.Transport.FailedStage != model.StageDNS || r.Transport.ErrorKind != model.ErrDNS || !strings.Contains(r.Transport.ErrorText, "семейства") {
		t.Fatalf("want family error, got %+v", r.Transport)
	}
}

func TestCertificateErrors(t *testing.T) {
	s := newTLSServer(t, okHandler)
	// Unknown CA: no test root installed → must fail, never skip verification.
	o := testOptions(s, loopbackResolver("example.com"))
	o.RootCAs = nil
	r := New(o).Probe(context.Background(), httpsEndpoint(s, "/"))
	if r.Transport.FailedStage != model.StageTLS || r.Transport.ErrorKind != model.ErrTLSCert {
		t.Fatalf("want tls cert error (unknown CA), got %+v", r.Transport)
	}
	if r.Timings.TLSMs == nil || r.Timings.TLSReadyMs != nil {
		t.Fatalf("tls attempted but not ready: %+v", r.Timings)
	}
	// Hostname mismatch (the test certificate covers example.com and *.example.com only).
	o = testOptions(s, loopbackResolver("mismatch.example.org"))
	ep := httpsEndpoint(s, "/")
	ep.URL = "https://mismatch.example.org:" + s.port + "/"
	r = New(o).Probe(context.Background(), ep)
	if r.Transport.FailedStage != model.StageTLS || r.Transport.ErrorKind != model.ErrTLSCert {
		t.Fatalf("want tls cert error (hostname), got %+v", r.Transport)
	}
}

func TestHTTPConnectProxy(t *testing.T) {
	s := newTLSServer(t, okHandler)
	paddr, tunnels := startConnectProxy(t, proxyOpts{resolve: loopbackAll})
	o := testOptions(s, failResolver{t})
	o.Route = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: paddr}
	p := New(o)
	r := p.Probe(context.Background(), httpsEndpoint(s, "/via-proxy"))
	if !r.Transport.OK || r.HTTP == nil || r.HTTP.Status != 200 {
		t.Fatalf("proxy probe failed: %+v http=%+v", r.Transport, r.HTTP)
	}
	if r.Timings.DNSMs != nil {
		t.Error("dns must be null (resolved remotely)")
	}
	if r.Timings.ProxyMs == nil || r.Timings.TCPMs == nil || r.Timings.TLSMs == nil {
		t.Errorf("proxy/tcp/tls must be measured: %+v", r.Timings)
	}
	if r.Transport.FamilyProven || r.Transport.PeerAddr != paddr {
		t.Errorf("peer must be the proxy and family unproven: %+v", r.Transport)
	}
	if tunnels.Load() != 1 {
		t.Errorf("want 1 tunnel, got %d", tunnels.Load())
	}
	// TLS-only through the proxy as well.
	ep := model.Endpoint{ID: "tls-proxy", Host: "example.com", Kind: model.KindTLS}
	p.o.tlsPortOverride = s.port
	r = p.Probe(context.Background(), ep)
	if !r.Transport.OK || r.Timings.ProxyMs == nil {
		t.Fatalf("tls via proxy failed: %+v", r.Transport)
	}
}

func TestSOCKS5Proxy(t *testing.T) {
	s := newTLSServer(t, okHandler)
	paddr, tunnels := startSocks5Proxy(t, proxyOpts{resolve: loopbackAll})
	o := testOptions(s, failResolver{t})
	o.Route = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxySOCKS5, ProxyAddr: paddr}
	r := New(o).Probe(context.Background(), httpsEndpoint(s, "/socks"))
	if !r.Transport.OK || r.HTTP == nil || r.HTTP.Status != 200 {
		t.Fatalf("socks probe failed: %+v http=%+v", r.Transport, r.HTTP)
	}
	if r.Timings.DNSMs != nil || r.Timings.ProxyMs == nil {
		t.Errorf("dns null / proxy measured expected: %+v", r.Timings)
	}
	if tunnels.Load() != 1 {
		t.Errorf("want 1 tunnel, got %d", tunnels.Load())
	}
}

func TestProxyAuthRequiredIsRejectedClearly(t *testing.T) {
	s := newTLSServer(t, okHandler)
	for _, kind := range []model.ProxyKind{model.ProxyHTTP, model.ProxySOCKS5} {
		var paddr string
		if kind == model.ProxyHTTP {
			paddr, _ = startConnectProxy(t, proxyOpts{authRequired: true, resolve: loopbackAll})
		} else {
			paddr, _ = startSocks5Proxy(t, proxyOpts{authRequired: true, resolve: loopbackAll})
		}
		o := testOptions(s, failResolver{t})
		o.Route = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: kind, ProxyAddr: paddr}
		r := New(o).Probe(context.Background(), httpsEndpoint(s, "/"))
		if r.Transport.FailedStage != model.StageProxy || r.Transport.ErrorKind != model.ErrProxy || !strings.Contains(r.Transport.ErrorText, "авторизац") {
			t.Errorf("%s: want proxy auth error, got %+v", kind, r.Transport)
		}
		if s.conns.Load() != 0 {
			t.Errorf("%s: no direct fallback allowed", kind)
		}
	}
}

func TestProxyDownNeverFallsBackToDirect(t *testing.T) {
	s := newTLSServer(t, okHandler)
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	o := testOptions(s, loopbackResolver("example.com")) // a working resolver is available, but must not be used
	o.Route = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: dead}
	r := New(o).Probe(context.Background(), httpsEndpoint(s, "/"))
	if r.Transport.OK || r.Transport.FailedStage != model.StageTCP || r.Transport.ErrorKind != model.ErrProxy {
		t.Fatalf("want proxy tcp failure, got %+v", r.Transport)
	}
	if s.conns.Load() != 0 {
		t.Fatal("must not fall back to a direct connection when the proxy is down")
	}
}

func TestSlowProxyTimesOut(t *testing.T) {
	s := newTLSServer(t, okHandler)
	paddr, _ := startConnectProxy(t, proxyOpts{delay: 5 * time.Second, resolve: loopbackAll})
	o := testOptions(s, failResolver{t})
	o.TCPTimeout = 300 * time.Millisecond
	o.Timeout = 2 * time.Second
	o.Route = model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: paddr}
	t0 := time.Now()
	r := New(o).Probe(context.Background(), httpsEndpoint(s, "/"))
	if time.Since(t0) > 1500*time.Millisecond {
		t.Fatalf("slow proxy not cut at TCP/proxy timeout: %v", time.Since(t0))
	}
	if r.Transport.FailedStage != model.StageProxy || r.Transport.ErrorKind != model.ErrProxy || !strings.Contains(r.Transport.ErrorText, "тайм-аут") {
		t.Fatalf("want proxy timeout, got %+v", r.Transport)
	}
}

func TestRateLimitHeadersAndCaptcha(t *testing.T) {
	s := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/429":
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(429)
		case "/403":
			w.Header().Set("cf-mitigated", "challenge")
			w.WriteHeader(403)
			w.Write([]byte("<title>Just a moment...</title>"))
		}
	})
	p := New(testOptions(s, loopbackResolver("example.com")))
	r := p.Probe(context.Background(), httpsEndpoint(s, "/429"))
	if r.HTTP == nil || r.HTTP.Status != 429 || r.HTTP.RetryAfter != "120" || r.HTTP.RateLimitReset == "" {
		t.Fatalf("429 handling wrong: %+v", r.HTTP)
	}
	reset, _ := time.Parse(time.RFC3339, r.HTTP.RateLimitReset)
	if d := time.Until(reset); d < 100*time.Second || d > 125*time.Second {
		t.Fatalf("reset not ~120s ahead: %v", d)
	}
	r = p.Probe(context.Background(), httpsEndpoint(s, "/403"))
	if r.HTTP == nil || r.HTTP.Status != 403 || !r.HTTP.Captcha {
		t.Fatalf("captcha not detected: %+v", r.HTTP)
	}
}

func TestHelpers(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	if ts, ok := parseRetryAfter("30", now); !ok || !ts.Equal(now.Add(30*time.Second)) {
		t.Error("retry-after seconds")
	}
	if ts, ok := parseRetryAfter("Sun, 13 Sep 2026 12:05:00 GMT", now); !ok || !ts.Equal(now.Add(5*time.Minute)) {
		t.Errorf("retry-after date: %v %v", ts, ok)
	}
	if _, ok := parseRetryAfter("garbage", now); ok {
		t.Error("garbage retry-after accepted")
	}
	h := http.Header{}
	h.Set("X-RateLimit-Reset", "1789400000") // epoch, ~27h after now
	if ts, ok := rateLimitReset(h, now); !ok || ts.Unix() != 1789400000 {
		t.Error("x-ratelimit-reset epoch")
	}
	h = http.Header{}
	h.Set("X-RateLimit-Reset-Requests", "6m0s")
	if ts, ok := rateLimitReset(h, now); !ok || !ts.Equal(now.Add(6*time.Minute)) {
		t.Error("openai duration reset")
	}
	if detectCaptcha(200, http.Header{}, []byte("captcha")) {
		t.Error("captcha must not trigger on 200")
	}
	if got := safeLocation("https://a.example/x?sig=abc#frag"); got != "https://a.example/x…" {
		t.Errorf("safeLocation: %q", got)
	}
	if got := sanitizeText("a\x00b\r\n\tc", 10); got != "ab c" {
		t.Errorf("sanitizeText: %q", got)
	}
	if got := sanitizeText(strings.Repeat("x", 20), 5); got != "xxxxx…" {
		t.Errorf("sanitizeText cap: %q", got)
	}
}

func TestSmallObservationHonoursResponseMetadataAndReadErrors(t *testing.T) {
	s := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "90")
		w.Header().Set("Content-Length", "30")
		w.Header().Set("cf-mitigated", "challenge")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("partial"))
	})
	p := New(testOptions(s, nil))
	result, _, err := p.FetchSmall(context.Background(), s.URL, 4096)
	if err == nil || result.Status != 429 || !result.Captcha || result.RateLimitReset == "" {
		t.Fatalf("incomplete observation: %+v, error %v", result, err)
	}
}
