// Package probe is the network measurement engine. It performs one probe of
// one endpoint through the selected route, never follows redirects, never
// retries, verifies certificates, limits the body and honours the deadlines
// and cancellation from the caller.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/guard"
	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// Resolver is the name-resolution dependency (net.DefaultResolver in production).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Options configure a Prober.
type Options struct {
	Route  model.RouteConfig
	Family model.IPFamily
	Policy guard.Policy

	Timeout       time.Duration // whole probe; default app.ProbeTimeout
	TCPTimeout    time.Duration // default app.TCPTimeout
	TLSTimeout    time.Duration // default app.TLSTimeout
	FallbackDelay time.Duration // Happy Eyeballs delay; default 300ms
	MaxBody       int64         // default app.MaxBodyBytes
	MaxHeader     int           // default app.MaxHeaderBytes
	UserAgent     string

	// Resolver is nil for the system resolver. Tests inject a static one.
	Resolver Resolver
	// RootCAs is nil for the Windows trust store. Tests inject a test CA.
	// Certificate verification is never disabled.
	RootCAs *x509.CertPool

	// OnStage, if set, is called when a probe enters a new phase (for UI progress).
	OnStage func(stage model.Stage)

	// tlsPortOverride replaces port 443 for tls probes. It is unexported on
	// purpose: only in-package tests can set it; production always uses 443.
	tlsPortOverride string
}

// notify reports a stage transition to the optional listener.
func (p *Prober) notify(info *dialInfo, s model.Stage) {
	info.stage = s
	if p.o.OnStage != nil {
		p.o.OnStage(s)
	}
}

// Prober performs probes.
type Prober struct {
	o Options
}

// New returns a prober with defaults filled in.
func New(o Options) *Prober {
	if o.Timeout <= 0 {
		o.Timeout = app.ProbeTimeout
	}
	if o.TCPTimeout <= 0 {
		o.TCPTimeout = app.TCPTimeout
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = app.TLSTimeout
	}
	if o.FallbackDelay <= 0 {
		o.FallbackDelay = 300 * time.Millisecond
	}
	if o.MaxBody <= 0 {
		o.MaxBody = app.MaxBodyBytes
	}
	if o.MaxHeader <= 0 {
		o.MaxHeader = app.MaxHeaderBytes
	}
	if o.UserAgent == "" {
		o.UserAgent = "VPNCheck/" + app.Version + " (local reachability check)"
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Family == "" {
		o.Family = model.FamilyAuto
	}
	if o.Route.Mode == "" {
		o.Route.Mode = model.RouteSystem
	}
	return &Prober{o: o}
}

// Options returns the effective options.
func (p *Prober) Options() Options { return p.o }

// Probe runs a single probe of ep. The result is raw: the Outcome is filled by
// the classifier.
func (p *Prober) Probe(ctx context.Context, ep model.Endpoint) model.ProbeResult {
	start := time.Now()
	res := model.ProbeResult{
		EndpointID: ep.ID,
		GroupID:    ep.GroupID,
		Host:       ep.Host,
		URL:        ep.URL,
		Kind:       ep.Kind,
		Attempt:    1,
		StartedAt:  start.UTC(),
		Route:      p.o.Route,
		IPFamily:   p.o.Family,
	}
	ctx, cancel := context.WithTimeout(ctx, p.o.Timeout)
	defer cancel()

	switch ep.Kind {
	case model.KindHTTPS:
		p.probeHTTPS(ctx, start, ep, &res)
	default:
		p.probeTLS(ctx, start, ep, &res)
	}
	res.Timings.TotalMs = model.Ms(time.Since(start))
	return res
}

func (p *Prober) tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		RootCAs:    p.o.RootCAs, // nil = system roots
		MinVersion: tls.VersionTLS12,
	}
}

func applyDialInfo(res *model.ProbeResult, info *dialInfo) {
	res.Timings.DNSMs = info.dnsMs
	res.Timings.TCPMs = info.tcpMs
	res.Timings.ProxyMs = info.proxyMs
	res.Transport.ResolvedAddrs = info.resolved
	res.Transport.PeerAddr = info.peer
	res.Transport.PeerFamily = info.family
	res.Transport.FamilyProven = info.proven
}

func fillTLS(t *model.Transport, cs tls.ConnectionState) {
	t.CertVerified = true
	t.TLSVersion = tls.VersionName(cs.Version)
	t.ALPN = cs.NegotiatedProtocol
	if len(cs.PeerCertificates) > 0 {
		c := cs.PeerCertificates[0]
		subj := c.Subject.CommonName
		if subj == "" && len(c.DNSNames) > 0 {
			subj = c.DNSNames[0]
		}
		t.CertSubject = sanitizeText(subj, 120)
		t.CertIssuer = sanitizeText(c.Issuer.CommonName, 120)
		t.CertNotAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
}

func setFailure(res *model.ProbeResult, stage model.Stage, err error) {
	kind, text := classifyErr(err)
	res.Transport.OK = false
	res.Transport.FailedStage = stage
	res.Transport.ErrorKind = kind
	res.Transport.ErrorText = text
}

// probeTLS: DNS → TCP 443 → TLS handshake with SNI and certificate verification → close.
func (p *Prober) probeTLS(ctx context.Context, start time.Time, ep model.Endpoint, res *model.ProbeResult) {
	info := &dialInfo{start: start}
	port := "443"
	if p.o.tlsPortOverride != "" {
		port = p.o.tlsPortOverride
	}
	conn, err := p.dial(ctx, ep.Host, port, info)
	applyDialInfo(res, info)
	if err != nil {
		setFailure(res, info.stage, err)
		return
	}
	defer conn.Close()

	p.notify(info, model.StageTLS)
	tc := tls.Client(conn, p.tlsConfig(ep.Host))
	hctx, cancel := context.WithTimeout(ctx, p.o.TLSTimeout)
	defer cancel()
	t0 := time.Now()
	err = tc.HandshakeContext(hctx)
	res.Timings.TLSMs = model.Ms(time.Since(t0))
	if err != nil {
		if hctx.Err() != nil && ctx.Err() == nil {
			err = context.DeadlineExceeded
		}
		setFailure(res, model.StageTLS, err)
		return
	}
	res.Timings.TLSReadyMs = model.Ms(time.Since(start))
	fillTLS(&res.Transport, tc.ConnectionState())
	res.Transport.OK = true
	res.Transport.FailedStage = model.StageDone
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_ = tc.Close() // sends close_notify, then the deferred conn.Close
}

// probeHTTPS performs exactly one GET and measures every phase on that request.
func (p *Prober) probeHTTPS(ctx context.Context, start time.Time, ep model.Endpoint, res *model.ProbeResult) {
	u, err := url.Parse(ep.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		setFailure(res, model.StageNone, errors.New(i18n.T("некорректный URL контрольной точки")))
		return
	}
	host := u.Hostname()
	res.Host = host

	info := &dialInfo{start: start}
	var (
		mu       sync.Mutex
		dialed   bool
		tlsStart time.Time
		tlsDone  time.Time
		tlsState *tls.ConnectionState
		tlsErr   error
		first    time.Time
	)
	transport := &http.Transport{
		Proxy: nil, // proxies are handled inside dial; never ProxyFromEnvironment
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			if dialed {
				mu.Unlock()
				return nil, errors.New(i18n.T("повторное соединение в пределах одной пробы не допускается"))
			}
			dialed = true
			mu.Unlock()
			h, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return p.dial(dctx, h, port, info)
		},
		TLSClientConfig:        p.tlsConfig(host),
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: int64(p.o.MaxHeader),
		TLSHandshakeTimeout:    p.o.TLSTimeout,
		ResponseHeaderTimeout:  p.o.Timeout,
	}
	defer transport.CloseIdleConnections()

	trace := &httptrace.ClientTrace{
		TLSHandshakeStart: func() {
			mu.Lock()
			tlsStart = time.Now()
			p.notify(info, model.StageTLS)
			mu.Unlock()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			mu.Lock()
			tlsDone = time.Now()
			if err == nil {
				c := cs
				tlsState = &c
				p.notify(info, model.StageHTTP)
			} else {
				tlsErr = err
			}
			mu.Unlock()
		},
		GotFirstResponseByte: func() {
			mu.Lock()
			first = time.Now()
			mu.Unlock()
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, u.String(), nil)
	if err != nil {
		setFailure(res, model.StageNone, err)
		return
	}
	req.Header.Set("User-Agent", p.o.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	for k, v := range ep.Headers {
		if allowedRequestHeader(k) {
			req.Header.Set(k, sanitizeText(v, 200))
		}
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)

	mu.Lock()
	applyDialInfo(res, info)
	stage := info.stage
	ts, td, fb := tlsStart, tlsDone, first
	state, terr := tlsState, tlsErr
	mu.Unlock()

	if !ts.IsZero() && !td.IsZero() {
		res.Timings.TLSMs = model.Ms(td.Sub(ts))
	}
	if state != nil {
		res.Timings.TLSReadyMs = model.Ms(td.Sub(start))
		fillTLS(&res.Transport, *state)
	}
	if err != nil {
		if stage == model.StageTLS && terr != nil {
			err = terr
		}
		if stage == model.StageNone {
			stage = model.StageDNS
		}
		if ctx.Err() != nil && !errors.Is(err, context.Canceled) {
			err = ctx.Err()
		}
		setFailure(res, stage, err)
		return
	}
	defer resp.Body.Close()
	res.Transport.OK = true
	res.Transport.FailedStage = model.StageDone
	if resp.TLS != nil && state == nil {
		fillTLS(&res.Transport, *resp.TLS)
	}
	if !fb.IsZero() {
		res.Timings.TTFBMs = model.Ms(fb.Sub(start))
	}

	h := &model.HTTPResult{
		Status:      resp.StatusCode,
		Proto:       resp.Proto,
		Location:    safeLocation(resp.Header.Get("Location")),
		Server:      sanitizeText(resp.Header.Get("Server"), 60),
		ContentType: sanitizeText(resp.Header.Get("Content-Type"), 60),
		RetryAfter:  sanitizeText(resp.Header.Get("Retry-After"), 40),
	}
	if reset, ok := rateLimitReset(resp.Header, time.Now()); ok {
		h.RateLimitReset = reset.UTC().Format(time.RFC3339)
	}
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, p.o.MaxBody+1))
	if int64(len(body)) > p.o.MaxBody {
		h.BodyLimit = true
		body = body[:p.o.MaxBody]
	}
	h.BytesRead = int64(len(body))
	if rerr != nil {
		if ctx.Err() != nil {
			rerr = ctx.Err()
		}
		_, text := classifyErr(rerr)
		h.BodyError = text
	}
	h.Captcha = detectCaptcha(resp.StatusCode, resp.Header, body)
	h.GeoBlocked, h.GeoSignature = detectGeoBlock(resp.StatusCode, body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.BodySnippet = bodySnippet(body, 240)
	}
	res.HTTP = h
}

// FetchSmall performs one GET through the configured route and returns the
// status and at most limit bytes of the body. It exists for the optional
// external-IP feature only: same guard, deadlines, no redirects, no retries.
func (p *Prober) FetchSmall(ctx context.Context, rawURL string, limit int64) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return 0, nil, errors.New(i18n.T("некорректный URL"))
	}
	ctx, cancel := context.WithTimeout(ctx, p.o.Timeout)
	defer cancel()
	info := &dialInfo{start: time.Now()}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dctx context.Context, _, addr string) (net.Conn, error) {
			h, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return p.dial(dctx, h, port, info)
		},
		TLSClientConfig:        p.tlsConfig(u.Hostname()),
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: int64(p.o.MaxHeader),
		TLSHandshakeTimeout:    p.o.TLSTimeout,
		ResponseHeaderTimeout:  p.o.Timeout,
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", p.o.UserAgent)
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.1")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		_, text := classifyErr(err)
		return 0, nil, errors.New(text)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, body, nil
}
