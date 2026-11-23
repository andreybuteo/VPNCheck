// Package speed measures latency, download and upload through the selected
// route (3.0). It is deliberately gentle with the public servers it uses:
// short phases, a byte cap per phase, few parallel connections, an honest
// User-Agent, no retries, and an immediate stop with a persisted pause on
// HTTP 429, 403 or a Cloudflare challenge (see Runner and package limiter).
package speed

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/i18n"
	"vpncheck/internal/probe"
)

// Server is a speed-test target.
type Server struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind: "cloudflare" (latency + download + upload, node chosen by the
	// network) or "file" (download of a fixed test file in a known city).
	Kind string `json:"kind"`
	Host string `json:"host"`
	// BaseURL is https://host (tests point it at a local server).
	BaseURL string `json:"-"`
	// FilePath and FileSize describe the test file for Kind "file".
	FilePath string `json:"-"`
	FileSize int64  `json:"-"`
	Note     string `json:"note"`
}

// Servers are the built-in targets. Cloudflare's endpoints are the ones its
// own page speed.cloudflare.com uses; Hetzner documents fsn1-speed.hetzner.com
// for this purpose, hel1 is its Helsinki twin.
var Servers = []Server{
	{ID: "cloudflare", Name: "Cloudflare — ближайший узел", Kind: "cloudflare", Host: "speed.cloudflare.com", BaseURL: "https://speed.cloudflare.com",
		Note: "Узел выбирает сеть: обычно ближайший к точке выхода трафика (к VPN-серверу). Код города показывается в результате."},
	{ID: "hetzner-fsn1", Name: "Hetzner — Фалькенштейн (Германия)", Kind: "file", Host: "fsn1-speed.hetzner.com", BaseURL: "https://fsn1-speed.hetzner.com",
		FilePath: "/100MB.bin", FileSize: 100 << 20, Note: "Неподвижная точка в Германии. Только скачивание."},
	{ID: "hetzner-hel1", Name: "Hetzner — Хельсинки (Финляндия)", Kind: "file", Host: "hel1-speed.hetzner.com", BaseURL: "https://hel1-speed.hetzner.com",
		FilePath: "/100MB.bin", FileSize: 100 << 20, Note: "Неподвижная точка в Финляндии. Только скачивание."},
}

// ServerByID finds a built-in server.
func ServerByID(id string) (Server, bool) {
	for _, s := range Servers {
		if s.ID == id {
			return s, true
		}
	}
	return Server{}, false
}

// Latency is the result of the latency phase.
type Latency struct {
	MedianMs float64
	JitterMs float64
	Samples  int
	Colo     string
}

// Throughput is the result of a download or upload phase.
type Throughput struct {
	Mbps       float64
	Bytes      int64
	Seconds    float64
	CapReached bool
}

// Live is called about four times a second during a transfer phase.
type Live func(mbps float64, bytes int64, elapsed time.Duration)

// Meter performs the three phases. The real one talks HTTPS; the demo one
// fabricates numbers without any network access.
type Meter interface {
	// ExitIP asks Cloudflare's trace page which public IP the route exits from.
	ExitIP(ctx context.Context) (ip, country string, err error)
	Latency(ctx context.Context, srv Server) (Latency, error)
	Download(ctx context.Context, srv Server, live Live) (Throughput, error)
	Upload(ctx context.Context, srv Server, live Live) (Throughput, error)
	Close()
}

// HTTPError is a refusal by the server. Stop reports whether the server must be
// paused (429, 403, Cloudflare challenge) instead of merely failing the phase.
type HTTPError struct {
	Host      string
	Status    int
	Challenge bool
	Until     time.Time // from Retry-After, zero if absent
}

func (e *HTTPError) Error() string {
	switch {
	case e.Challenge:
		return i18n.T("%s запросил проверку «человек ли вы» (HTTP %d)", e.Host, e.Status)
	case e.Status == http.StatusTooManyRequests:
		return i18n.T("%s ограничил частоту запросов (HTTP 429)", e.Host)
	case e.Status == http.StatusForbidden:
		return i18n.T("%s отказал в доступе (HTTP 403)", e.Host)
	}
	return i18n.T("%s ответил HTTP %d", e.Host, e.Status)
}

// Stop reports whether the server should be paused.
func (e *HTTPError) Stop() bool {
	return e.Challenge || e.Status == http.StatusTooManyRequests || e.Status == http.StatusForbidden
}

// Config tunes the real meter; zero values take the app defaults.
type Config struct {
	Phase     time.Duration
	Warmup    time.Duration
	Parallel  int
	DownCap   int64
	UpCap     int64
	Samples   int
	UserAgent string
	Now       func() time.Time
}

func (c *Config) fill() {
	if c.Phase <= 0 {
		c.Phase = app.SpeedPhase
	}
	if c.Warmup <= 0 {
		c.Warmup = app.SpeedWarmup
	}
	if c.Parallel <= 0 {
		c.Parallel = app.SpeedParallel
	}
	if c.DownCap <= 0 {
		c.DownCap = app.SpeedDownCap
	}
	if c.UpCap <= 0 {
		c.UpCap = app.SpeedUpCap
	}
	if c.Samples <= 0 {
		c.Samples = app.SpeedLatencySamples
	}
	if c.UserAgent == "" {
		c.UserAgent = "VPNCheck/" + app.Version + " (speed test, one run on user request)"
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// HTTPMeter is the real meter.
type HTTPMeter struct {
	c      Config
	tr     *http.Transport
	client *http.Client
}

// NewHTTPMeter builds a meter on a prober's route (system or proxy).
func NewHTTPMeter(p *probe.Prober, c Config) *HTTPMeter {
	c.fill()
	if c.UserAgent == "" {
		c.UserAgent = p.UserAgentString()
	}
	tr := p.BulkTransport(c.Parallel)
	return &HTTPMeter{c: c, tr: tr, client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Close drops idle connections.
func (m *HTTPMeter) Close() { m.tr.CloseIdleConnections() }

// ExitIP performs one small GET to the same trace page the probe runs use.
func (m *HTTPMeter) ExitIP(ctx context.Context) (string, string, error) {
	rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := m.newReq(rctx, http.MethodGet, TraceURL, nil, 0)
	if err != nil {
		return "", "", err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if refusal := m.check(Server{Host: req.URL.Hostname()}, resp, http.StatusOK); refusal != nil {
		return "", "", refusal
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", "", err
	}
	ip, loc := parseTraceIP(string(body))
	if ip == "" {
		return "", "", errors.New(i18n.T("в ответе нет ip="))
	}
	return ip, loc, nil
}

func (m *HTTPMeter) newReq(ctx context.Context, method, url string, body io.Reader, size int64) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", m.c.UserAgent)
	req.Header.Set("Accept", "*/*")
	if body != nil {
		req.ContentLength = size
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	return req, nil
}

func (m *HTTPMeter) check(srv Server, resp *http.Response, ok ...int) error {
	challenge := strings.EqualFold(resp.Header.Get("cf-mitigated"), "challenge")
	for _, s := range ok {
		if resp.StatusCode == s && !challenge {
			return nil
		}
	}
	e := &HTTPError{Host: srv.Host, Status: resp.StatusCode, Challenge: challenge}
	if t, ok := probe.RetryAfter(resp.Header.Get("Retry-After"), m.c.Now()); ok {
		e.Until = t
	}
	return e
}

// Latency sends Samples empty requests over one kept-alive connection (after
// one uncounted request that opens it) and takes the time from the request
// written to the first response byte, minus the server's own processing time
// when Cloudflare reports it in Server-Timing.
func (m *HTTPMeter) Latency(ctx context.Context, srv Server) (Latency, error) {
	var out Latency
	if srv.Kind != "cloudflare" {
		return out, errors.New(i18n.T("задержка измеряется только через Cloudflare"))
	}
	url := srv.BaseURL + "/__down?bytes=0"
	var samples []float64
	for i := 0; i <= m.c.Samples; i++ {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		var timingMu sync.Mutex
		var wrote, first time.Time
		trace := &httptrace.ClientTrace{
			WroteRequest: func(httptrace.WroteRequestInfo) {
				timingMu.Lock()
				wrote = time.Now()
				timingMu.Unlock()
			},
			GotFirstResponseByte: func() {
				timingMu.Lock()
				first = time.Now()
				timingMu.Unlock()
			},
		}
		rctx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), 6*time.Second)
		req, err := m.newReq(rctx, http.MethodGet, url, nil, 0)
		if err != nil {
			cancel()
			return out, err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			cancel()
			return out, err
		}
		if err := m.check(srv, resp, http.StatusOK); err != nil {
			resp.Body.Close()
			cancel()
			return out, err
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		cancel()
		if out.Colo == "" {
			out.Colo = coloFromRay(resp.Header.Get("Cf-Ray"))
		}
		timingMu.Lock()
		sent, received := wrote, first
		timingMu.Unlock()
		if i == 0 || sent.IsZero() || received.Before(sent) {
			continue // connection set-up is not latency
		}
		ms := float64(received.Sub(sent)) / float64(time.Millisecond)
		if st := serverTimingMs(resp.Header.Get("Server-Timing")); st > 0 && st < ms {
			ms -= st
		}
		samples = append(samples, ms)
	}
	if len(samples) == 0 {
		return out, errors.New(i18n.T("нет ни одного замера задержки"))
	}
	out.Samples = len(samples)
	out.MedianMs = median(samples)
	var sum float64
	for i := 1; i < len(samples); i++ {
		d := samples[i] - samples[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	if len(samples) > 1 {
		out.JitterMs = sum / float64(len(samples)-1)
	}
	return out, nil
}

// chunkSize grows per worker: 1, 10, then 25 MB per request, like a
// browser-based speed test ramping up.
func chunkSize(n int) int64 {
	switch n {
	case 0:
		return 1 << 20
	case 1:
		return 10 << 20
	}
	return 25 << 20
}

// Download runs Parallel workers that request chunks until the phase time or
// the byte cap is reached.
func (m *HTTPMeter) Download(ctx context.Context, srv Server, live Live) (Throughput, error) {
	return m.transfer(ctx, srv, m.c.DownCap, live, func(rctx context.Context, n, worker int, size int64, counter *atomic.Int64) error {
		var url string
		var req *http.Request
		var err error
		if srv.Kind == "cloudflare" {
			url = srv.BaseURL + "/__down?bytes=" + strconv.FormatInt(size, 10)
			req, err = m.newReq(rctx, http.MethodGet, url, nil, 0)
		} else {
			span := srv.FileSize - size
			off := int64(0)
			if span > 0 {
				off = (int64(n*m.c.Parallel+worker) * (7 << 20)) % span
			}
			req, err = m.newReq(rctx, http.MethodGet, srv.BaseURL+srv.FilePath, nil, 0)
			if err == nil {
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+size-1))
			}
		}
		if err != nil {
			return err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := m.check(srv, resp, http.StatusOK, http.StatusPartialContent); err != nil {
			return err
		}
		buf := make([]byte, 64<<10)
		var read int64
		for read < size {
			k, rerr := resp.Body.Read(buf[:min(int64(len(buf)), size-read)])
			if k > 0 {
				read += int64(k)
				counter.Add(int64(k))
			}
			if rerr != nil {
				if rerr == io.EOF {
					if read < size {
						return io.ErrUnexpectedEOF
					}
					return nil
				}
				return rerr
			}
		}
		return nil
	})
}

// Upload posts chunks of random bytes (incompressible) to Cloudflare's sink.
func (m *HTTPMeter) Upload(ctx context.Context, srv Server, live Live) (Throughput, error) {
	if srv.Kind != "cloudflare" {
		return Throughput{}, errors.New(i18n.T("отдача измеряется только через Cloudflare"))
	}
	block := make([]byte, 1<<20)
	if _, err := rand.Read(block); err != nil {
		return Throughput{}, err
	}
	return m.transfer(ctx, srv, m.c.UpCap, live, func(rctx context.Context, _, _ int, size int64, counter *atomic.Int64) error {
		body := &countingReader{block: block, left: size, counter: counter}
		req, err := m.newReq(rctx, http.MethodPost, srv.BaseURL+"/__up", body, size)
		if err != nil {
			return err
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := m.check(srv, resp, http.StatusOK); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return err
	})
}

// countingReader yields left bytes cycling over block and counts what the
// transport has taken.
type countingReader struct {
	block   []byte
	pos     int
	left    int64
	counter *atomic.Int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.left {
		n = int(r.left)
	}
	if rem := len(r.block) - r.pos; n > rem {
		n = rem
	}
	copy(p, r.block[r.pos:r.pos+n])
	r.pos = (r.pos + n) % len(r.block)
	r.left -= int64(n)
	r.counter.Add(int64(n))
	return n, nil
}

type sample struct {
	t time.Duration
	b int64
}

// transfer runs the workers, samples the byte counter every 250 ms and computes
// the rate after the warm-up. It stops at the phase time or at the byte cap.
func (m *HTTPMeter) transfer(ctx context.Context, srv Server, byteCap int64, live Live, do func(context.Context, int, int, int64, *atomic.Int64) error) (Throughput, error) {
	var out Throughput
	phaseCtx, cancel := context.WithTimeout(ctx, m.c.Phase)
	defer cancel()
	var counter atomic.Int64
	start := time.Now()
	var mu sync.Mutex
	var firstErr error
	remaining := byteCap
	var wg sync.WaitGroup
	for w := 0; w < m.c.Parallel; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; phaseCtx.Err() == nil; n++ {
				mu.Lock()
				size := min(chunkSize(n), remaining)
				if srv.Kind == "file" {
					size = min(size, srv.FileSize)
				}
				remaining -= size
				mu.Unlock()
				if size == 0 {
					return
				}
				err := do(phaseCtx, n, worker, size, &counter)
				if err == nil {
					continue
				}
				if phaseCtx.Err() != nil {
					return // time or cap: normal end of the phase
				}
				var he *HTTPError
				isHTTP := errors.As(err, &he)
				mu.Lock()
				if firstErr == nil || (isHTTP && he.Stop()) {
					firstErr = err
				}
				mu.Unlock()
				if isHTTP {
					cancel() // a refusal stops every worker at once
				}
				return
			}
		}(w)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	samples := []sample{{0, 0}}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-tick.C:
			el := time.Since(start)
			b := counter.Load()
			samples = append(samples, sample{el, b})
			if live != nil {
				live(windowMbps(samples, time.Second), b, el)
			}
			// Workers finish the final reserved request and check its response.
		}
	}
	el := time.Since(start)
	total := counter.Load()
	samples = append(samples, sample{el, total})
	out.Bytes = total
	out.Seconds = el.Seconds()
	if total >= byteCap {
		out.CapReached = true
	}
	if err := ctx.Err(); err != nil {
		return out, err // cancelled by the user
	}
	if firstErr != nil {
		var he *HTTPError
		if errors.As(firstErr, &he) || total == 0 {
			return out, firstErr
		}
	}
	if total == 0 {
		return out, errors.New(i18n.T("данные не передавались"))
	}
	out.Mbps = rateAfter(samples, m.c.Warmup)
	return out, nil
}

// rateAfter is the rate between the first sample at or after warm-up and the
// last one; for a phase shorter than warm-up + 1 s the whole phase is used.
func rateAfter(s []sample, warm time.Duration) float64 {
	last := s[len(s)-1]
	from := s[0]
	for _, x := range s {
		if x.t >= warm {
			from = x
			break
		}
	}
	if last.t-from.t < time.Second {
		from = s[0]
	}
	dt := (last.t - from.t).Seconds()
	if dt <= 0 {
		return 0
	}
	return float64(last.b-from.b) * 8 / dt / 1e6
}

// windowMbps is the rate over the last window of samples (live display).
func windowMbps(s []sample, window time.Duration) float64 {
	last := s[len(s)-1]
	from := s[0]
	for i := len(s) - 1; i >= 0; i-- {
		if last.t-s[i].t >= window {
			from = s[i]
			break
		}
	}
	dt := (last.t - from.t).Seconds()
	if dt <= 0 {
		return 0
	}
	return float64(last.b-from.b) * 8 / dt / 1e6
}

func median(v []float64) float64 {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// coloFromRay takes the city code from a CF-Ray header like "8c1f2e3d4a5b6c7d-FRA".
func coloFromRay(v string) string {
	i := strings.LastIndexByte(v, '-')
	if i < 0 || i == len(v)-1 {
		return ""
	}
	c := strings.ToUpper(strings.TrimSpace(v[i+1:]))
	if len(c) < 3 || len(c) > 4 {
		return ""
	}
	for _, r := range c {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return c
}

// serverTimingMs reads "cfRequestDuration;dur=12.3" (milliseconds) from Server-Timing.
func serverTimingMs(v string) float64 {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "cfRequestDuration") {
			continue
		}
		for _, kv := range strings.Split(part, ";") {
			kv = strings.TrimSpace(kv)
			if strings.HasPrefix(kv, "dur=") {
				if f, err := strconv.ParseFloat(strings.TrimPrefix(kv, "dur="), 64); err == nil {
					return f
				}
			}
		}
	}
	return 0
}
