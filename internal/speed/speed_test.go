package speed

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpncheck/internal/guard"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/store"
)

// fakeCF imitates speed.cloudflare.com and a Hetzner test file on a local TLS
// server. No external network is used by these tests.
type fakeCF struct {
	mode      atomic.Value // "", "429", "challenge"
	upBytes   atomic.Int64
	downReqs  atomic.Int32
	lastRange atomic.Value
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch m, _ := f.mode.Load().(string); m {
	case "429":
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	case "challenge":
		w.Header().Set("cf-mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Cf-Ray", "8c1f2e3d4a5b6c7d-FRA")
	w.Header().Set("Server-Timing", "cfRequestDuration;dur=0.4")
	switch r.URL.Path {
	case "/__down":
		f.downReqs.Add(1)
		n, _ := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		writeZeros(w, n)
	case "/__up":
		k, _ := io.Copy(io.Discard, r.Body)
		f.upBytes.Add(k)
		w.WriteHeader(http.StatusOK)
	case "/100MB.bin":
		rg := r.Header.Get("Range")
		f.lastRange.Store(rg)
		var a, b int64
		if _, err := fmtSscanRange(rg, &a, &b); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := b - a + 1
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		w.WriteHeader(http.StatusPartialContent)
		writeZeros(w, n)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func fmtSscanRange(v string, a, b *int64) (int, error) {
	v = strings.TrimPrefix(v, "bytes=")
	parts := strings.SplitN(v, "-", 2)
	if len(parts) != 2 {
		return 0, errors.New("bad range")
	}
	var err error
	if *a, err = strconv.ParseInt(parts[0], 10, 64); err != nil {
		return 0, err
	}
	if *b, err = strconv.ParseInt(parts[1], 10, 64); err != nil {
		return 0, err
	}
	return 2, nil
}

var zeros = make([]byte, 64<<10)

func writeZeros(w io.Writer, n int64) {
	for n > 0 {
		k := int64(len(zeros))
		if k > n {
			k = n
		}
		if _, err := w.Write(zeros[:k]); err != nil {
			return
		}
		n -= k
	}
}

func newTestMeter(t *testing.T, c Config) (*HTTPMeter, *fakeCF, Server, Server) {
	t.Helper()
	f := &fakeCF{}
	ts := httptest.NewTLSServer(f)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	p := probe.New(probe.Options{Route: model.RouteConfig{Mode: model.RouteSystem}, Policy: guard.Policy{AllowLoopback: true}, RootCAs: pool})
	if c.Phase == 0 {
		c.Phase = 1200 * time.Millisecond
	}
	if c.Warmup == 0 {
		c.Warmup = 300 * time.Millisecond
	}
	if c.Parallel == 0 {
		c.Parallel = 2
	}
	if c.Samples == 0 {
		c.Samples = 3
	}
	m := NewHTTPMeter(p, c)
	t.Cleanup(m.Close)
	cf := Server{ID: "cf", Kind: "cloudflare", Host: "127.0.0.1", BaseURL: ts.URL}
	file := Server{ID: "file", Kind: "file", Host: "127.0.0.1", BaseURL: ts.URL, FilePath: "/100MB.bin", FileSize: 100 << 20}
	return m, f, cf, file
}

func TestLatencyColoAndServerTiming(t *testing.T) {
	m, _, cf, _ := newTestMeter(t, Config{})
	l, err := m.Latency(context.Background(), cf)
	if err != nil {
		t.Fatal(err)
	}
	if l.Samples != 3 || l.Colo != "FRA" || l.MedianMs < 0 || l.JitterMs < 0 {
		t.Fatalf("latency: %+v", l)
	}
}

func TestDownloadStopsAtByteCap(t *testing.T) {
	m, _, cf, _ := newTestMeter(t, Config{DownCap: 6 << 20, Phase: 5 * time.Second})
	var lives int
	start := time.Now()
	th, err := m.Download(context.Background(), cf, func(float64, int64, time.Duration) { lives++ })
	if err != nil {
		t.Fatal(err)
	}
	if !th.CapReached || th.Bytes < 6<<20 {
		t.Fatalf("cap not reached: %+v", th)
	}
	if th.Bytes > 6<<20+2*(64<<10)+(1<<20) {
		t.Fatalf("read far beyond the cap: %d bytes", th.Bytes)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("cap did not stop the phase early: %v", time.Since(start))
	}
	if th.Mbps <= 0 {
		t.Fatalf("no rate: %+v", th)
	}
}

func TestDownloadStopsAtPhaseTime(t *testing.T) {
	m, _, cf, _ := newTestMeter(t, Config{Phase: 700 * time.Millisecond, DownCap: 1 << 40})
	start := time.Now()
	th, err := m.Download(context.Background(), cf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("phase overran: %v", el)
	}
	if th.CapReached || th.Bytes == 0 {
		t.Fatalf("unexpected: %+v", th)
	}
}

func TestUploadCountsAndRespectsCap(t *testing.T) {
	m, f, cf, _ := newTestMeter(t, Config{UpCap: 3 << 20, Phase: 5 * time.Second})
	th, err := m.Upload(context.Background(), cf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !th.CapReached || th.Bytes < 3<<20 || f.upBytes.Load() == 0 {
		t.Fatalf("upload: %+v server got %d", th, f.upBytes.Load())
	}
}

func TestFileServerUsesRanges(t *testing.T) {
	m, f, _, file := newTestMeter(t, Config{DownCap: 3 << 20, Phase: 5 * time.Second})
	th, err := m.Download(context.Background(), file, nil)
	if err != nil {
		t.Fatal(err)
	}
	rg, _ := f.lastRange.Load().(string)
	if !strings.HasPrefix(rg, "bytes=") || th.Bytes < 3<<20 {
		t.Fatalf("range %q, %+v", rg, th)
	}
	if _, err := m.Upload(context.Background(), file, nil); err == nil {
		t.Fatal("upload to a file server must be refused")
	}
	if _, err := m.Latency(context.Background(), file); err == nil {
		t.Fatal("latency on a file server must be refused")
	}
}

func TestRefusalsStopAtOnce(t *testing.T) {
	m, f, cf, _ := newTestMeter(t, Config{})
	f.mode.Store("429")
	_, err := m.Download(context.Background(), cf, nil)
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 429 || !he.Stop() || time.Until(he.Until) < 100*time.Second {
		t.Fatalf("429: %v %+v", err, he)
	}
	if n := f.downReqs.Load(); n != 0 {
		t.Fatalf("download handler must not be reached on 429, got %d", n)
	}
	f.mode.Store("challenge")
	_, err = m.Latency(context.Background(), cf)
	if !errors.As(err, &he) || !he.Challenge || !he.Stop() {
		t.Fatalf("challenge: %v", err)
	}
}

func TestCancelStopsTransfer(t *testing.T) {
	m, _, cf, _ := newTestMeter(t, Config{Phase: 10 * time.Second, DownCap: 1 << 40})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	start := time.Now()
	_, err := m.Download(ctx, cf, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("cancel was not prompt")
	}
}

func TestHelpers(t *testing.T) {
	if coloFromRay("8c1f2e3d4a5b6c7d-FRA") != "FRA" || coloFromRay("nonsense") != "" || coloFromRay("x-12") != "" {
		t.Fatal("coloFromRay")
	}
	if v := serverTimingMs("cfL4;desc=x, cfRequestDuration;dur=12.5"); v != 12.5 {
		t.Fatalf("serverTiming %v", v)
	}
	s := []sample{{0, 0}, {500 * time.Millisecond, 1e6}, {1500 * time.Millisecond, 3e6}, {2500 * time.Millisecond, 5e6}}
	if r := rateAfter(s, time.Second); r < 15.9 || r > 16.1 { // 2e6 bytes/s = 16 Mbit/s
		t.Fatalf("rateAfter %v", r)
	}
}

// scripted is a fake meter for runner tests.
type scripted struct {
	downErr error
	mu      sync.Mutex
	calls   []string
}

func (s *scripted) Close() {}
func (s *scripted) ExitIP(context.Context) (string, string, error) {
	return "203.0.113.5", "DE", nil
}
func (s *scripted) Latency(context.Context, Server) (Latency, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "latency")
	s.mu.Unlock()
	return Latency{MedianMs: 20, JitterMs: 2, Samples: 10, Colo: "AMS"}, nil
}
func (s *scripted) Download(_ context.Context, _ Server, live Live) (Throughput, error) {
	for i, v := range []float64{10.04, 55.5, 88.26} {
		if live != nil {
			live(v, int64(i+1)<<20, time.Duration(i+1)*250*time.Millisecond)
		}
	}
	s.mu.Lock()
	s.calls = append(s.calls, "download")
	s.mu.Unlock()
	if s.downErr != nil {
		return Throughput{}, s.downErr
	}
	return Throughput{Mbps: 90, Bytes: 9e7, Seconds: 8}, nil
}
func (s *scripted) Upload(context.Context, Server, Live) (Throughput, error) {
	s.mu.Lock()
	s.calls = append(s.calls, "upload")
	s.mu.Unlock()
	return Throughput{Mbps: 40, Bytes: 4e7, Seconds: 8}, nil
}

func newRunner(t *testing.T, m Meter) (*Runner, *limiter.Limiter, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lim := limiter.New(st, time.Now)
	lim.SpeedCooldown = 0
	r := NewRunner(Deps{Store: st, Limiter: lim, NewMeter: func(model.RouteConfig) Meter { return m }})
	return r, lim, st
}

var sysRoute = model.RouteConfig{Mode: model.RouteSystem}

func TestRunnerCompletesAndPersists(t *testing.T) {
	m := &scripted{}
	r, lim, st := newRunner(t, m)
	if _, err := r.Start(Request{Route: sysRoute, ServerID: "cloudflare", ProfileName: "DE"}); err != nil {
		t.Fatal(err)
	}
	if err := lim.StartRun(); !errors.Is(err, limiter.ErrSpeedActive) {
		t.Fatalf("a probe run must not overlap a speed test, got %v", err)
	}
	r.Wait()
	h := r.History()
	if len(h) != 1 || h[0].Status != "completed" || h[0].Colo != "AMS" || *h[0].DownMbps != 90 || *h[0].UpMbps != 40 || *h[0].LatencyMs != 20 {
		t.Fatalf("history: %+v", h)
	}
	if s := h[0].DownSeries; len(s) != 3 || s[0] != 10 || s[2] != 88.3 || len(h[0].UpSeries) != 0 {
		t.Fatalf("down series %v up %v", s, h[0].UpSeries)
	}
	if got := strings.Join(m.calls, ","); got != "latency,download,upload" {
		t.Fatalf("phases %s", got)
	}
	r2 := NewRunner(Deps{Store: st, Limiter: lim, NewMeter: func(model.RouteConfig) Meter { return m }})
	if len(r2.History()) != 1 {
		t.Fatal("history not persisted")
	}
	if !r2.Delete(h[0].ID) || len(r2.History()) != 0 {
		t.Fatal("delete")
	}
}

func TestRunnerFileServerOnlyDownloads(t *testing.T) {
	m := &scripted{}
	r, _, _ := newRunner(t, m)
	if _, err := r.Start(Request{Route: sysRoute, ServerID: "hetzner-fsn1"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	h := r.History()[0]
	if strings.Join(m.calls, ",") != "download" || h.UpMbps != nil || h.LatencyMs != nil || h.Status != "completed" {
		t.Fatalf("calls %v result %+v", m.calls, h)
	}
}

func TestRunnerRefusalPausesServer(t *testing.T) {
	m := &scripted{downErr: &HTTPError{Host: "speed.cloudflare.com", Status: 429}}
	r, lim, _ := newRunner(t, m)
	if _, err := r.Start(Request{Route: sysRoute, ServerID: "cloudflare"}); err != nil {
		t.Fatal(err)
	}
	r.Wait()
	h := r.History()[0]
	if h.Status != "partial" || h.UpMbps != nil || !strings.Contains(h.Message, "приостановлены") {
		t.Fatalf("result %+v", h)
	}
	if strings.Contains(strings.Join(m.calls, ","), "upload") {
		t.Fatal("upload must not run after a refusal")
	}
	_, err := r.Start(Request{Route: sysRoute, ServerID: "cloudflare"})
	var be *limiter.BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("server must be paused, got %v", err)
	}
	if _, err := r.Start(Request{Route: sysRoute, ServerID: "hetzner-fsn1"}); err != nil {
		t.Fatalf("other servers stay available: %v", err)
	}
	r.Wait()
	if lim.Speed().Blocks["speed.cloudflare.com"].Status != 429 {
		t.Fatal("block not visible in status")
	}
}

func TestRunnerRejectsBadInput(t *testing.T) {
	r, _, _ := newRunner(t, &scripted{})
	if _, err := r.Start(Request{Route: sysRoute, ServerID: "nope"}); err == nil {
		t.Fatal("unknown server accepted")
	}
	if _, err := r.Start(Request{Route: model.RouteConfig{Mode: model.RouteProxy, ProxyKind: "http", ProxyAddr: "bad"}, ServerID: "cloudflare"}); err == nil {
		t.Fatal("bad proxy accepted")
	}
}
