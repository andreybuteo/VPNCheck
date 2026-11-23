package runner

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/registry"
	"vpncheck/internal/store"
)

// fakeProber returns canned results; hosts containing "block" hang until ctx is done.
type fakeProber struct {
	opts     probe.Options
	delay    time.Duration
	statuses map[string]int // host → http status for https endpoints
	traceIPs *[]string
	mu       *sync.Mutex
	calls    *[]string
}

var probeTimes = struct {
	mu sync.Mutex
	m  map[string][]time.Time
}{m: map[string][]time.Time{}}

func (f *fakeProber) Probe(ctx context.Context, ep model.Endpoint) model.ProbeResult {
	f.mu.Lock()
	*f.calls = append(*f.calls, ep.ID)
	f.mu.Unlock()
	probeTimes.mu.Lock()
	probeTimes.m[ep.ID] = append(probeTimes.m[ep.ID], time.Now()) // monotonic
	probeTimes.mu.Unlock()
	if f.opts.OnStage != nil {
		f.opts.OnStage(model.StageDNS)
	}
	res := model.ProbeResult{EndpointID: ep.ID, GroupID: ep.GroupID, Host: ep.Host, URL: ep.URL, Kind: ep.Kind, Route: f.opts.Route, IPFamily: f.opts.Family, StartedAt: time.Now()}
	if strings.Contains(ep.Host, "block") {
		<-ctx.Done()
		res.Transport = model.Transport{OK: false, FailedStage: model.StageTCP, ErrorKind: model.ErrCancelled, ErrorText: "cancelled"}
		return res
	}
	select {
	case <-time.After(f.delay):
	case <-ctx.Done():
		res.Transport = model.Transport{OK: false, FailedStage: model.StageTCP, ErrorKind: model.ErrCancelled}
		return res
	}
	if strings.Contains(ep.Host, "fail") {
		res.Transport = model.Transport{OK: false, FailedStage: model.StageDNS, ErrorKind: model.ErrDNS, ErrorText: "no such host"}
		return res
	}
	ms := 120.0
	res.Timings = model.Timings{DNSMs: &ms, TCPMs: &ms, TLSMs: &ms, TLSReadyMs: &ms, TotalMs: &ms}
	res.Transport = model.Transport{OK: true, CertVerified: true, PeerAddr: "1.2.3.4:443", PeerFamily: "ipv4", FamilyProven: true}
	if ep.Kind == model.KindHTTPS {
		st := 200
		if s, ok := f.statuses[ep.Host]; ok {
			st = s
		}
		res.HTTP = &model.HTTPResult{Status: st, Proto: "HTTP/2.0"}
		res.Timings.TTFBMs = &ms
	}
	return res
}

func (f *fakeProber) FetchSmall(ctx context.Context, url string, limit int64) (int, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(url, "yandex.ru") {
		return 200, []byte(`<html>{"ip":{"v4":"192.0.2.10","v6":null},"isp":{"isVpn":false},"clientRegion":{"name":"Москва","ip":"Москва","id":213}}</html>`), nil
	}
	if f.traceIPs == nil || len(*f.traceIPs) == 0 {
		return 500, nil, nil
	}
	ip := (*f.traceIPs)[0]
	*f.traceIPs = (*f.traceIPs)[1:]
	return 200, []byte("fl=1\nip=" + ip + "\nloc=DE\n"), nil
}

type harness struct {
	r      *Runner
	st     *store.Store
	reg    *registry.Registry
	lim    *limiter.Limiter
	events *[]string
	calls  *[]string
	mu     *sync.Mutex
	ips    *[]string
}

func newHarness(t *testing.T, eps []model.Endpoint) *harness {
	t.Helper()
	st, _ := store.Open(t.TempDir())
	reg, _ := registry.Load(st)
	// Replace the registry content with the test endpoints (custom points).
	doc := registry.Document{SchemaVersion: 1, Endpoints: eps}
	data, _ := jsonMarshal(doc)
	if err := reg.Import(data); err != nil {
		t.Fatal(err)
	}
	// Disable every built-in point so only the test points run.
	for _, e := range reg.List() {
		if reg.IsBuiltin(e.ID) {
			_ = reg.SetEnabled(e.ID, false)
		}
	}
	lim := limiter.New(st, time.Now)
	lim.GroupSpacing = 10 * time.Millisecond
	lim.RunCooldown = 0
	events := &[]string{}
	calls := &[]string{}
	mu := &sync.Mutex{}
	ips := &[]string{}
	h := &harness{st: st, reg: reg, lim: lim, events: events, calls: calls, mu: mu, ips: ips}
	h.r = New(Deps{
		Store: st, Registry: reg, Limiter: lim,
		Publish: func(ev string, _ any) {
			mu.Lock()
			*events = append(*events, ev)
			mu.Unlock()
		},
		NewProber: func(o probe.Options) Prober {
			return &fakeProber{opts: o, delay: 20 * time.Millisecond, statuses: map[string]int{"api.t1.example.com": 401, "limited.t3.example.com": 429}, mu: mu, calls: calls, traceIPs: ips}
		},
		StabilityInterval: 60 * time.Millisecond,
	})
	return h
}

func testEndpoints() []model.Endpoint {
	return []model.Endpoint{
		{ID: "t1-web", GroupID: "t1", Group: "T1", Label: "web", Host: "www.t1.example.com", Kind: model.KindTLS, Enabled: true},
		{ID: "t1-api", GroupID: "t1", Group: "T1", Label: "api", Host: "api.t1.example.com", URL: "https://api.t1.example.com/v1", Kind: model.KindHTTPS, ExpectedStatuses: []int{401}, Enabled: true},
		{ID: "t2-web", GroupID: "t2", Group: "T2", Label: "web", Host: "www.t2.example.com", Kind: model.KindTLS, Enabled: true},
		{ID: "t2-fail", GroupID: "t2", Group: "T2", Label: "fail", Host: "fail.t2.example.com", Kind: model.KindTLS, Enabled: true},
		{ID: "t3-lim", GroupID: "t3", Group: "T3", Label: "lim", Host: "limited.t3.example.com", URL: "https://limited.t3.example.com/", Kind: model.KindHTTPS, ExpectedStatuses: []int{200}, Enabled: true},
		{ID: "t3-off", GroupID: "t3", Group: "T3", Label: "off", Host: "off.t3.example.com", Kind: model.KindTLS, Enabled: false},
	}
}

func TestFastRunCompletesAndPersists(t *testing.T) {
	h := newHarness(t, testEndpoints())
	sum, err := h.r.Start(Request{ProfileName: "VPN — Тест", Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, SlowThresholdMs: 1500})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, err := h.st.LoadRun(sum.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.RunCompleted || len(run.Results) != 5 {
		t.Fatalf("status=%s results=%d msg=%q", run.Status, len(run.Results), run.Message)
	}
	byID := map[string]model.ProbeResult{}
	for _, r := range run.Results {
		byID[r.EndpointID] = r
	}
	if byID["t1-api"].Outcome.Code != "http_expected" || byID["t1-api"].Outcome.Level != model.LevelOK {
		t.Errorf("expected 401 must be OK: %+v", byID["t1-api"].Outcome)
	}
	if byID["t2-fail"].Outcome.Code != "dns_error" {
		t.Errorf("dns failure: %+v", byID["t2-fail"].Outcome)
	}
	if byID["t3-lim"].Outcome.Code != "http_429" {
		t.Errorf("429: %+v", byID["t3-lim"].Outcome)
	}
	if _, ok := byID["t3-off"]; ok {
		t.Error("disabled endpoint must not be probed")
	}
	c := run.Counts
	if c.Planned != 5 || c.Probed != 5 || c.TLSOK != 4 || c.HTTPSTotal != 2 || c.HTTPMatch != 1 || c.Errors != 1 || c.Limited != 1 {
		t.Errorf("counts: %+v", c)
	}
	if run.MedianTLSReady == nil {
		t.Error("median missing")
	}
	// 429 block persisted in the limiter for that host.
	if a := h.lim.Allowance("limited.t3.example.com"); a.OK {
		t.Error("429 must block the host afterwards")
	}
	// Events.
	h.mu.Lock()
	ev := strings.Join(*h.events, ",")
	h.mu.Unlock()
	for _, want := range []string{"run.started", "probe.started", "probe.finished", "run.finished"} {
		if !strings.Contains(ev, want) {
			t.Errorf("missing event %s in %s", want, ev)
		}
	}
	// Interleaving: first two probes belong to different groups.
	h.mu.Lock()
	calls := append([]string(nil), *h.calls...)
	h.mu.Unlock()
	if len(calls) >= 2 && strings.HasPrefix(calls[0], "t1") && strings.HasPrefix(calls[1], "t1") {
		t.Errorf("probes should be interleaved across groups: %v", calls)
	}
	if h.lim.RunActive() {
		t.Error("run slot must be released")
	}
	list, _ := h.st.ListRuns()
	if len(list) != 1 || list[0].ID != sum.ID {
		t.Errorf("history: %+v", list)
	}
}

func TestSkippedByLimiterAndPartialStatus(t *testing.T) {
	h := newHarness(t, testEndpoints())
	// Pre-block a host as if a 429 happened earlier (survives profile changes).
	h.lim.Report("www.t2.example.com", &model.ProbeResult{HTTP: &model.HTTPResult{Status: 429}})
	sum, err := h.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	if run.Status != model.RunPartial {
		t.Fatalf("want partial, got %s", run.Status)
	}
	var skipped *model.ProbeResult
	for i := range run.Results {
		if run.Results[i].EndpointID == "t2-web" {
			skipped = &run.Results[i]
		}
	}
	if skipped == nil || !skipped.Skipped || skipped.Outcome.Code != "rate_limited_429" || skipped.Outcome.Level != model.LevelNeutral {
		t.Fatalf("skipped result wrong: %+v", skipped)
	}
	if run.Counts.Skipped != 1 || run.Counts.Limited != 2 {
		t.Fatalf("counts: %+v", run.Counts)
	}
}

func TestCancelStopsActiveAndPending(t *testing.T) {
	eps := testEndpoints()
	eps = append(eps, model.Endpoint{ID: "t4-block", GroupID: "t4", Group: "T4", Label: "b", Host: "block.t4.example.com", Kind: model.KindTLS, Enabled: true})
	h := newHarness(t, eps)
	h.r.d.Workers = 1 // serialise so that pending endpoints exist when we cancel
	sum, err := h.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t4-block", "t1-web", "t2-web"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}}); !errors.Is(err, limiter.ErrRunActive) {
		t.Fatalf("second start: want ErrRunActive, got %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if !h.r.Cancel() {
		t.Fatal("cancel should report an active run")
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	if run.Status != model.RunCancelled {
		t.Fatalf("want cancelled, got %s", run.Status)
	}
	if len(run.Results) != 3 {
		t.Fatalf("every planned probe needs a result, got %d", len(run.Results))
	}
	for _, r := range run.Results {
		if r.Outcome.Code != "cancelled" || r.Outcome.Level != model.LevelNeutral {
			t.Errorf("%s: want cancelled outcome, got %+v", r.EndpointID, r.Outcome)
		}
	}
	if h.r.Cancel() {
		t.Error("cancel after finish must report nothing running")
	}
	if h.lim.RunActive() {
		t.Error("run slot must be released after cancel")
	}
}

func TestStabilityMode(t *testing.T) {
	h := newHarness(t, testEndpoints())
	if _, err := h.r.Start(Request{Mode: model.ModeStability, Route: model.RouteConfig{Mode: model.RouteSystem}}); err == nil {
		t.Fatal("stability without endpoints must fail")
	}
	if _, err := h.r.Start(Request{Mode: model.ModeStability, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"a", "b", "c", "d", "e", "f"}}); err == nil {
		t.Fatal("more than 5 endpoints must fail")
	}
	probeTimes.mu.Lock()
	probeTimes.m = map[string][]time.Time{}
	probeTimes.mu.Unlock()
	sum, err := h.r.Start(Request{Mode: model.ModeStability, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web", "t2-web"}})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	if len(run.Results) != 6 {
		t.Fatalf("want 2×3 results, got %d", len(run.Results))
	}
	attempts := map[string]int{}
	for _, r := range run.Results {
		attempts[r.EndpointID]++
	}
	probeTimes.mu.Lock()
	defer probeTimes.mu.Unlock()
	for id, n := range attempts {
		if n != 3 {
			t.Errorf("%s: want 3 attempts, got %d", id, n)
		}
		ts := probeTimes.m[id]
		for i := 1; i < len(ts); i++ {
			// Monotonic clock: the interval must be honoured between probe starts.
			// The runner measures from just before Probe is called; this fake
			// records inside Probe, a fraction of a millisecond later and not by
			// the same amount every time, so allow 2 ms of that jitter.
			if d := ts[i].Sub(ts[i-1]); d < 58*time.Millisecond {
				t.Errorf("%s: attempts must be spaced by the interval, got %v", id, d)
			}
		}
	}
}

func TestProxyModeForcesAutoFamilyAndValidation(t *testing.T) {
	h := newHarness(t, testEndpoints())
	bad := []model.RouteConfig{
		{Mode: model.RouteProxy},
		{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "nohost"},
		{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "user:pw@127.0.0.1:1080"},
		{Mode: model.RouteProxy, ProxyKind: "ftp", ProxyAddr: "127.0.0.1:1080"},
		{Mode: "magic"},
	}
	for _, rc := range bad {
		if err := ValidateRoute(rc); err == nil {
			t.Errorf("route %+v must be invalid", rc)
		}
	}
	sum, err := h.r.Start(Request{Mode: model.ModeFast, IPFamily: model.FamilyV6, Route: model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxySOCKS5, ProxyAddr: "127.0.0.1:1080"}, EndpointIDs: []string{"t1-web"}})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	if run.IPFamily != model.FamilyAuto || !strings.Contains(run.Message, "Auto") {
		t.Fatalf("proxy mode must force auto family with a note: family=%s msg=%q", run.IPFamily, run.Message)
	}
	if run.Results[0].Route.Mode != model.RouteProxy {
		t.Fatal("results must carry the proxy route")
	}
}

func TestExternalIPBeforeAfter(t *testing.T) {
	h := newHarness(t, testEndpoints())
	*h.ips = []string{"203.0.113.10", "203.0.113.20"}
	sum, err := h.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web"}, ShowExternalIP: true})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	x := run.ExternalIP
	if x == nil || x.Before != "203.0.113.10" || x.After != "203.0.113.20" || !x.Changed || x.Country != "DE" || x.Provider == "" {
		t.Fatalf("external ip: %+v", x)
	}
	// Without the option nothing is requested.
	h2 := newHarness(t, testEndpoints())
	*h2.ips = []string{"203.0.113.10"}
	sum2, _ := h2.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web"}})
	h2.r.Wait()
	run2, _ := h2.st.LoadRun(sum2.ID)
	if run2.ExternalIP != nil || len(*h2.ips) != 1 {
		t.Fatal("external IP must not be requested when the option is off")
	}
}

func TestParseTrace(t *testing.T) {
	ip, loc := parseTrace("fl=1\nh=x\nip=2606:4700::1\nloc=US\n")
	if ip != "2606:4700::1" || loc != "US" {
		t.Fatalf("got %s %s", ip, loc)
	}
	if ip, _ := parseTrace("ip=not-an-ip"); ip != "" {
		t.Fatal("invalid ip must be ignored")
	}
}

func TestDiagModeProbesBothRoutesAndProducesVerdicts(t *testing.T) {
	h := newHarness(t, testEndpoints())
	alt := model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: "127.0.0.1:10809"}
	if _, err := h.r.Start(Request{Mode: model.ModeDiag, Route: model.RouteConfig{Mode: model.RouteSystem}, EndpointIDs: []string{"t1-web"}}); err == nil {
		t.Fatal("diag without alt route must fail")
	}
	sum, err := h.r.Start(Request{Mode: model.ModeDiag, Route: model.RouteConfig{Mode: model.RouteSystem}, AltRoute: &alt, EndpointIDs: []string{"t1-web", "t1-api"}, EnvMode: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	h.r.Wait()
	run, _ := h.st.LoadRun(sum.ID)
	if len(run.Results) != 4 || run.AltRoute == nil || run.AltRoute.ProxyAddr != alt.ProxyAddr {
		t.Fatalf("results=%d alt=%+v", len(run.Results), run.AltRoute)
	}
	routes := map[string]int{}
	for _, r := range run.Results {
		routes[string(r.Route.Mode)]++
		if r.Route.Mode == model.RouteProxy && r.Attempt != 2 {
			t.Errorf("alt route probe must be attempt 2: %+v", r.Attempt)
		}
	}
	if routes["system"] != 2 || routes["proxy"] != 2 {
		t.Fatalf("routes: %v", routes)
	}
	if len(run.Verdicts) != 1 || run.Verdicts[0].GroupID != "t1" || run.Verdicts[0].Code == "" {
		t.Fatalf("verdicts: %+v", run.Verdicts)
	}
	// Fast runs get verdicts as well.
	h2 := newHarness(t, testEndpoints())
	sum2, _ := h2.r.Start(Request{Mode: model.ModeFast, Route: model.RouteConfig{Mode: model.RouteSystem}})
	h2.r.Wait()
	run2, _ := h2.st.LoadRun(sum2.ID)
	if len(run2.Verdicts) != 3 {
		t.Fatalf("fast run verdicts: %d", len(run2.Verdicts))
	}
}
