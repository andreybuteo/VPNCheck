package speed

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/i18n"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/runner"
	"vpncheck/internal/store"
)

const historyFile = "speed.json"

// maxSeries bounds the stored live samples per phase (4 a second).
const maxSeries = 80

// Result is one speed test. Unmeasured values are null.
type Result struct {
	ID          string            `json:"id"`
	StartedAt   time.Time         `json:"startedAt"`
	FinishedAt  *time.Time        `json:"finishedAt"`
	ProfileName string            `json:"profileName"`
	Route       model.RouteConfig `json:"route"`
	ServerID    string            `json:"serverId"`
	ServerName  string            `json:"serverName"`
	Host        string            `json:"host"`
	Colo        string            `json:"colo"`
	ExitIP      string            `json:"exitIp,omitempty"`
	ExitCountry string            `json:"exitCountry,omitempty"`
	// Status: running | completed | partial | cancelled | failed
	Status    string   `json:"status"`
	LatencyMs *float64 `json:"latencyMs"`
	JitterMs  *float64 `json:"jitterMs"`
	Samples   int      `json:"latencySamples"`
	DownMbps  *float64 `json:"downMbps"`
	DownBytes int64    `json:"downBytes"`
	DownSec   float64  `json:"downSeconds"`
	DownCap   bool     `json:"downCapReached"`
	UpMbps    *float64 `json:"upMbps"`
	UpBytes   int64    `json:"upBytes"`
	UpSec     float64  `json:"upSeconds"`
	UpCap     bool     `json:"upCapReached"`
	// DownSeries and UpSeries are the live rate (Mbit/s over the last second)
	// sampled four times a second: the line drawn under the result.
	DownSeries []float64 `json:"downSeries,omitempty"`
	UpSeries   []float64 `json:"upSeries,omitempty"`
	Message    string    `json:"message,omitempty"`
	Demo       bool      `json:"demo,omitempty"`
}

// Progress is the live state shown while a test runs.
type Progress struct {
	Result
	// Phase: latency | download | upload | done
	Phase      string   `json:"phase"`
	LiveMbps   *float64 `json:"liveMbps"`
	LiveBytes  int64    `json:"liveBytes"`
	ElapsedMs  int64    `json:"elapsedMs"`
	PhaseMs    int64    `json:"phaseMs"`
	PhaseIndex int      `json:"phaseIndex"`
	PhaseCount int      `json:"phaseCount"`
}

type historyDoc struct {
	SchemaVersion int      `json:"schemaVersion"`
	Results       []Result `json:"results"`
}

// Request starts a test.
type Request struct {
	ProfileName string            `json:"profileName"`
	Route       model.RouteConfig `json:"route"`
	ServerID    string            `json:"serverId"`
	// RecordIP asks for the exit IP for the IP log (set by the API from settings).
	RecordIP bool `json:"-"`
}

// Deps wires the runner.
type Deps struct {
	Store    *store.Store
	Limiter  *limiter.Limiter
	Publish  func(event string, payload any)
	NewMeter func(route model.RouteConfig) Meter
	Logger   *log.Logger
	Now      func() time.Time
	Demo     bool
}

// Runner holds at most one speed test at a time.
type Runner struct {
	d       Deps
	mu      sync.Mutex
	cur     *Progress
	cancel  context.CancelFunc
	done    chan struct{}
	history []Result
}

// NewRunner loads the history.
func NewRunner(d Deps) *Runner {
	if d.Publish == nil {
		d.Publish = func(string, any) {}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = log.New(io.Discard, "", 0)
	}
	r := &Runner{d: d}
	if d.Store != nil {
		var doc historyDoc
		if info, err := d.Store.LoadJSON(historyFile, &doc); err == nil && info.Found && !info.Corrupt {
			r.history = doc.Results
		}
	}
	return r
}

// Start validates the request, claims the limiter slot and runs in background.
func (r *Runner) Start(req Request) (Progress, error) {
	srv, ok := ServerByID(req.ServerID)
	if !ok {
		return Progress{}, errors.New(i18n.T("неизвестный сервер замера"))
	}
	if err := runner.ValidateRoute(req.Route); err != nil {
		return Progress{}, err
	}
	if err := r.d.Limiter.StartSpeed(srv.Host); err != nil {
		return Progress{}, err
	}
	now := r.d.Now()
	phases := 3
	if srv.Kind != "cloudflare" {
		phases = 1
	}
	p := &Progress{Result: Result{ID: store.NewRunID(now), StartedAt: now.UTC(), ProfileName: req.ProfileName, Route: req.Route,
		ServerID: srv.ID, ServerName: srv.Name, Host: srv.Host, Status: "running", Demo: r.d.Demo}, PhaseCount: phases}
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cur = p
	r.cancel = cancel
	r.done = make(chan struct{})
	snap := *p
	r.mu.Unlock()
	r.d.Publish("speed.started", map[string]any{"progress": snap})
	go r.execute(ctx, srv, req)
	return snap, nil
}

// Cancel stops the running test.
func (r *Runner) Cancel() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil || r.cur == nil {
		return false
	}
	r.cancel()
	return true
}

// Wait blocks until the running test (if any) ends.
func (r *Runner) Wait() {
	r.mu.Lock()
	ch := r.done
	r.mu.Unlock()
	if ch != nil {
		<-ch
	}
}

// Current returns the running test or nil.
func (r *Runner) Current() *Progress {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cur == nil {
		return nil
	}
	c := *r.cur
	return &c
}

// History returns stored results, newest first.
func (r *Runner) History() []Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Result{}, r.history...)
}

// Delete removes one stored result.
func (r *Runner) Delete(id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, h := range r.history {
		if h.ID == id {
			next := slices.Delete(slices.Clone(r.history), i, i+1)
			if err := r.saveLocked(next); err != nil {
				return false, err
			}
			r.history = next
			return true, nil
		}
	}
	return false, nil
}

func (r *Runner) saveLocked(results []Result) error {
	if r.d.Store == nil {
		return nil
	}
	return r.d.Store.SaveJSON(historyFile, historyDoc{SchemaVersion: model.SchemaVersion, Results: results})
}

func (r *Runner) update(f func(p *Progress)) {
	r.mu.Lock()
	f(r.cur)
	snap := *r.cur
	r.mu.Unlock()
	r.d.Publish("speed.progress", map[string]any{"progress": snap})
}

func f64(v float64) *float64 { return &v }

func (r *Runner) execute(ctx context.Context, srv Server, req Request) {
	m := r.d.NewMeter(req.Route)
	defer func() {
		m.Close()
		r.mu.Lock()
		r.d.Limiter.EndSpeed()
		close(r.done)
		r.mu.Unlock()
	}()

	var stopErr error // a refusal or cancellation that ends the test
	var msgs []string
	measured := 0
	phase := func(idx int, name string, dur time.Duration) {
		r.update(func(p *Progress) {
			p.Phase, p.PhaseIndex, p.PhaseMs, p.ElapsedMs, p.LiveMbps, p.LiveBytes = name, idx, dur.Milliseconds(), 0, nil, 0
		})
	}
	liveFor := func(down bool) Live {
		return func(mbps float64, b int64, el time.Duration) {
			v := math.Round(mbps*10) / 10
			r.update(func(p *Progress) {
				p.LiveMbps, p.LiveBytes, p.ElapsedMs = f64(mbps), b, el.Milliseconds()
				if down && len(p.DownSeries) < maxSeries {
					p.DownSeries = append(p.DownSeries, v)
				} else if !down && len(p.UpSeries) < maxSeries {
					p.UpSeries = append(p.UpSeries, v)
				}
			})
		}
	}
	handle := func(what string, err error) bool {
		if err == nil {
			measured++
			return true
		}
		if ctx.Err() != nil {
			stopErr = ctx.Err()
			return false
		}
		var he *HTTPError
		if errors.As(err, &he) && he.Stop() {
			until := he.Until
			if until.IsZero() || until.Before(r.d.Now()) {
				until = r.d.Now().Add(app.SpeedBlockDefault)
			}
			r.d.Limiter.BlockSpeedServer(srv.Host, until, he.Error(), he.Status)
			stopErr = he
			msgs = append(msgs, i18n.T("%s: %s. Замеры через этот сервер приостановлены до %s.", what, he.Error(), until.Local().Format("02.01 15:04")))
			return false
		}
		msgs = append(msgs, what+": "+err.Error())
		return true
	}

	if req.RecordIP {
		if ip, loc, err := r.observeExit(ctx, m); err == nil {
			r.update(func(p *Progress) { p.ExitIP, p.ExitCountry = ip, loc })
		} else if ctx.Err() == nil {
			msgs = append(msgs, i18n.T("внешний IP не определён: ")+err.Error())
		}
	}
	idx := 0
	if srv.Kind == "cloudflare" {
		idx++
		phase(idx, "latency", 0)
		lat, err := m.Latency(ctx, srv)
		if handle(i18n.T("задержка"), err) && err == nil {
			r.update(func(p *Progress) {
				p.LatencyMs, p.JitterMs, p.Samples, p.Colo = f64(lat.MedianMs), f64(lat.JitterMs), lat.Samples, lat.Colo
			})
		}
	}
	if stopErr == nil {
		idx++
		phase(idx, "download", app.SpeedPhase)
		t, err := m.Download(ctx, srv, liveFor(true))
		ok := handle(i18n.T("скачивание"), err)
		if ok && err == nil {
			r.update(func(p *Progress) {
				p.DownMbps, p.DownBytes, p.DownSec, p.DownCap = f64(t.Mbps), t.Bytes, t.Seconds, t.CapReached
			})
		} else {
			r.update(func(p *Progress) { p.DownBytes, p.DownSec = t.Bytes, t.Seconds })
		}
	}
	if stopErr == nil && srv.Kind == "cloudflare" {
		idx++
		phase(idx, "upload", app.SpeedPhase)
		t, err := m.Upload(ctx, srv, liveFor(false))
		ok := handle(i18n.T("отдача"), err)
		if ok && err == nil {
			r.update(func(p *Progress) {
				p.UpMbps, p.UpBytes, p.UpSec, p.UpCap = f64(t.Mbps), t.Bytes, t.Seconds, t.CapReached
			})
		} else {
			r.update(func(p *Progress) { p.UpBytes, p.UpSec = t.Bytes, t.Seconds })
		}
	}

	fin := r.d.Now().UTC()
	r.mu.Lock()
	p := r.cur
	p.FinishedAt = &fin
	p.Phase = "done"
	p.LiveMbps = nil
	switch {
	case errors.Is(stopErr, context.Canceled):
		p.Status = "cancelled"
		msgs = append(msgs, i18n.T("Замер остановлен пользователем."))
	case measured == 0:
		p.Status = "failed"
	case len(msgs) > 0:
		p.Status = "partial"
	default:
		p.Status = "completed"
	}
	p.Message = strings.Join(msgs, " ")
	res := p.Result
	r.history = append([]Result{res}, r.history...)
	if len(r.history) > app.SpeedHistoryLimit {
		r.history = r.history[:app.SpeedHistoryLimit]
	}
	if err := r.saveLocked(r.history); err != nil {
		res.Message += i18n.T(" Не удалось сохранить запуск в историю: ") + err.Error()
		r.history[0] = res
		r.d.Logger.Print(res.Message)
	}
	r.cur = nil
	r.cancel = nil
	r.mu.Unlock()
	r.d.Logger.Printf("speed %s %s: %s", res.ID, res.ServerID, res.Status)
	r.d.Publish("speed.finished", map[string]any{"result": res})
}

// The IP observer and the speed server are distinct hosts. Honour and record
// the observer's cooldown without charging a refusal to the transfer server.
func (r *Runner) observeExit(ctx context.Context, m Meter) (string, string, error) {
	host := runner.ExternalIPProvider.Host
	if a := r.d.Limiter.Allowance(host); !a.OK {
		return "", "", &a
	}
	ip, loc, err := m.ExitIP(ctx)
	var refusal *HTTPError
	if errors.As(err, &refusal) && refusal.Status == 429 {
		h := model.HTTPResult{Status: refusal.Status}
		if !refusal.Until.IsZero() {
			h.RateLimitReset = refusal.Until.UTC().Format(time.RFC3339)
		}
		r.d.Limiter.Report(host, &model.ProbeResult{HTTP: &h})
	}
	return ip, loc, err
}
