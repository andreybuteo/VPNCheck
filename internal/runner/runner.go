// Package runner orchestrates one check run: builds the queue, drives the
// probe engine through the limiter, classifies results, streams progress and
// persists the finished run. Exactly one run is active per process.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/classify"
	"vpncheck/internal/diag"
	"vpncheck/internal/i18n"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/registry"
	"vpncheck/internal/store"
)

// Prober is the engine dependency (probe.Prober in production).
type Prober interface {
	Probe(ctx context.Context, ep model.Endpoint) model.ProbeResult
	FetchSmall(ctx context.Context, url string, limit int64) (int, []byte, error)
}

// ExternalIPProvider is the documented public-IP source (see docs/REGISTRY.md).
var ExternalIPProvider = struct {
	Name, URL, Host, Group string
}{Name: "Cloudflare (cdn-cgi/trace)", URL: "https://www.cloudflare.com/cdn-cgi/trace", Host: "www.cloudflare.com", Group: "cloudflare"}

// Deps wires the runner.
type Deps struct {
	Store    *store.Store
	Registry *registry.Registry
	Limiter  *limiter.Limiter
	Publish  func(event string, payload any)
	Logger   *log.Logger
	// NewProber builds an engine for the given options; nil uses probe.New.
	NewProber func(o probe.Options) Prober
	// BaseOptions carries timeouts and test hooks; route/family are set per run.
	BaseOptions       probe.Options
	Now               func() time.Time
	StabilityInterval time.Duration
	StabilityProbes   int
	Workers           int
}

// Request describes a run to start.
type Request struct {
	ProfileName     string            `json:"profileName"`
	Mode            model.RunMode     `json:"mode"`
	Route           model.RouteConfig `json:"route"`
	IPFamily        model.IPFamily    `json:"ipFamily"`
	EndpointIDs     []string          `json:"endpointIds"`
	ShowExternalIP  bool              `json:"showExternalIp"`
	SlowThresholdMs int               `json:"slowThresholdMs"`
	SystemProxyHint string            `json:"systemProxyHint"`
	// RecordIP asks for the exit IP for the IP log (set by the API from settings).
	RecordIP bool `json:"-"`
	// AltRoute enables diag mode: every endpoint is probed through Route and AltRoute.
	AltRoute *model.RouteConfig `json:"altRoute,omitempty"`
	// Environment is the network passport (JSON) captured by the caller at start.
	Environment json.RawMessage `json:"-"`
	// EnvMode and SplitTunnel feed the diagnostic analysis.
	EnvMode     string `json:"-"`
	SplitTunnel bool   `json:"-"`
}

// ActiveProbe is a probe in flight.
type ActiveProbe struct {
	EndpointID string      `json:"endpointId"`
	Host       string      `json:"host"`
	Attempt    int         `json:"attempt"`
	Stage      model.Stage `json:"stage"`
}

// Progress is the live state of the current run.
type Progress struct {
	RunID   string          `json:"runId"`
	Status  model.RunStatus `json:"status"`
	Total   int             `json:"total"`
	Done    int             `json:"done"`
	Active  []ActiveProbe   `json:"active"`
	Pending []string        `json:"pending"`
	Message string          `json:"message,omitempty"`
}

// Runner holds the single active run.
type Runner struct {
	d           Deps
	mu          sync.Mutex
	run         *model.Run
	prog        Progress
	cancel      context.CancelFunc
	done        chan struct{}
	active      map[string]*ActiveProbe
	th          classify.Thresholds
	envMode     string
	splitTunnel bool
}

// New creates a runner.
func New(d Deps) *Runner {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.NewProber == nil {
		d.NewProber = func(o probe.Options) Prober { return probe.New(o) }
	}
	if d.Publish == nil {
		d.Publish = func(string, any) {}
	}
	if d.Logger == nil {
		d.Logger = log.New(discard{}, "", 0)
	}
	if d.StabilityInterval <= 0 {
		d.StabilityInterval = app.StabilityInterval
	}
	if d.StabilityProbes <= 0 {
		d.StabilityProbes = app.StabilityProbes
	}
	if d.Workers <= 0 {
		d.Workers = app.MaxConcurrentProbes
	}
	return &Runner{d: d, active: map[string]*ActiveProbe{}}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// ValidateRoute checks a route configuration.
func ValidateRoute(rc model.RouteConfig) error {
	switch rc.Mode {
	case model.RouteSystem:
		return nil
	case model.RouteProxy:
		if rc.ProxyKind != model.ProxyHTTP && rc.ProxyKind != model.ProxySOCKS5 {
			return errors.New(i18n.T("тип прокси должен быть http или socks5"))
		}
		host, port, err := net.SplitHostPort(strings.TrimSpace(rc.ProxyAddr))
		if err != nil || host == "" {
			return errors.New(i18n.T("адрес прокси должен быть в виде host:port"))
		}
		if strings.ContainsAny(host, "@/ \\") {
			return errors.New(i18n.T("адрес прокси не должен содержать логин, пароль или путь"))
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return errors.New(i18n.T("некорректный порт прокси"))
		}
		return nil
	}
	return errors.New(i18n.T("режим маршрута должен быть system или proxy"))
}

// Start validates the request, claims the run slot and starts execution.
func (r *Runner) Start(req Request) (model.RunSummary, error) {
	if req.Mode != model.ModeFast && req.Mode != model.ModeStability && req.Mode != model.ModeDiag {
		return model.RunSummary{}, errors.New(i18n.T("режим должен быть fast, stability или diag"))
	}
	if req.Mode == model.ModeDiag {
		if req.AltRoute == nil {
			return model.RunSummary{}, errors.New(i18n.T("для диагностики нужен альтернативный маршрут"))
		}
		if err := ValidateRoute(*req.AltRoute); err != nil {
			return model.RunSummary{}, i18n.Errorf("альтернативный маршрут: %w", err)
		}
		if len(req.EndpointIDs) == 0 {
			return model.RunSummary{}, errors.New(i18n.T("для диагностики выберите группу или узлы"))
		}
		if len(req.EndpointIDs) > 12 {
			return model.RunSummary{}, errors.New(i18n.T("для диагностики не более 12 узлов"))
		}
	} else {
		req.AltRoute = nil
	}
	if err := ValidateRoute(req.Route); err != nil {
		return model.RunSummary{}, err
	}
	switch req.IPFamily {
	case "", model.FamilyAuto:
		req.IPFamily = model.FamilyAuto
	case model.FamilyV4, model.FamilyV6:
	default:
		return model.RunSummary{}, errors.New(i18n.T("семейство IP должно быть auto, ipv4 или ipv6"))
	}
	var notes []string
	if req.Route.Mode == model.RouteProxy && req.IPFamily != model.FamilyAuto {
		notes = append(notes, i18n.T("Выбор семейства IP не применяется в режиме прокси: имя разрешает прокси. Использован режим Auto."))
		req.IPFamily = model.FamilyAuto
	}
	eps, err := r.selectEndpoints(req)
	if err != nil {
		return model.RunSummary{}, err
	}
	if len(strings.TrimSpace(req.ProfileName)) > 80 {
		return model.RunSummary{}, errors.New(i18n.T("название профиля слишком длинное"))
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done != nil {
		select {
		case <-r.done:
		default:
			return model.RunSummary{}, limiter.ErrRunActive
		}
	}
	if err := r.d.Limiter.StartRun(); err != nil {
		return model.RunSummary{}, err
	}
	now := r.d.Now()
	run := &model.Run{
		SchemaVersion: model.SchemaVersion,
		ID:            store.NewRunID(now),
		ProfileName:   strings.TrimSpace(req.ProfileName),
		StartedAt:     now.UTC(),
		AppVersion:    app.Version,
		Mode:          req.Mode,
		Route:         req.Route,
		IPFamily:      req.IPFamily,
		SystemProxy:   req.SystemProxyHint,
		Endpoints:     eps,
		Results:       []model.ProbeResult{},
		Status:        model.RunRunning,
		Message:       strings.Join(notes, " "),
		AltRoute:      req.AltRoute,
		Environment:   req.Environment,
	}
	total := len(eps)
	if req.Mode == model.ModeStability {
		total *= r.d.StabilityProbes
	}
	if req.Mode == model.ModeDiag {
		total *= 2
	}
	pending := make([]string, 0, len(eps))
	for _, e := range eps {
		pending = append(pending, e.ID)
	}
	r.run = run
	r.prog = Progress{RunID: run.ID, Status: model.RunRunning, Total: total, Pending: pending, Active: []ActiveProbe{}}
	r.active = map[string]*ActiveProbe{}
	r.th = classify.Thresholds{SlowMs: req.SlowThresholdMs}
	r.envMode, r.splitTunnel = req.EnvMode, req.SplitTunnel
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	sum := run.Summary()
	r.d.Publish("run.started", map[string]any{"run": sum, "progress": r.prog})
	go r.execute(ctx, run, eps, req)
	return sum, nil
}

func (r *Runner) selectEndpoints(req Request) ([]model.Endpoint, error) {
	all := r.d.Registry.List()
	byID := map[string]model.Endpoint{}
	for _, e := range all {
		byID[e.ID] = e
	}
	var chosen []model.Endpoint
	if len(req.EndpointIDs) == 0 {
		if req.Mode == model.ModeStability {
			return nil, errors.New(i18n.T("для режима «Стабильность» выберите от 1 до 5 узлов"))
		}
		for _, e := range all {
			if e.Enabled {
				chosen = append(chosen, e)
			}
		}
	} else {
		seen := map[string]bool{}
		for _, id := range req.EndpointIDs {
			e, ok := byID[id]
			if !ok {
				return nil, i18n.Errorf("неизвестная контрольная точка %q", id)
			}
			if !e.Enabled {
				return nil, i18n.Errorf("точка %q выключена в реестре", id)
			}
			if !seen[id] {
				seen[id] = true
				chosen = append(chosen, e)
			}
		}
	}
	if len(chosen) == 0 {
		return nil, errors.New(i18n.T("нет включённых контрольных точек"))
	}
	if req.Mode == model.ModeStability && len(chosen) > app.StabilityMaxEndpoints {
		return nil, i18n.Errorf("для режима «Стабильность» можно выбрать не более %d узлов", app.StabilityMaxEndpoints)
	}
	return interleaveGroups(chosen), nil
}

// interleaveGroups orders endpoints round-robin across groups so that the
// per-group start spacing does not serialise the whole run.
func interleaveGroups(eps []model.Endpoint) []model.Endpoint {
	var order []string
	buckets := map[string][]model.Endpoint{}
	for _, e := range eps {
		if _, ok := buckets[e.GroupID]; !ok {
			order = append(order, e.GroupID)
		}
		buckets[e.GroupID] = append(buckets[e.GroupID], e)
	}
	out := make([]model.Endpoint, 0, len(eps))
	for len(out) < len(eps) {
		for _, g := range order {
			if len(buckets[g]) > 0 {
				out = append(out, buckets[g][0])
				buckets[g] = buckets[g][1:]
			}
		}
	}
	return out
}

// Cancel stops the active run. It returns false when nothing is running.
func (r *Runner) Cancel() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil || r.prog.Status != model.RunRunning {
		return false
	}
	r.prog.Message = i18n.T("Остановка: активные пробы завершаются, новые не запускаются")
	r.cancel()
	return true
}

// Wait blocks until the current run has finished (tests).
func (r *Runner) Wait() {
	r.mu.Lock()
	done := r.done
	r.mu.Unlock()
	if done != nil {
		<-done
	}
}

// Snapshot returns a copy of the current run and progress (nil run if none).
func (r *Runner) Snapshot() (*model.Run, Progress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.prog
	p.Active = make([]ActiveProbe, 0, len(r.active))
	for _, a := range r.active {
		p.Active = append(p.Active, *a)
	}
	p.Pending = append([]string(nil), r.prog.Pending...)
	if r.run == nil {
		return nil, p
	}
	cp := *r.run
	cp.Results = append(make([]model.ProbeResult, 0, len(r.run.Results)), r.run.Results...)
	cp.Endpoints = append(make([]model.Endpoint, 0, len(r.run.Endpoints)), r.run.Endpoints...)
	return &cp, p
}

func (r *Runner) proberFor(req Request, onStage func(model.Stage)) Prober {
	o := r.d.BaseOptions
	o.Route = req.Route
	o.Family = req.IPFamily
	o.OnStage = onStage
	return r.d.NewProber(o)
}

func (r *Runner) execute(ctx context.Context, run *model.Run, eps []model.Endpoint, req Request) {
	for _, ep := range eps {
		if ep.GroupID == "anthropic" {
			req.ShowExternalIP = true
			break
		}
	}
	if req.RecordIP {
		req.ShowExternalIP = true
	}
	defer func() {
		r.finish(ctx, run)
	}()
	if req.ShowExternalIP {
		r.externalIP(ctx, run, req, true)
	}
	var wg sync.WaitGroup
	if req.Mode == model.ModeDiag {
		// Two routes per endpoint: attempt 1 = selected route, attempt 2 = alternative.
		alt := req
		alt.Route = *req.AltRoute
		alt.IPFamily = model.FamilyAuto
		tasks := make(chan model.Endpoint)
		for i := 0; i < r.d.Workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ep := range tasks {
					r.doProbe(ctx, run, req, ep, 1)
					r.doProbe(ctx, run, alt, ep, 2)
				}
			}()
		}
		for _, ep := range eps {
			tasks <- ep
		}
		close(tasks)
	} else if req.Mode == model.ModeStability {
		for _, ep := range eps {
			wg.Add(1)
			go func(ep model.Endpoint) {
				defer wg.Done()
				for attempt := 1; attempt <= r.d.StabilityProbes; attempt++ {
					started := r.doProbe(ctx, run, req, ep, attempt)
					if attempt < r.d.StabilityProbes {
						// The interval counts from the actual start of the previous probe.
						wait := r.d.StabilityInterval - time.Since(started)
						if wait > 0 {
							t := time.NewTimer(wait)
							select {
							case <-t.C:
							case <-ctx.Done():
								t.Stop()
							}
						}
					}
				}
			}(ep)
		}
	} else {
		tasks := make(chan model.Endpoint)
		for i := 0; i < r.d.Workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ep := range tasks {
					r.doProbe(ctx, run, req, ep, 1)
				}
			}()
		}
		for _, ep := range eps {
			tasks <- ep
		}
		close(tasks)
	}
	wg.Wait()
	if req.ShowExternalIP {
		r.externalIP(ctx, run, req, false)
	}
}

// doProbe executes one probe (or records why it was skipped) and returns the
// monotonic time at which the probe actually started.
func (r *Runner) doProbe(ctx context.Context, run *model.Run, req Request, ep model.Endpoint, attempt int) time.Time {
	key := ep.ID + "#" + strconv.Itoa(attempt)
	base := model.ProbeResult{
		EndpointID: ep.ID, GroupID: ep.GroupID, Host: ep.Host, URL: ep.URL, Kind: ep.Kind,
		Attempt: attempt, StartedAt: r.d.Now().UTC(), Route: req.Route, IPFamily: req.IPFamily,
		ProfileVersion: registry.ProfileVersion,
	}
	r.removePending(ep.ID)
	if ctx.Err() != nil {
		res := base
		res.Skipped = true
		res.SkipReason = i18n.T("отменено до запуска")
		res.Outcome = classify.Cancelled()
		r.record(run, ep, res)
		return time.Now()
	}
	scope := ""
	if run.Mode == model.ModeDiag {
		scope = string(req.Route.Mode) + req.Route.ProxyAddr
	}
	if a := r.d.Limiter.AllowanceScoped(ep.Host, scope); !a.OK {
		res := base
		res.Skipped = true
		res.SkipReason = a.Reason
		label := i18n.T("Пропущено: ") + a.Reason
		if !a.Until.IsZero() {
			label += i18n.T(" (до ") + a.Until.Local().Format("15:04") + ")"
		}
		res.Outcome = classify.Skipped(a.Code, label)
		r.record(run, ep, res)
		return time.Now()
	}
	release, err := r.d.Limiter.Acquire(ctx, ep.Host, ep.GroupID)
	if err != nil {
		res := base
		res.Skipped = true
		res.SkipReason = i18n.T("отменено в очереди")
		res.Outcome = classify.Cancelled()
		r.record(run, ep, res)
		return time.Now()
	}
	ap := &ActiveProbe{EndpointID: ep.ID, Host: ep.Host, Attempt: attempt}
	r.mu.Lock()
	r.active[key] = ap
	r.mu.Unlock()
	r.d.Publish("probe.started", map[string]any{"endpointId": ep.ID, "host": ep.Host, "attempt": attempt, "progress": r.progress()})
	probeStart := time.Now()
	prober := r.proberFor(req, func(s model.Stage) {
		r.mu.Lock()
		ap.Stage = s
		r.mu.Unlock()
	})
	res := prober.Probe(ctx, ep)
	release()
	res.Attempt = attempt
	res.ProfileVersion = registry.ProfileVersion
	r.d.Limiter.ReportScoped(ep.Host, scope, &res)
	res.Outcome = classify.Probe(&res, ep, r.th)
	r.mu.Lock()
	delete(r.active, key)
	r.mu.Unlock()
	r.record(run, ep, res)
	return probeStart
}

func (r *Runner) removePending(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.prog.Pending {
		if p == id {
			r.prog.Pending = append(r.prog.Pending[:i], r.prog.Pending[i+1:]...)
			return
		}
	}
}

func (r *Runner) progress() Progress {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := r.prog
	p.Active = make([]ActiveProbe, 0, len(r.active))
	for _, a := range r.active {
		p.Active = append(p.Active, *a)
	}
	p.Pending = append([]string(nil), r.prog.Pending...)
	return p
}

func (r *Runner) record(run *model.Run, ep model.Endpoint, res model.ProbeResult) {
	r.mu.Lock()
	run.Results = append(run.Results, res)
	r.prog.Done++
	var groupResults []model.ProbeResult
	latest := map[string]model.ProbeResult{}
	for _, x := range run.Results {
		if x.GroupID == ep.GroupID {
			if prev, ok := latest[x.EndpointID]; !ok || x.Attempt >= prev.Attempt {
				latest[x.EndpointID] = x
			}
		}
	}
	for _, x := range latest {
		groupResults = append(groupResults, x)
	}
	r.mu.Unlock()
	g := classify.Group(ep.GroupID, ep.Group, groupResults)
	r.d.Publish("probe.finished", map[string]any{"result": res, "group": g, "progress": r.progress()})
}

func (r *Runner) finish(ctx context.Context, run *model.Run) {
	classify.Summarize(run)
	r.mu.Lock()
	dctx := diag.Context{PrimaryRoute: run.Route, AltRoute: run.AltRoute, EnvMode: r.envMode, SplitTunnel: r.splitTunnel}
	r.compareAnthropicIP(run)
	if run.ExternalIP != nil {
		dctx.ExitCountry = run.ExternalIP.Country
	}
	run.Verdicts = diag.Analyze(run, dctx)
	now := r.d.Now().UTC()
	run.FinishedAt = &now
	switch {
	case ctx.Err() != nil:
		run.Status = model.RunCancelled
		run.Message = strings.TrimSpace(run.Message + i18n.T(" Проверка остановлена пользователем; часть точек не проверена."))
	case run.Counts.Skipped > 0:
		run.Status = model.RunPartial
		run.Message = strings.TrimSpace(run.Message + i18n.T(" Часть точек пропущена из-за локальных ограничений частоты."))
	case run.Counts.Probed == 0:
		run.Status = model.RunFailed
	default:
		run.Status = model.RunCompleted
	}
	r.prog.Status = run.Status
	r.prog.Message = run.Message
	r.active = map[string]*ActiveProbe{}
	r.prog.Pending = nil
	done := r.done
	r.mu.Unlock()

	if r.d.Store != nil {
		if err := r.d.Store.SaveRun(run); err != nil {
			r.d.Logger.Printf("не удалось сохранить запуск %s: %v", run.ID, err)
			r.mu.Lock()
			r.prog.Message = strings.TrimSpace(r.prog.Message + i18n.T(" Не удалось сохранить запуск в историю: ") + err.Error())
			r.mu.Unlock()
		}
	}
	r.d.Limiter.EndRun()
	r.d.Publish("run.finished", map[string]any{"run": run.Summary(), "progress": r.progress(), "externalIp": run.ExternalIP, "message": run.Message})
	close(done)
}

// externalIP performs the optional public-IP observation through the same
// route and limiter. The provider and the fact of the request are recorded.
func (r *Runner) externalIP(ctx context.Context, run *model.Run, req Request, before bool) {
	r.mu.Lock()
	if run.ExternalIP == nil {
		run.ExternalIP = &model.ExternalIP{Provider: ExternalIPProvider.Name, ProviderURL: ExternalIPProvider.URL}
	}
	x := run.ExternalIP
	r.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	setErr := func(msg string) {
		r.mu.Lock()
		if x.Error == "" {
			x.Error = msg
		} else {
			x.Error += "; " + msg
		}
		r.mu.Unlock()
	}
	if a := r.d.Limiter.Allowance(ExternalIPProvider.Host); !a.OK {
		setErr(i18n.T("запрос внешнего IP пропущен: ") + a.Reason)
		return
	}
	release, err := r.d.Limiter.Acquire(ctx, ExternalIPProvider.Host, ExternalIPProvider.Group)
	if err != nil {
		return
	}
	prober := r.proberFor(req, nil)
	status, body, err := prober.FetchSmall(ctx, ExternalIPProvider.URL, 4096)
	release()
	if err != nil {
		setErr(i18n.T("внешний IP не получен: ") + err.Error())
		return
	}
	if status != 200 {
		setErr(i18n.T("внешний IP не получен: статус %d", status))
		return
	}
	ip, loc := parseTrace(string(body))
	if ip == "" {
		setErr(i18n.T("внешний IP не получен: ответ провайдера не содержит ip="))
		return
	}
	r.mu.Lock()
	if before {
		x.Before = ip
		x.Country = loc
	} else {
		x.After = ip
		x.AfterCountry = loc
		if x.Country == "" {
			x.Country = loc
		}
		x.Changed = x.Before != "" && x.Before != x.After
	}
	r.mu.Unlock()
	r.d.Publish("externalip", map[string]any{"externalIp": x, "phase": map[bool]string{true: "before", false: "after"}[before]})
}

// ParseTrace reads ip= and loc= from a Cloudflare /cdn-cgi/trace answer.
func ParseTrace(s string) (ip, loc string) { return parseTrace(s) }

func parseTrace(s string) (ip, loc string) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			if net.ParseIP(v) != nil {
				ip = v
			}
		case "loc":
			if len(v) <= 3 {
				loc = strings.ToUpper(v)
			}
		}
	}
	return ip, loc
}
