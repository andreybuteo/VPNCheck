// Package api mounts the JSON endpoints used by the embedded UI on the
// protected local server. Nothing here performs external network requests on
// its own: probes start only from POST /api/run.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/classify"
	"vpncheck/internal/guard"
	"vpncheck/internal/i18n"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/registry"
	"vpncheck/internal/report"
	"vpncheck/internal/runner"
	"vpncheck/internal/server"
	"vpncheck/internal/speed"
	"vpncheck/internal/store"
	"vpncheck/internal/sysenv"
	"vpncheck/internal/sysproxy"
)

// Deps are the wired components.
type Deps struct {
	Server       *server.Server
	Store        *store.Store
	Registry     *registry.Registry
	RegistryInfo registry.LoadInfo
	Limiter      *limiter.Limiter
	Runner       *runner.Runner
	Speed        *speed.Runner
	Settings     model.Settings
	SettingsInfo store.LoadInfo
	Logger       *log.Logger
	// Demo marks the QA mode with fabricated results (see package demo).
	Demo bool
}

// API holds mutable state shared by handlers.
type API struct {
	d        Deps
	mu       sync.Mutex
	settings model.Settings
	warnings []string
}

// Mount registers all handlers.
func Mount(d Deps) *API {
	a := &API{d: d, settings: d.Settings}
	if d.SettingsInfo.Corrupt {
		a.warnings = append(a.warnings, i18n.T("Файл настроек был повреждён и заменён значениями по умолчанию. Копия сохранена рядом: ")+baseName(d.SettingsInfo.Backup))
	}
	if d.RegistryInfo.Corrupt {
		a.warnings = append(a.warnings, i18n.T("Файл реестра был повреждён; используется встроенный набор. Копия: ")+baseName(d.RegistryInfo.Backup))
	}
	if d.RegistryInfo.Invalid != "" {
		a.warnings = append(a.warnings, i18n.T("Файл реестра не прошёл проверку и не применён: ")+d.RegistryInfo.Invalid)
	}
	s := apiRouter{d.Server}
	s.HandleAPI("GET /api/i18n/{lang}", a.handleCatalog)
	s.HandleAPI("GET /api/state", a.handleState)
	s.HandleAPI("PUT /api/settings", a.handlePutSettings)
	s.HandleAPI("POST /api/run", a.handleStartRun)
	s.HandleAPI("POST /api/run/cancel", a.handleCancelRun)
	s.HandleAPI("GET /api/run/current", a.handleCurrentRun)
	s.HandleAPI("GET /api/history", a.handleHistory)
	s.HandleAPI("GET /api/history/{id}", a.handleHistoryGet)
	s.HandleAPI("DELETE /api/history/{id}", a.handleHistoryDelete)
	s.HandleAPI("GET /api/compare", a.handleCompare)
	s.HandleAPI("GET /api/export/{id}/json", a.handleExportJSON)
	s.HandleAPI("GET /api/export/{id}/csv", a.handleExportCSV)
	s.HandleAPI("GET /api/summary/{id}", a.handleSummary)
	s.HandleAPI("GET /api/registry", a.handleRegistryList)
	s.HandleAPI("PUT /api/registry/{id}/enabled", a.handleRegistryEnabled)
	s.HandleAPI("POST /api/registry", a.handleRegistryUpsert)
	s.HandleAPI("DELETE /api/registry/{id}", a.handleRegistryDelete)
	s.HandleAPI("POST /api/registry/import", a.handleRegistryImport)
	s.HandleAPI("GET /api/registry/export", a.handleRegistryExport)
	s.HandleAPI("POST /api/registry/reset", a.handleRegistryReset)
	s.HandleAPI("GET /api/sysproxy", a.handleSysProxy)
	s.HandleAPI("GET /api/environment", a.handleEnvironment)
	s.HandleAPI("POST /api/diagnose", a.handleDiagnose)
	s.HandleAPI("GET /api/report/{id}/json", a.handleReport)
	s.HandleAPI("GET /api/speed", a.handleSpeedState)
	s.HandleAPI("POST /api/speed", a.handleSpeedStart)
	s.HandleAPI("POST /api/speed/cancel", a.handleSpeedCancel)
	s.HandleAPI("DELETE /api/speed/{id}", a.handleSpeedDelete)
	return a
}

func baseName(p string) string {
	if p == "" {
		return "—"
	}
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	body := map[string]any{"error": code, "message": i18n.T(msg)}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

func readJSON(r *http.Request, v any, limit int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New(i18n.T("некорректный JSON: ") + err.Error())
	}
	return nil
}

type limiterView struct {
	CooldownUntil *time.Time  `json:"cooldownUntil"`
	RunActive     bool        `json:"runActive"`
	Blocks        []blockView `json:"blocks"`
}

type blockView struct {
	Host   string    `json:"host"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}

func (a *API) limiterView() limiterView {
	v := limiterView{RunActive: a.d.Limiter.RunActive(), Blocks: []blockView{}}
	if u := a.d.Limiter.CooldownUntil(); !u.IsZero() {
		u = u.UTC()
		v.CooldownUntil = &u
	}
	snap := a.d.Limiter.Snapshot()
	for h, b := range snap.HostBlocks {
		v.Blocks = append(v.Blocks, blockView{Host: h, Until: b.Until.UTC(), Reason: b.Reason})
	}
	return v
}

type currentView struct {
	Run       *model.Run                `json:"run"`
	Progress  runner.Progress           `json:"progress"`
	Groups    []classify.GroupSummary   `json:"groups"`
	Stability map[string]classify.Stats `json:"stability,omitempty"`
}

func viewOf(run *model.Run, prog runner.Progress) currentView {
	v := currentView{Run: run, Progress: prog, Groups: []classify.GroupSummary{}}
	if run == nil {
		return v
	}
	v.Groups = report.GroupSummaries(run)
	if run.Mode == model.ModeStability {
		v.Stability = map[string]classify.Stats{}
		byID := map[string][]model.ProbeResult{}
		for _, r := range run.Results {
			byID[r.EndpointID] = append(byID[r.EndpointID], r)
		}
		for id, list := range byID {
			v.Stability[id] = classify.Stability(list)
		}
	}
	return v
}

func (a *API) handleState(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	settings := a.settings
	warnings := append([]string(nil), a.warnings...)
	a.mu.Unlock()
	run, prog := a.d.Runner.Snapshot()
	history, _ := a.d.Store.ListRuns()
	if history == nil {
		history = []model.RunSummary{}
	}
	groups := []map[string]string{}
	for _, g := range a.d.Registry.Groups() {
		groups = append(groups, map[string]string{"id": g.ID, "name": g.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"app":         map[string]any{"name": app.Name, "version": app.Version, "dataDir": a.d.Store.Dir(), "demo": a.d.Demo},
		"settings":    settings,
		"warnings":    warnings,
		"registry":    map[string]any{"endpoints": a.d.Registry.List(), "groups": groups, "profileVersion": registry.ProfileVersion},
		"limiter":     a.limiterView(),
		"current":     viewOf(run, prog),
		"sysproxy":    sysproxy.Detect(),
		"environment": sysenv.Collect(),
		"history":     history,
		"speed":       a.speedView(),
		"ipLog":       a.ipLog(),
		"limits": map[string]any{
			"probeTimeoutMs":       app.ProbeTimeout.Milliseconds(),
			"tcpTimeoutMs":         app.TCPTimeout.Milliseconds(),
			"tlsTimeoutMs":         app.TLSTimeout.Milliseconds(),
			"maxConcurrent":        app.MaxConcurrentProbes,
			"cooldownSec":          int(a.d.Limiter.Cooldown().Seconds()),
			"cooldownMinSec":       int(app.MinRunCooldown.Seconds()),
			"cooldownMaxSec":       int(app.MaxRunCooldown.Seconds()),
			"hostHourlyCap":        app.HostHourlyCap,
			"stabilityProbes":      app.StabilityProbes,
			"stabilityIntervalSec": int(app.StabilityInterval.Seconds()),
			"stabilityMax":         app.StabilityMaxEndpoints,
			"maxBodyBytes":         app.MaxBodyBytes,
			"historyLimit":         app.HistoryLimit,
		},
		"externalIpProvider": map[string]string{"name": runner.ExternalIPProvider.Name, "url": runner.ExternalIPProvider.URL},
	})
}

func validateSettings(s *model.Settings) error {
	s.ProfileName = strings.TrimSpace(s.ProfileName)
	if len([]rune(s.ProfileName)) > 80 {
		return errors.New(i18n.T("название профиля: не более 80 символов"))
	}
	if s.Theme != "light" && s.Theme != "dark" {
		return errors.New(i18n.T("тема должна быть dark или light"))
	}
	if err := runner.ValidateRoute(s.Route); err != nil {
		return err
	}
	if s.Route.Mode == model.RouteSystem {
		s.Route.ProxyKind, s.Route.ProxyAddr = "", ""
	}
	switch s.IPFamily {
	case "", model.FamilyAuto:
		s.IPFamily = model.FamilyAuto
	case model.FamilyV4, model.FamilyV6:
	default:
		return errors.New(i18n.T("семейство IP должно быть auto, ipv4 или ipv6"))
	}
	if s.Mode != model.ModeFast && s.Mode != model.ModeStability {
		return errors.New(i18n.T("режим должен быть fast или stability"))
	}
	if s.SlowThresholdMs < 0 || s.SlowThresholdMs > 60000 {
		return errors.New(i18n.T("порог «медленно» должен быть от 0 до 60000 мс (0 — выключить)"))
	}
	if s.RunCooldownSec == 0 {
		s.RunCooldownSec = int(app.RunCooldown.Seconds())
	}
	if minS, maxS := int(app.MinRunCooldown.Seconds()), int(app.MaxRunCooldown.Seconds()); s.RunCooldownSec < minS || s.RunCooldownSec > maxS {
		return i18n.Errorf("пауза между запусками должна быть от %d до %d с", minS, maxS)
	}
	if s.Language != "" && !i18n.Supported(s.Language) {
		return errors.New(i18n.T("неизвестный язык интерфейса"))
	}
	if s.SpeedServer == "" {
		s.SpeedServer = "cloudflare"
	}
	if _, ok := speed.ServerByID(s.SpeedServer); !ok {
		return errors.New(i18n.T("неизвестный сервер замера скорости"))
	}
	if len(s.SelectedEndpoints) > 500 || len(s.StabilityEndpoints) > app.StabilityMaxEndpoints {
		return errors.New(i18n.T("слишком длинный список выбранных точек"))
	}
	if s.SelectedEndpoints == nil {
		s.SelectedEndpoints = []string{}
	}
	if s.StabilityEndpoints == nil {
		s.StabilityEndpoints = []string{}
	}
	s.SchemaVersion = model.SchemaVersion
	return nil
}

func (a *API) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var s model.Settings
	if err := readJSON(r, &s, 64*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if err := validateSettings(&s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		return
	}
	if err := a.d.Store.SaveSettings(s); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", i18n.T("не удалось сохранить настройки: ")+err.Error(), nil)
		return
	}
	a.mu.Lock()
	a.settings = s
	a.mu.Unlock()
	a.applyCooldown(s)
	writeJSON(w, http.StatusOK, s)
}

// applyCooldown passes the user's pause between runs to the limiter. The demo
// mode keeps its own short QA pause.
func (a *API) applyCooldown(s model.Settings) {
	if a.d.Demo || s.RunCooldownSec <= 0 {
		return
	}
	a.d.Limiter.SetRunCooldown(time.Duration(s.RunCooldownSec) * time.Second)
}

type startRequest struct {
	ProfileName     string            `json:"profileName"`
	Mode            model.RunMode     `json:"mode"`
	Route           model.RouteConfig `json:"route"`
	IPFamily        model.IPFamily    `json:"ipFamily"`
	EndpointIDs     []string          `json:"endpointIds"`
	ShowExternalIP  bool              `json:"showExternalIp"`
	SlowThresholdMs int               `json:"slowThresholdMs"`
}

func (a *API) handleStartRun(w http.ResponseWriter, r *http.Request) {
	var req startRequest
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	env := sysenv.Collect()
	envJSON, _ := json.Marshal(env)
	hint := sysproxy.Detect()
	sum, err := a.d.Runner.Start(runner.Request{
		Environment:     envJSON,
		EnvMode:         env.Verdict.Mode,
		SplitTunnel:     env.SplitTunnelNote() != "",
		ProfileName:     req.ProfileName,
		Mode:            req.Mode,
		Route:           req.Route,
		IPFamily:        req.IPFamily,
		EndpointIDs:     req.EndpointIDs,
		ShowExternalIP:  req.ShowExternalIP,
		SlowThresholdMs: req.SlowThresholdMs,
		SystemProxyHint: hint.Short(),
		RecordIP:        a.ipLogOn(),
	})
	if err != nil {
		var ce *limiter.CooldownError
		switch {
		case errors.As(err, &ce):
			writeErr(w, http.StatusTooManyRequests, "cooldown", i18n.T("Между запусками нужна пауза %d с. Следующий запуск через %d с.", int(a.d.Limiter.Cooldown().Seconds()), int(ce.Wait.Seconds())+1), map[string]any{"until": ce.Until.UTC()})
		case errors.Is(err, limiter.ErrRunActive):
			writeErr(w, http.StatusConflict, "run_active", i18n.T("Проверка уже выполняется."), nil)
		case errors.Is(err, limiter.ErrSpeedActive):
			writeErr(w, http.StatusConflict, "speed_active", i18n.T("Идёт замер скорости: дождитесь его окончания или остановите его."), nil)
		default:
			writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"run": sum})
}

func (a *API) handleCancelRun(w http.ResponseWriter, _ *http.Request) {
	ok := a.d.Runner.Cancel()
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": ok})
}

func (a *API) handleCurrentRun(w http.ResponseWriter, _ *http.Request) {
	run, prog := a.d.Runner.Snapshot()
	writeJSON(w, http.StatusOK, viewOf(run, prog))
}

func (a *API) handleHistory(w http.ResponseWriter, _ *http.Request) {
	list, err := a.d.Store.ListRuns()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	if list == nil {
		list = []model.RunSummary{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) loadRun(w http.ResponseWriter, id string) *model.Run {
	// The active run is served from memory so history can show it live.
	if cur, prog := a.d.Runner.Snapshot(); cur != nil && cur.ID == id && prog.Status == model.RunRunning {
		return cur
	}
	run, err := a.d.Store.LoadRun(id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeErr(w, http.StatusNotFound, "not_found", i18n.T("Запуск не найден."), nil)
		} else if errors.Is(err, store.ErrInvalidID) {
			writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		} else {
			writeErr(w, http.StatusInternalServerError, "store", err.Error(), nil)
		}
		return nil
	}
	return run
}

func (a *API) handleHistoryGet(w http.ResponseWriter, r *http.Request) {
	run := a.loadRun(w, r.PathValue("id"))
	if run == nil {
		return
	}
	_, prog := a.d.Runner.Snapshot()
	if prog.RunID != run.ID {
		prog = runner.Progress{RunID: run.ID, Status: run.Status, Total: len(run.Results), Done: len(run.Results), Active: []runner.ActiveProbe{}, Pending: []string{}}
	}
	writeJSON(w, http.StatusOK, viewOf(run, prog))
}

func (a *API) handleHistoryDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if cur, prog := a.d.Runner.Snapshot(); cur != nil && cur.ID == id && prog.Status == model.RunRunning {
		writeErr(w, http.StatusConflict, "run_active", i18n.T("Нельзя удалить выполняющийся запуск."), nil)
		return
	}
	if err := a.d.Store.DeleteRun(id); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *API) handleCompare(w http.ResponseWriter, r *http.Request) {
	ra := a.loadRun(w, r.URL.Query().Get("a"))
	if ra == nil {
		return
	}
	rb := a.loadRun(w, r.URL.Query().Get("b"))
	if rb == nil {
		return
	}
	writeJSON(w, http.StatusOK, report.Compare(ra, rb))
}

func exportOptions(r *http.Request) report.Options {
	return report.Options{IncludeSensitive: r.URL.Query().Get("sensitive") == "1"}
}

func safeFileName(run *model.Run, ext string) string {
	name := "vpncheck-" + run.StartedAt.UTC().Format("20060102-150405")
	if run.ProfileName != "" {
		clean := strings.Map(func(c rune) rune {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c >= 'А' && c <= 'я' || c == 'ё' || c == 'Ё' {
				return c
			}
			return '_'
		}, run.ProfileName)
		if len([]rune(clean)) > 40 {
			clean = string([]rune(clean)[:40])
		}
		name += "-" + clean
	}
	return name + ext
}

func (a *API) handleExportJSON(w http.ResponseWriter, r *http.Request) {
	run := a.loadRun(w, r.PathValue("id"))
	if run == nil {
		return
	}
	data, err := report.ExportJSON(run, exportOptions(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlEncode(safeFileName(run, ".json")))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (a *API) handleExportCSV(w http.ResponseWriter, r *http.Request) {
	run := a.loadRun(w, r.PathValue("id"))
	if run == nil {
		return
	}
	data := report.ExportCSV(run, exportOptions(r))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlEncode(safeFileName(run, ".csv")))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (a *API) handleSummary(w http.ResponseWriter, r *http.Request) {
	run := a.loadRun(w, r.PathValue("id"))
	if run == nil {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, report.Summary(run, exportOptions(r)))
}

func urlEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (a *API) handleRegistryList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": a.d.Registry.List(), "profileVersion": registry.ProfileVersion})
}

func (a *API) handleRegistryEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &body, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if err := a.d.Registry.SetEnabled(r.PathValue("id"), body.Enabled); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": a.d.Registry.List()})
}

func (a *API) handleRegistryUpsert(w http.ResponseWriter, r *http.Request) {
	var ep model.Endpoint
	if err := readJSON(r, &ep, 16*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if ep.ID == "" {
		ep.ID = "custom-" + strings.Map(func(c rune) rune {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
				return c
			}
			return '-'
		}, strings.ToLower(ep.Host))
	}
	if ep.GroupID == "" {
		ep.GroupID = "custom"
	}
	if ep.Group == "" {
		ep.Group = i18n.T("Свои точки")
	}
	if err := registry.Validate(ep, guard.Default()); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		return
	}
	if err := a.d.Registry.Upsert(ep); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": a.d.Registry.List()})
}

func (a *API) handleRegistryDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.d.Registry.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": a.d.Registry.List()})
}

func (a *API) handleRegistryImport(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	if err := a.d.Registry.Import(data); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid", i18n.T("Импорт отклонён, прежняя конфигурация сохранена: ")+err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": a.d.Registry.List()})
}

func (a *API) handleRegistryExport(w http.ResponseWriter, _ *http.Request) {
	data, err := a.d.Registry.Export()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=vpncheck-registry.json")
	_, _ = w.Write(data)
}

func (a *API) handleRegistryReset(w http.ResponseWriter, _ *http.Request) {
	if err := a.d.Registry.Reset(); err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"endpoints": a.d.Registry.List()})
}

func (a *API) handleSysProxy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, sysproxy.Detect())
}

func (a *API) handleEnvironment(w http.ResponseWriter, _ *http.Request) {
	env := sysenv.Collect()
	writeJSON(w, http.StatusOK, map[string]any{"environment": env, "splitTunnelNote": env.SplitTunnelNote(), "short": env.Short()})
}

type diagnoseRequest struct {
	ProfileName     string            `json:"profileName"`
	Route           model.RouteConfig `json:"route"`
	GroupID         string            `json:"groupId"`
	EndpointIDs     []string          `json:"endpointIds"`
	ShowExternalIP  bool              `json:"showExternalIp"`
	SlowThresholdMs int               `json:"slowThresholdMs"`
}

// handleDiagnose starts a diag run: the group's endpoints through the selected
// route and through the alternative route derived from the environment.
func (a *API) handleDiagnose(w http.ResponseWriter, r *http.Request) {
	var req diagnoseRequest
	if err := readJSON(r, &req, 64*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	ids := req.EndpointIDs
	if req.GroupID != "" {
		for _, e := range a.d.Registry.List() {
			if e.GroupID == req.GroupID && e.Enabled {
				ids = append(ids, e.ID)
			}
		}
	}
	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, "invalid", i18n.T("Для диагностики нужна группа с включёнными узлами."), nil)
		return
	}
	env := sysenv.Collect()
	envJSON, _ := json.Marshal(env)
	var alt model.RouteConfig
	if req.Route.Mode == model.RouteProxy {
		alt = model.RouteConfig{Mode: model.RouteSystem}
	} else {
		switch {
		case env.Verdict.SuggestedRoute != nil && env.Verdict.SuggestedRoute.Mode == model.RouteProxy:
			alt = *env.Verdict.SuggestedRoute
		case env.Proxies.Suggested != nil:
			alt = *env.Proxies.Suggested
		default:
			writeErr(w, http.StatusBadRequest, "no_alt_route", i18n.T("Альтернативный маршрут не найден: локальный прокси VPN-клиента не обнаружен. Задайте прокси в настройках и запустите диагностику из режима «Прокси»."), nil)
			return
		}
	}
	hint := sysproxy.Detect()
	sum, err := a.d.Runner.Start(runner.Request{
		ProfileName: req.ProfileName, Mode: model.ModeDiag, Route: req.Route, IPFamily: model.FamilyAuto,
		EndpointIDs: ids, ShowExternalIP: req.ShowExternalIP, SlowThresholdMs: req.SlowThresholdMs, RecordIP: a.ipLogOn(),
		SystemProxyHint: hint.Short(), AltRoute: &alt, Environment: envJSON, EnvMode: env.Verdict.Mode, SplitTunnel: env.SplitTunnelNote() != "",
	})
	if err != nil {
		var ce *limiter.CooldownError
		switch {
		case errors.As(err, &ce):
			writeErr(w, http.StatusTooManyRequests, "cooldown", i18n.T("Между запусками нужна пауза %d с. Диагностика возможна через %d с.", int(a.d.Limiter.Cooldown().Seconds()), int(ce.Wait.Seconds())+1), map[string]any{"until": ce.Until.UTC()})
		case errors.Is(err, limiter.ErrRunActive):
			writeErr(w, http.StatusConflict, "run_active", i18n.T("Проверка уже выполняется."), nil)
		case errors.Is(err, limiter.ErrSpeedActive):
			writeErr(w, http.StatusConflict, "speed_active", i18n.T("Идёт замер скорости: дождитесь его окончания или остановите его."), nil)
		default:
			writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"run": sum, "altRoute": alt})
}

func (a *API) handleReport(w http.ResponseWriter, r *http.Request) {
	run := a.loadRun(w, r.PathValue("id"))
	if run == nil {
		return
	}
	envJSON, _ := json.Marshal(sysenv.Collect())
	data, err := report.Diagnostic(run, envJSON, exportOptions(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "export", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlEncode(safeFileName(run, "-diagnostic.json")))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
