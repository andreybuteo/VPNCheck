package api

import (
	"errors"
	"net/http"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/i18n"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/speed"
)

// speedView is the speed-test part of /api/state and GET /api/speed.
func (a *API) speedView() map[string]any {
	if a.d.Speed == nil {
		return map[string]any{"enabled": false}
	}
	hist := a.d.Speed.History()
	if hist == nil {
		hist = []speed.Result{}
	}
	return map[string]any{
		"enabled": true,
		"servers": speed.Servers,
		"current": a.d.Speed.Current(),
		"history": hist,
		"limits":  a.d.Limiter.Speed(),
		"plan": map[string]any{
			"phaseSec":     app.SpeedPhase.Seconds(),
			"parallel":     app.SpeedParallel,
			"downCapMB":    app.SpeedDownCap >> 20,
			"upCapMB":      app.SpeedUpCap >> 20,
			"latencyCount": app.SpeedLatencySamples,
		},
	}
}

func (a *API) handleSpeedState(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.speedView())
}

type speedRequest struct {
	ProfileName string            `json:"profileName"`
	Route       model.RouteConfig `json:"route"`
	ServerID    string            `json:"serverId"`
}

func (a *API) handleSpeedStart(w http.ResponseWriter, r *http.Request) {
	if a.d.Speed == nil {
		writeErr(w, http.StatusNotFound, "speed_off", i18n.T("Замер скорости недоступен."), nil)
		return
	}
	var req speedRequest
	if err := readJSON(r, &req, 16*1024); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}
	p, err := a.d.Speed.Start(speed.Request{ProfileName: req.ProfileName, Route: req.Route, ServerID: req.ServerID, RecordIP: a.ipLogOn()})
	if err != nil {
		var ce *limiter.CooldownError
		var dc *limiter.DailyCapError
		var be *limiter.BlockedError
		switch {
		case errors.As(err, &ce):
			writeErr(w, http.StatusTooManyRequests, "speed_cooldown", i18n.T("Между замерами скорости нужна пауза %d мин. Следующий замер через %d с.", int(app.SpeedCooldown.Minutes()), int(ce.Wait.Seconds())+1), map[string]any{"until": ce.Until.UTC()})
		case errors.As(err, &dc):
			writeErr(w, http.StatusTooManyRequests, "speed_daily_cap", i18n.T("За сутки сделано %d замеров — это предел. Следующий возможен после %s.", dc.Cap, dc.Until.Local().Format("02.01 15:04")), map[string]any{"until": dc.Until.UTC()})
		case errors.As(err, &be):
			writeErr(w, http.StatusTooManyRequests, "speed_blocked", i18n.T("Сервер %s приостановлен до %s: %s. Выберите другой сервер в настройках.", be.Host, be.Block.Until.Local().Format("02.01 15:04"), be.Block.Reason), map[string]any{"until": be.Block.Until.UTC()})
		case errors.Is(err, limiter.ErrRunActive):
			writeErr(w, http.StatusConflict, "run_active", i18n.T("Идёт проверка сервисов: замер скорости можно запустить после неё."), nil)
		case errors.Is(err, limiter.ErrSpeedActive):
			writeErr(w, http.StatusConflict, "speed_active", i18n.T("Замер скорости уже идёт."), nil)
		default:
			writeErr(w, http.StatusBadRequest, "invalid", err.Error(), nil)
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"progress": p, "startedAt": time.Now().UTC()})
}

func (a *API) handleSpeedCancel(w http.ResponseWriter, _ *http.Request) {
	ok := a.d.Speed != nil && a.d.Speed.Cancel()
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": ok})
}

func (a *API) handleSpeedDelete(w http.ResponseWriter, r *http.Request) {
	if a.d.Speed == nil || !a.d.Speed.Delete(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "not_found", i18n.T("Замер не найден."), nil)
		return
	}
	writeJSON(w, http.StatusOK, a.speedView())
}
