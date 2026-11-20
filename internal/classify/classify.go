// Package classify turns raw probe results into honest, human-readable
// outcomes (spec §8). The transport result and the HTTP result stay separate;
// the outcome is one label that never hides the actual status code.
package classify

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// Thresholds are local display heuristics, not service SLAs.
type Thresholds struct {
	// SlowMs marks a successful probe as "slow" when tlsReadyMs exceeds it.
	SlowMs int
}

// Skipped builds the outcome for a probe that was not executed.
func Skipped(code, label string) model.Outcome {
	return model.Outcome{Code: code, Label: label, Level: model.LevelNeutral}
}

// Cancelled is the outcome for a probe interrupted by the user.
func Cancelled() model.Outcome {
	return model.Outcome{Code: "cancelled", Label: i18n.T("Отменено"), Level: model.LevelNeutral}
}

// Probe classifies one result. ep provides the expected statuses.
func Probe(r *model.ProbeResult, ep model.Endpoint, th Thresholds) model.Outcome {
	if r.Skipped {
		if r.Outcome.Code != "" {
			return r.Outcome
		}
		return Skipped("skipped", i18n.T("Пропущено"))
	}
	tr := r.Transport
	if !tr.OK {
		return transportOutcome(tr)
	}
	slow := th.SlowMs > 0 && r.Timings.TLSReadyMs != nil && *r.Timings.TLSReadyMs > float64(th.SlowMs)
	if r.Kind == model.KindTLS || r.HTTP == nil {
		o := model.Outcome{Code: "tls_ok", Label: i18n.T("TLS доступен; работа приложения не проверялась"), Level: model.LevelOK}
		if slow {
			o.Code = "tls_slow"
			o.Label = i18n.T("TLS доступен, но медленно; работа приложения не проверялась")
			o.Level = model.LevelWarn
			o.Detail = slowDetail(r, th)
		}
		return o
	}
	return httpOutcome(r, ep, slow, th)
}

func slowDetail(r *model.ProbeResult, th Thresholds) string {
	return i18n.T("время до готовности TLS %.0f мс превышает локальный порог %d мс", *r.Timings.TLSReadyMs, th.SlowMs)
}

func transportOutcome(tr model.Transport) model.Outcome {
	detail := tr.ErrorText
	switch tr.ErrorKind {
	case model.ErrCancelled:
		return model.Outcome{Code: "cancelled", Label: i18n.T("Отменено"), Level: model.LevelNeutral}
	case model.ErrBlockedAddr:
		return model.Outcome{Code: "blocked_address", Label: i18n.T("Адрес заблокирован политикой безопасности приложения"), Level: model.LevelError, Detail: detail}
	case model.ErrProxy:
		return model.Outcome{Code: "proxy_error", Label: i18n.T("Ошибка прокси; целевой сервер не проверен"), Level: model.LevelError, Detail: detail}
	}
	switch tr.FailedStage {
	case model.StageDNS:
		if tr.ErrorKind == model.ErrTimeout {
			return model.Outcome{Code: "dns_timeout", Label: i18n.T("DNS: тайм-аут разрешения имени"), Level: model.LevelError, Detail: detail}
		}
		return model.Outcome{Code: "dns_error", Label: i18n.T("DNS: имя не разрешается"), Level: model.LevelError, Detail: detail}
	case model.StageTCP:
		switch tr.ErrorKind {
		case model.ErrTimeout:
			return model.Outcome{Code: "tcp_timeout", Label: i18n.T("TCP: тайм-аут подключения"), Level: model.LevelError, Detail: detail}
		case model.ErrRefused:
			return model.Outcome{Code: "tcp_refused", Label: i18n.T("TCP: соединение отклонено"), Level: model.LevelError, Detail: detail}
		case model.ErrUnreachable:
			return model.Outcome{Code: "tcp_unreachable", Label: i18n.T("TCP: сеть или узел недоступны"), Level: model.LevelError, Detail: detail}
		case model.ErrReset:
			return model.Outcome{Code: "tcp_reset", Label: i18n.T("TCP: соединение сброшено"), Level: model.LevelError, Detail: detail}
		}
		return model.Outcome{Code: "tcp_error", Label: i18n.T("TCP: ошибка подключения"), Level: model.LevelError, Detail: detail}
	case model.StageProxy:
		return model.Outcome{Code: "proxy_error", Label: i18n.T("Ошибка прокси; целевой сервер не проверен"), Level: model.LevelError, Detail: detail}
	case model.StageTLS:
		switch tr.ErrorKind {
		case model.ErrTLSCert:
			return model.Outcome{Code: "tls_cert_error", Label: i18n.T("TLS: сертификат не прошёл проверку"), Level: model.LevelError, Detail: detail}
		case model.ErrTimeout:
			return model.Outcome{Code: "tls_timeout", Label: i18n.T("TLS: тайм-аут рукопожатия"), Level: model.LevelError, Detail: detail}
		case model.ErrReset:
			return model.Outcome{Code: "tls_reset", Label: i18n.T("TLS: соединение сброшено во время рукопожатия"), Level: model.LevelError, Detail: detail}
		}
		return model.Outcome{Code: "tls_handshake_error", Label: i18n.T("TLS: ошибка рукопожатия"), Level: model.LevelError, Detail: detail}
	case model.StageHTTP:
		switch tr.ErrorKind {
		case model.ErrTimeout:
			return model.Outcome{Code: "http_timeout", Label: i18n.T("HTTP: нет ответа (тайм-аут); TLS был успешен"), Level: model.LevelError, Detail: detail}
		case model.ErrReset:
			return model.Outcome{Code: "http_reset", Label: i18n.T("HTTP: соединение закрыто до ответа; TLS был успешен"), Level: model.LevelError, Detail: detail}
		}
		return model.Outcome{Code: "http_error", Label: i18n.T("HTTP: ошибка обмена; TLS был успешен"), Level: model.LevelError, Detail: detail}
	}
	return model.Outcome{Code: "error", Label: i18n.T("Ошибка проверки"), Level: model.LevelError, Detail: detail}
}

func httpOutcome(r *model.ProbeResult, ep model.Endpoint, slow bool, th Thresholds) model.Outcome {
	h := r.HTTP
	expected := false
	for _, s := range ep.ExpectedStatuses {
		if s == h.Status {
			expected = true
			break
		}
	}
	var o model.Outcome
	bodyNote := ""
	if h.BodyError != "" {
		bodyNote = i18n.T("тело ответа дочитать не удалось: ") + h.BodyError
	}
	switch {
	case h.Captcha:
		o = model.Outcome{Code: "captcha", Label: i18n.T("Запрос отклонён / требуется проверка (%d); причина не установлена", h.Status), Level: model.LevelWarn}
	case expected && h.Status == 401:
		o = model.Outcome{Code: "http_expected", Label: i18n.T("Сервер ответил; требуется авторизация (ожидаемо для API без ключа)"), Level: model.LevelOK}
	case expected:
		o = model.Outcome{Code: "http_expected", Label: i18n.T("Контрольный ресурс доступен (%d)", h.Status), Level: model.LevelOK}
	case h.Status == 401:
		o = model.Outcome{Code: "http_401", Label: i18n.T("Сервер ответил; требуется авторизация"), Level: model.LevelWarn}
	case h.Status == 403:
		o = model.Outcome{Code: "http_403", Label: i18n.T("Запрос отклонён (403); причина не установлена"), Level: model.LevelWarn}
	case h.Status == 429:
		label := i18n.T("Ограничение частоты (429)")
		if h.RateLimitReset != "" {
			if t, err := time.Parse(time.RFC3339, h.RateLimitReset); err == nil {
				label += i18n.T("; повтор после ") + t.Local().Format("15:04")
			}
		} else {
			label += i18n.T("; локальная пауза 15 минут")
		}
		o = model.Outcome{Code: "http_429", Label: label, Level: model.LevelWarn}
	case h.Status >= 300 && h.Status < 400:
		label := i18n.T("Перенаправление (%d)", h.Status)
		if h.Location != "" {
			label += " → " + h.Location
		}
		o = model.Outcome{Code: "http_redirect", Label: label, Level: model.LevelWarn, Detail: i18n.T("Это не ошибка сети: сервер ответил, но контрольный адрес не окончательный.")}
	case h.Status == 404 || h.Status == 405:
		o = model.Outcome{Code: "http_unexpected", Label: i18n.T("Контрольный URL или метод не подходит (%d); это не значит, что VPN не работает", h.Status), Level: model.LevelWarn}
	case h.Status >= 500:
		o = model.Outcome{Code: "http_5xx", Label: i18n.T("Ошибка сервера/шлюза (%d); соединение и TLS были успешны", h.Status), Level: model.LevelWarn}
	case h.Status >= 200 && h.Status < 300:
		o = model.Outcome{Code: "http_unexpected", Label: i18n.T("Сервер ответил %d, но для этой точки ожидался другой статус", h.Status), Level: model.LevelWarn}
	default:
		o = model.Outcome{Code: "http_unexpected", Label: i18n.T("Неожиданный статус %d", h.Status), Level: model.LevelWarn}
	}
	if slow && o.Level == model.LevelOK {
		o.Level = model.LevelWarn
		o.Code += "_slow"
		o.Label += i18n.T("; медленно")
		o.Detail = slowDetail(r, th)
	}
	if bodyNote != "" {
		if o.Detail != "" {
			o.Detail += ". "
		}
		o.Detail += bodyNote
	}
	return o
}

// GroupSummary is the aggregated card state for one service group.
type GroupSummary struct {
	GroupID   string      `json:"groupId"`
	Group     string      `json:"group"`
	Total     int         `json:"total"`
	OK        int         `json:"ok"`
	Warn      int         `json:"warn"`
	Error     int         `json:"error"`
	Skipped   int         `json:"skipped"`
	Level     model.Level `json:"level"`
	Label     string      `json:"label"`
	MedianMs  *float64    `json:"medianTlsReadyMs"`
	MetricTag string      `json:"metric"`
}

// Group aggregates the latest result of each endpoint in a group. A group is
// green only when every probed endpoint is OK.
func Group(groupID, group string, results []model.ProbeResult) GroupSummary {
	g := GroupSummary{GroupID: groupID, Group: group, MetricTag: i18n.T("медиана времени до готовности TLS")}
	var lat []float64
	for _, r := range results {
		g.Total++
		switch r.Outcome.Level {
		case model.LevelOK:
			g.OK++
		case model.LevelWarn:
			g.Warn++
		case model.LevelError:
			g.Error++
		default:
			g.Skipped++
		}
		if r.Transport.OK && r.Timings.TLSReadyMs != nil {
			lat = append(lat, *r.Timings.TLSReadyMs)
		}
	}
	g.MedianMs = median(lat)
	probed := g.Total - g.Skipped
	switch {
	case g.Total == 0:
		g.Level, g.Label = model.LevelNeutral, i18n.T("Нет точек")
	case probed == 0:
		g.Level, g.Label = model.LevelNeutral, i18n.T("Не проверено")
	case g.Error == 0 && g.Warn == 0:
		g.Level = model.LevelOK
		g.Label = i18n.T("%d/%d доступны", g.OK, probed)
	case g.OK == 0 && g.Warn == 0:
		g.Level = model.LevelError
		g.Label = i18n.T("0/%d доступны, %d %s", probed, g.Error, plural(g.Error, "ошибка", "ошибки", "ошибок"))
	default:
		g.Level = model.LevelWarn
		parts := []string{i18n.T("%d/%d доступны", g.OK, probed)}
		if g.Warn > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", g.Warn, plural(g.Warn, "ответ отклонён/ограничен", "ответа отклонены/ограничены", "ответов отклонены/ограничены")))
		}
		if g.Error > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", g.Error, plural(g.Error, "ошибка", "ошибки", "ошибок")))
		}
		g.Label = strings.Join(parts, ", ")
	}
	if g.Skipped > 0 && g.Total > 0 && probed > 0 {
		g.Label += i18n.T(", %d не проверено", g.Skipped)
	}
	return g
}

// Summarize fills run counts and the median TLS-ready time.
func Summarize(run *model.Run) {
	var c model.Counts
	var lat []float64
	expectedByID := map[string][]int{}
	for _, e := range run.Endpoints {
		expectedByID[e.ID] = e.ExpectedStatuses
	}
	for _, r := range run.Results {
		c.Planned++
		if r.Skipped {
			c.Skipped++
			if r.Outcome.Code == "limited" || r.Outcome.Code == "hourly_cap" || r.Outcome.Code == "rate_limited_429" || r.Outcome.Code == "run_block_403" || r.Outcome.Code == "run_block_captcha" {
				c.Limited++
			}
			continue
		}
		if r.Outcome.Code == "cancelled" {
			c.Skipped++
			continue
		}
		c.Probed++
		if r.Transport.OK {
			c.TLSOK++
			if r.Timings.TLSReadyMs != nil {
				lat = append(lat, *r.Timings.TLSReadyMs)
			}
		}
		if r.Kind == model.KindHTTPS {
			c.HTTPSTotal++
			if r.HTTP != nil {
				for _, s := range expectedByID[r.EndpointID] {
					if s == r.HTTP.Status {
						c.HTTPMatch++
						break
					}
				}
				if r.HTTP.Status == 429 {
					c.Limited++
				}
			}
		}
		if r.Outcome.Level == model.LevelError {
			c.Errors++
		}
	}
	run.Counts = c
	run.MedianTLSReady = median(lat)
}

// Stats describes a stability-mode series for one endpoint.
type Stats struct {
	N           int      `json:"n"`
	Success     int      `json:"success"`
	MinMs       *float64 `json:"minMs"`
	MedianMs    *float64 `json:"medianMs"`
	MaxMs       *float64 `json:"maxMs"`
	SpreadMs    *float64 `json:"spreadMs"`
	SmallSample bool     `json:"smallSample"`
	Metric      string   `json:"metric"`
}

// Stability computes min/median/max of tlsReadyMs over successful probes.
// The spread is the latency range of this metric, not network jitter; the
// failure share is a share of failed probes, not packet loss.
func Stability(results []model.ProbeResult) Stats {
	s := Stats{Metric: i18n.T("время до готовности TLS, мс")}
	var v []float64
	for _, r := range results {
		if r.Skipped || r.Outcome.Code == "cancelled" {
			continue
		}
		s.N++
		if r.Transport.OK && r.Timings.TLSReadyMs != nil {
			s.Success++
			v = append(v, *r.Timings.TLSReadyMs)
		}
	}
	s.SmallSample = s.N < 3 || s.Success < 3
	if len(v) > 0 {
		sort.Float64s(v)
		mn, mx := v[0], v[len(v)-1]
		s.MinMs, s.MaxMs = &mn, &mx
		s.MedianMs = median(v)
		sp := mx - mn
		s.SpreadMs = &sp
	}
	return s
}

func median(v []float64) *float64 {
	if len(v) == 0 {
		return nil
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	var m float64
	if len(c)%2 == 1 {
		m = c[len(c)/2]
	} else {
		m = (c[len(c)/2-1] + c[len(c)/2]) / 2
	}
	m = float64(int64(m*10+0.5)) / 10
	return &m
}

func plural(n int, one, few, many string) string {
	n = n % 100
	if n >= 11 && n <= 19 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	}
	return many
}
