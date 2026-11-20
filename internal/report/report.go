// Package report produces exports (JSON, CSV), the short text summary and the
// comparison of two runs. Sensitive data (external IPs, local proxy
// addresses, query strings of custom URLs, system proxy hints) is hidden
// unless the caller explicitly asks for it.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpncheck/internal/app"
	"vpncheck/internal/classify"
	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

const hidden = "скрыто"

// Options control redaction.
type Options struct {
	// IncludeSensitive keeps external IPs, proxy addresses, peer addresses in
	// proxy mode, query strings and the system proxy hint.
	IncludeSensitive bool
}

// Redact returns a copy of run with sensitive fields hidden per options.
func Redact(run *model.Run, o Options) *model.Run {
	cp := *run
	cp.Endpoints = append([]model.Endpoint(nil), run.Endpoints...)
	cp.Results = append([]model.ProbeResult(nil), run.Results...)
	if run.ExternalIP != nil {
		x := *run.ExternalIP
		cp.ExternalIP = &x
	}
	if o.IncludeSensitive {
		return &cp
	}
	if cp.Route.ProxyAddr != "" {
		cp.Route.ProxyAddr = i18n.T(hidden)
	}
	if cp.SystemProxy != "" {
		cp.SystemProxy = i18n.T(hidden)
	}
	if cp.ExternalIP != nil {
		if cp.ExternalIP.PreviousIP != "" {
			cp.ExternalIP.PreviousIP = i18n.T(hidden)
		}
		if cp.ExternalIP.Before != "" {
			cp.ExternalIP.Before = i18n.T(hidden)
		}
		if cp.ExternalIP.After != "" {
			cp.ExternalIP.After = i18n.T(hidden)
		}
	}
	for i := range cp.Endpoints {
		if cp.Endpoints[i].Custom {
			cp.Endpoints[i].URL = stripQuery(cp.Endpoints[i].URL)
		}
	}
	custom := map[string]bool{}
	for _, e := range run.Endpoints {
		if e.Custom {
			custom[e.ID] = true
		}
	}
	for i := range cp.Results {
		r := &cp.Results[i]
		if r.Route.ProxyAddr != "" {
			r.Route.ProxyAddr = i18n.T(hidden)
		}
		if r.Route.Mode == model.RouteProxy && r.Transport.PeerAddr != "" {
			r.Transport.PeerAddr = i18n.T(hidden)
		}
		if custom[r.EndpointID] {
			r.URL = stripQuery(r.URL)
		}
	}
	return &cp
}

func stripQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.RawQuery == "" && u.Fragment == "" {
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String() + "?…"
}

// JSONDocument is the versioned export envelope.
type JSONDocument struct {
	SchemaVersion     int        `json:"schemaVersion"`
	App               string     `json:"app"`
	AppVersion        string     `json:"appVersion"`
	ExportedAt        time.Time  `json:"exportedAt"`
	IncludesSensitive bool       `json:"includesSensitiveData"`
	Note              string     `json:"note"`
	Run               *model.Run `json:"run"`
}

// ExportJSON serialises a run.
func ExportJSON(run *model.Run, o Options) ([]byte, error) {
	doc := JSONDocument{
		SchemaVersion:     model.SchemaVersion,
		App:               app.Name,
		AppVersion:        app.Version,
		ExportedAt:        time.Now().UTC(),
		IncludesSensitive: o.IncludeSensitive,
		Note:              i18n.T("Проверялась доступность контрольных узлов, а не полноценная работа приложений. Неизмеренные метрики = null."),
		Run:               Redact(run, o),
	}
	return json.MarshalIndent(doc, "", "  ")
}

var csvHeader = []string{
	"Запуск", "Профиль", "Начало (UTC)", "Статус запуска", "Режим", "Маршрут", "Прокси", "Семейство IP (запрошено)",
	"Группа", "Точка", "Хост", "Тип пробы", "URL", "Попытка", "Начало пробы (UTC)",
	"Итог", "Уровень", "Подробности",
	"DNS, мс", "TCP, мс", "Прокси, мс", "TLS, мс", "TLS готов, мс", "TTFB, мс", "Всего, мс",
	"HTTP статус", "HTTP протокол", "Location", "Прочитано байт", "Тело ограничено",
	"Peer", "Семейство peer", "Семейство доказано", "TLS версия", "ALPN", "Сертификат проверен",
	"Этап сбоя", "Тип ошибки", "Ошибка", "Пропущено", "Версия профиля",
}

// ExportCSV writes one row per probe: UTF-8 with BOM, semicolon separator
// (Excel in a Russian locale opens it directly), formula-injection safe.
func ExportCSV(run *model.Run, o Options) []byte {
	r := Redact(run, o)
	var b bytes.Buffer
	b.WriteString("\xEF\xBB\xBF")
	head := make([]string, len(csvHeader))
	for i, h := range csvHeader {
		head[i] = i18n.T(h)
	}
	writeRow(&b, head)
	epByID := map[string]model.Endpoint{}
	for _, e := range r.Endpoints {
		epByID[e.ID] = e
	}
	status := string(r.Status)
	if r.Status == model.RunCancelled {
		status = i18n.T("cancelled (запуск отменён; данные неполные)")
	}
	proxy := ""
	if r.Route.Mode == model.RouteProxy {
		proxy = string(r.Route.ProxyKind) + " " + r.Route.ProxyAddr
	}
	for _, p := range r.Results {
		ep := epByID[p.EndpointID]
		h := p.HTTP
		row := []string{
			r.ID, r.ProfileName, r.StartedAt.UTC().Format(time.RFC3339), status, string(r.Mode), string(r.Route.Mode), proxy, string(r.IPFamily),
			ep.Group, ep.Label, p.Host, string(p.Kind), p.URL, strconv.Itoa(p.Attempt), p.StartedAt.UTC().Format(time.RFC3339),
			p.Outcome.Label, string(p.Outcome.Level), p.Outcome.Detail,
			num(p.Timings.DNSMs), num(p.Timings.TCPMs), num(p.Timings.ProxyMs), num(p.Timings.TLSMs), num(p.Timings.TLSReadyMs), num(p.Timings.TTFBMs), num(p.Timings.TotalMs),
			httpInt(h), httpStr(h, func(x *model.HTTPResult) string { return x.Proto }), httpStr(h, func(x *model.HTTPResult) string { return x.Location }),
			httpStr(h, func(x *model.HTTPResult) string { return strconv.FormatInt(x.BytesRead, 10) }), httpStr(h, func(x *model.HTTPResult) string { return yesno(x.BodyLimit) }),
			p.Transport.PeerAddr, p.Transport.PeerFamily, yesno(p.Transport.FamilyProven), p.Transport.TLSVersion, p.Transport.ALPN, yesno(p.Transport.CertVerified),
			string(p.Transport.FailedStage), string(p.Transport.ErrorKind), p.Transport.ErrorText, yesno(p.Skipped), strconv.Itoa(p.ProfileVersion),
		}
		writeRow(&b, row)
	}
	return b.Bytes()
}

func num(v *float64) string {
	if v == nil {
		return "—"
	}
	return strconv.FormatFloat(*v, 'f', 1, 64)
}

func httpInt(h *model.HTTPResult) string {
	if h == nil {
		return "—"
	}
	return strconv.Itoa(h.Status)
}

func httpStr(h *model.HTTPResult, f func(*model.HTTPResult) string) string {
	if h == nil {
		return "—"
	}
	return f(h)
}

func yesno(b bool) string {
	if b {
		return i18n.T("да")
	}
	return i18n.T("нет")
}

// writeRow escapes each cell against CSV formula injection and quoting rules.
func writeRow(b *bytes.Buffer, cells []string) {
	for i, c := range cells {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(csvCell(c))
	}
	b.WriteString("\r\n")
}

func csvCell(s string) string {
	if s == "" {
		return ""
	}
	// Formula injection: neutralise leading = + - @ and control characters.
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r', '\n':
		if s != "—" {
			s = "'" + s
		}
	}
	if strings.ContainsAny(s, ";\"\n\r'") || strings.HasPrefix(s, " ") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// Summary renders the short text for sending to an administrator. External
// IPs and local proxy addresses are hidden unless IncludeSensitive.
func Summary(run *model.Run, o Options) string {
	r := Redact(run, o)
	var b strings.Builder
	fmt.Fprintf(&b, i18n.T("%s %s — краткий итог\n"), app.Name, app.Version)
	if r.ProfileName != "" {
		fmt.Fprintf(&b, i18n.T("Профиль: %s\n"), r.ProfileName)
	}
	fmt.Fprintf(&b, i18n.T("Запуск: %s (UTC), режим: %s, статус: %s\n"), r.StartedAt.UTC().Format("2006-01-02 15:04:05"), modeName(r.Mode), statusName(r.Status))
	route := i18n.T("системный маршрут")
	if r.Route.Mode == model.RouteProxy {
		route = i18n.T("прокси %s (%s)", r.Route.ProxyKind, r.Route.ProxyAddr)
	}
	fmt.Fprintf(&b, i18n.T("Маршрут: %s, семейство IP: %s\n"), route, r.IPFamily)
	c := r.Counts
	fmt.Fprintf(&b, i18n.T("Проверено узлов: %d из %d; TLS подтверждён: %d/%d; HTTP-ответ по профилю: %d/%d; ошибок: %d; ограничений/пропусков: %d\n"),
		c.Probed, c.Planned, c.TLSOK, c.Probed, c.HTTPMatch, c.HTTPSTotal, c.Errors, c.Limited+c.Skipped)
	if r.MedianTLSReady != nil {
		fmt.Fprintf(&b, i18n.T("Медиана времени до готовности TLS: %.0f мс\n"), *r.MedianTLSReady)
	}
	if r.ExternalIP != nil {
		x := r.ExternalIP
		if x.Error != "" {
			fmt.Fprintf(&b, i18n.T("Внешний IP: не получен (%s)\n"), x.Error)
		} else {
			fmt.Fprintf(&b, i18n.T("Внешний IP (%s): %s → %s"), x.Provider, x.Before, x.After)
			if x.Changed {
				b.WriteString(i18n.T(" — изменился во время запуска, условия менялись"))
			}
			if x.Country != "" {
				fmt.Fprintf(&b, i18n.T(", страна: %s"), x.Country)
			}
			b.WriteString("\n")
		}
	}
	if r.Message != "" {
		fmt.Fprintf(&b, i18n.T("Примечание: %s\n"), r.Message)
	}
	b.WriteString(i18n.T("\nПо группам:\n"))
	for _, g := range groupSummaries(r) {
		fmt.Fprintf(&b, "  %-22s %s", g.Group, g.Label)
		if g.MedianMs != nil {
			fmt.Fprintf(&b, i18n.T(" (медиана TLS готов %.0f мс)"), *g.MedianMs)
		}
		b.WriteString("\n")
	}
	var problems []string
	epByID := map[string]model.Endpoint{}
	for _, e := range r.Endpoints {
		epByID[e.ID] = e
	}
	for _, p := range latestPerEndpoint(r) {
		if p.Outcome.Level == model.LevelError || p.Outcome.Level == model.LevelWarn {
			ep := epByID[p.EndpointID]
			problems = append(problems, fmt.Sprintf("  %s / %s (%s): %s", ep.Group, ep.Label, p.Host, p.Outcome.Label))
		}
	}
	if len(problems) > 0 {
		b.WriteString(i18n.T("\nПроблемы:\n"))
		for _, p := range problems {
			b.WriteString(p + "\n")
		}
	}
	b.WriteString(i18n.T("\nПроверялась доступность контрольных узлов; полноценная работа приложений не гарантируется.\n"))
	return b.String()
}

func modeName(m model.RunMode) string {
	if m == model.ModeStability {
		return i18n.T("стабильность")
	}
	if m == model.ModeDiag {
		return i18n.T("диагностика (два маршрута)")
	}
	return i18n.T("быстрая")
}

func statusName(s model.RunStatus) string {
	switch s {
	case model.RunCompleted:
		return i18n.T("завершён")
	case model.RunCancelled:
		return i18n.T("отменён")
	case model.RunPartial:
		return i18n.T("частичный")
	case model.RunFailed:
		return i18n.T("не выполнен")
	case model.RunRunning:
		return i18n.T("выполняется")
	}
	return string(s)
}

func latestPerEndpoint(r *model.Run) []model.ProbeResult {
	latest := map[string]model.ProbeResult{}
	var order []string
	for _, p := range r.Results {
		if prev, ok := latest[p.EndpointID]; !ok {
			order = append(order, p.EndpointID)
			latest[p.EndpointID] = p
		} else if p.Attempt >= prev.Attempt {
			latest[p.EndpointID] = p
		}
	}
	out := make([]model.ProbeResult, 0, len(order))
	for _, id := range order {
		out = append(out, latest[id])
	}
	return out
}

func groupSummaries(r *model.Run) []classify.GroupSummary {
	byGroup := map[string][]model.ProbeResult{}
	names := map[string]string{}
	var order []string
	for _, e := range r.Endpoints {
		if _, ok := names[e.GroupID]; !ok {
			names[e.GroupID] = e.Group
			order = append(order, e.GroupID)
		}
	}
	for _, p := range latestPerEndpoint(r) {
		byGroup[p.GroupID] = append(byGroup[p.GroupID], p)
	}
	out := make([]classify.GroupSummary, 0, len(order))
	for _, g := range order {
		out = append(out, classify.Group(g, names[g], byGroup[g]))
	}
	return out
}

// GroupSummaries is exported for the API.
func GroupSummaries(r *model.Run) []classify.GroupSummary { return groupSummaries(r) }

// CompareRow is the per-endpoint comparison.
type CompareRow struct {
	EndpointID string         `json:"endpointId"`
	Group      string         `json:"group"`
	Label      string         `json:"label"`
	Host       string         `json:"host"`
	Before     *model.Outcome `json:"before"`
	After      *model.Outcome `json:"after"`
	BeforeMs   *float64       `json:"beforeMs"`
	AfterMs    *float64       `json:"afterMs"`
	DeltaMs    *float64       `json:"deltaMs"`
	DeltaPct   *float64       `json:"deltaPct"`
	Comparable bool           `json:"comparable"`
	Reason     string         `json:"reason,omitempty"`
	Changed    bool           `json:"changed"`
}

// Comparison is the result of comparing run A (before) with run B (after).
type Comparison struct {
	A            model.RunSummary `json:"a"`
	B            model.RunSummary `json:"b"`
	Metric       string           `json:"metric"`
	RouteChanged bool             `json:"routeChanged"`
	Notes        []string         `json:"notes"`
	Rows         []CompareRow     `json:"rows"`
	OnlyInA      []string         `json:"onlyInA"`
	OnlyInB      []string         `json:"onlyInB"`
}

// Compare matches endpoints by stable ID and reports status and metric changes.
func Compare(a, b *model.Run) Comparison {
	cmp := Comparison{A: a.Summary(), B: b.Summary(), Metric: i18n.T("время до готовности TLS, мс"), Notes: []string{}, Rows: []CompareRow{}, OnlyInA: []string{}, OnlyInB: []string{}}
	cmp.RouteChanged = a.Route != b.Route
	if cmp.RouteChanged {
		cmp.Notes = append(cmp.Notes, i18n.T("Маршруты запусков различаются — это и есть предмет сравнения."))
	}
	if a.IPFamily != b.IPFamily {
		cmp.Notes = append(cmp.Notes, i18n.T("Запрошенное семейство IP различается; сравнение задержек некорректно."))
	}
	if a.Mode != b.Mode {
		cmp.Notes = append(cmp.Notes, i18n.T("Режимы запусков различаются; для режима «Стабильность» используется медиана."))
	}
	if a.Status == model.RunCancelled || b.Status == model.RunCancelled {
		cmp.Notes = append(cmp.Notes, i18n.T("Один из запусков был отменён: часть узлов не проверена."))
	}
	epA := map[string]model.Endpoint{}
	for _, e := range a.Endpoints {
		epA[e.ID] = e
	}
	epB := map[string]model.Endpoint{}
	for _, e := range b.Endpoints {
		epB[e.ID] = e
	}
	resA := metricPerEndpoint(a)
	resB := metricPerEndpoint(b)
	var ids []string
	for id := range resA {
		if _, ok := resB[id]; ok {
			ids = append(ids, id)
		} else {
			cmp.OnlyInA = append(cmp.OnlyInA, id)
		}
	}
	for id := range resB {
		if _, ok := resA[id]; !ok {
			cmp.OnlyInB = append(cmp.OnlyInB, id)
		}
	}
	sort.Strings(ids)
	sort.Strings(cmp.OnlyInA)
	sort.Strings(cmp.OnlyInB)
	for _, id := range ids {
		ra, rb := resA[id], resB[id]
		ea, eb := epA[id], epB[id]
		row := CompareRow{EndpointID: id, Group: eb.Group, Label: eb.Label, Host: eb.Host}
		oa, ob := ra.outcome, rb.outcome
		row.Before, row.After = &oa, &ob
		row.BeforeMs, row.AfterMs = ra.ms, rb.ms
		row.Changed = oa.Code != ob.Code || oa.Level != ob.Level
		row.Comparable = true
		switch {
		case ea.Kind != eb.Kind:
			row.Comparable, row.Reason = false, i18n.T("тип пробы изменился")
		case ea.URL != eb.URL:
			row.Comparable, row.Reason = false, i18n.T("URL контрольной точки изменился")
		case a.IPFamily != b.IPFamily:
			row.Comparable, row.Reason = false, i18n.T("семейство IP изменилось")
		case ra.family != "" && rb.family != "" && ra.family != rb.family:
			row.Comparable, row.Reason = false, i18n.T("фактическое семейство IP различается (")+ra.family+" → "+rb.family+")"
		}
		if row.Comparable && ra.ms != nil && rb.ms != nil {
			d := *rb.ms - *ra.ms
			d = math.Round(d*10) / 10
			row.DeltaMs = &d
			if *ra.ms > 0 {
				pct := d / *ra.ms * 100
				pct = math.Round(pct*10) / 10
				row.DeltaPct = &pct
			}
		}
		cmp.Rows = append(cmp.Rows, row)
	}
	return cmp
}

type metric struct {
	outcome model.Outcome
	ms      *float64
	family  string
}

func metricPerEndpoint(r *model.Run) map[string]metric {
	byID := map[string][]model.ProbeResult{}
	for _, p := range r.Results {
		byID[p.EndpointID] = append(byID[p.EndpointID], p)
	}
	out := map[string]metric{}
	for id, list := range byID {
		latest := list[0]
		for _, p := range list {
			if p.Attempt >= latest.Attempt {
				latest = p
			}
		}
		m := metric{outcome: latest.Outcome}
		if latest.Transport.FamilyProven {
			m.family = latest.Transport.PeerFamily
		}
		if r.Mode == model.ModeStability {
			m.ms = classify.Stability(list).MedianMs
		} else if latest.Transport.OK {
			m.ms = latest.Timings.TLSReadyMs
		}
		out[id] = m
	}
	return out
}

// DiagnosticDocument is the self-describing report meant to be handed to a
// person or an LLM for root-cause analysis. It bundles the network passport,
// the run with every probe, per-group verdicts and a reading guide.
type DiagnosticDocument struct {
	SchemaVersion     int                     `json:"schemaVersion"`
	Kind              string                  `json:"kind"`
	App               string                  `json:"app"`
	AppVersion        string                  `json:"appVersion"`
	GeneratedAt       time.Time               `json:"generatedAt"`
	IncludesSensitive bool                    `json:"includesSensitiveData"`
	HowToRead         []string                `json:"howToRead"`
	Glossary          map[string]string       `json:"glossary"`
	Environment       json.RawMessage         `json:"environment"`
	Verdicts          []model.Verdict         `json:"verdicts"`
	Groups            []classify.GroupSummary `json:"groups"`
	Run               *model.Run              `json:"run"`
	Limitations       []string                `json:"limitations"`
}

// Diagnostic builds the report for one run. env is the passport at export time
// when the run did not capture one.
func Diagnostic(run *model.Run, env json.RawMessage, o Options) ([]byte, error) {
	r := Redact(run, o)
	if len(r.Environment) == 0 {
		r.Environment = env
	}
	if !o.IncludeSensitive {
		r.Environment = redactEnvironment(r.Environment)
	}
	verdicts := r.Verdicts
	if verdicts == nil {
		verdicts = []model.Verdict{}
	}
	doc := DiagnosticDocument{
		SchemaVersion:     2,
		Kind:              "vpncheck-diagnostic-report",
		App:               app.Name,
		AppVersion:        app.Version,
		GeneratedAt:       time.Now().UTC(),
		IncludesSensitive: o.IncludeSensitive,
		HowToRead: []string{
			i18n.T("Это отчёт локальной утилиты VPN Check (Windows). Она проверяет доступность контрольных узлов (TLS-рукопожатие или один GET), а не полноценную работу приложений."),
			i18n.T("Начните с verdicts: для каждой группы сервисов дан код причины, объяснение, улики (evidence) и совет. confidence — уверенность эвристики."),
			i18n.T("environment — «паспорт» машины: verdict.mode = tun (весь трафик через VPN-адаптер) | proxy (VPN-клиент как локальный прокси, программы без настройки прокси идут напрямую) | none | client-no-proxy; adapters, defaultRoute, vpnClients, localProxyListeners, proxies (WinINET/переменные окружения)."),
			i18n.T("run.route — маршрут проб (system = как настроена Windows, proxy = явный HTTP CONNECT/SOCKS5). В режиме diag каждый узел проверен дважды: attempt 1 по run.route, attempt 2 по run.altRoute. Сравнивайте пары."),
			i18n.T("run.results[]: transport (этап сбоя failedStage: dns|tcp|proxy|tls|http, errorKind, errorText, peerAddr, resolvedAddrs, certVerified) и http (status, location, geoBlocked/geoSignature, captcha, bodySnippet, retryAfter) хранятся раздельно; outcome — итоговая подпись. timings в мс: dnsMs, tcpMs, proxyMs, tlsMs, tlsReadyMs (старт пробы → сертификат проверен), ttfbMs; null = не измерено (например DNS за прокси)."),
			i18n.T("Типичные картины: tcp timeout напрямую и ok через прокси = трафик программ идёт мимо VPN; reset на tls = активная блокировка по SNI/IP (DPI); http 403 с geoBlocked = сервис отказывает по стране выхода VPN (смените сервер); captcha = репутация IP выхода; tls_certificate = перехват TLS или неверные часы; 429 = лимит частоты."),
			i18n.T("run.externalIp (если включено) — IP выхода до/после запуска и страна по данным провайдера; по умолчанию скрыт, если includesSensitiveData=false."),
		},
		Glossary: map[string]string{
			"tls":           i18n.T("проба: DNS → TCP 443 → TLS с проверкой сертификата, без HTTP-запроса"),
			"https":         i18n.T("проба: один GET к документированному небольшому ресурсу, все этапы на одном запросе"),
			"tlsReadyMs":    i18n.T("время от старта пробы до успешной проверки сертификата; основная метрика для сравнения"),
			"familyProven":  i18n.T("false за прокси: семейство IP конечного сервера не наблюдалось"),
			"outcome.level": i18n.T("ok | warn (сервер ответил, но не как ожидалось, или медленно) | error (транспортная ошибка) | neutral (не проверено/отменено)"),
			"verdict.code":  "geo_block | ip_reputation | dns_spoof | proxy_down | tls_intercept | direct_blocked_proxy_ok | route_dependent | dns_fail | dpi_reset | drop_timeout | refused | rate_limited | service_error | http_denied | profile_mismatch | slow | ok | not_probed",
			"limits":        i18n.T("не более 4 проб одновременно, одна на хост, часового лимита нет, пауза между запусками (настраивается, по умолчанию 60 с), тайм-аут пробы 10 с"),
		},
		Environment: r.Environment,
		Verdicts:    verdicts,
		Groups:      groupSummaries(r),
		Run:         r,
		Limitations: []string{
			i18n.T("Вердикты — эвристики без захвата пакетов и без прав администратора; сброс соединения можно спутать с падением сервиса."),
			i18n.T("За локальным прокси VPN-клиента DNS и TCP до конечного сервера не наблюдаются; время удалённого подключения входит в tlsMs."),
			i18n.T("Доступность контрольного узла не гарантирует работу приложения (401 = «сервер ответил, требуется авторизация»)."),
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// redactEnvironment hides local addresses of adapters in the passport.
func redactEnvironment(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	if ads, ok := m["adapters"].([]any); ok {
		for _, a := range ads {
			if am, ok := a.(map[string]any); ok {
				for _, k := range []string{"ipv4", "ipv6"} {
					if list, ok := am[k].([]any); ok && len(list) > 0 {
						am[k] = []string{hidden}
					}
				}
			}
		}
	}
	if dr, ok := m["defaultRoute"].(map[string]any); ok {
		if _, has := dr["nextHop"]; has {
			dr["nextHop"] = i18n.T(hidden)
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}
