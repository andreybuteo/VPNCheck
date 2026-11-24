// Package diag turns probe results (optionally over two routes) and the
// network passport into per-group verdicts: what is most likely wrong and
// what to do. Verdicts are heuristics with a stated confidence, not proof.
package diag

import (
	"fmt"
	"sort"
	"strings"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// Context is what the analysis knows besides the results.
type Context struct {
	// PrimaryRoute is the route the user selected; AltRoute the alternative (may be nil).
	PrimaryRoute model.RouteConfig
	AltRoute     *model.RouteConfig
	// ExitCountry is the country of the external IP if it was observed ("" otherwise).
	ExitCountry string
	// EnvMode is the passport verdict mode: tun | proxy | client-no-proxy | none | unknown.
	EnvMode string
	// SplitTunnel is true when a tunnel adapter is up but not the default route.
	SplitTunnel bool
}

func routeName(r model.RouteConfig) string {
	if r.Mode == model.RouteProxy {
		return i18n.T("через прокси ") + string(r.ProxyKind) + " " + r.ProxyAddr
	}
	return i18n.T("напрямую (системный маршрут)")
}

// latest returns the latest result per endpoint per route key.
func latest(results []model.ProbeResult) map[string]map[string]model.ProbeResult {
	out := map[string]map[string]model.ProbeResult{}
	for _, r := range results {
		key := string(r.Route.Mode) + "|" + r.Route.ProxyAddr
		m := out[r.EndpointID]
		if m == nil {
			m = map[string]model.ProbeResult{}
			out[r.EndpointID] = m
		}
		if prev, ok := m[key]; !ok || r.Attempt >= prev.Attempt {
			m[key] = r
		}
	}
	return out
}

// Analyze produces one verdict per group present in the run.
func Analyze(run *model.Run, ctx Context) []model.Verdict {
	groups := map[string]string{}
	var order []string
	epsByGroup := map[string][]model.Endpoint{}
	for _, e := range run.Endpoints {
		if _, ok := groups[e.GroupID]; !ok {
			groups[e.GroupID] = e.Group
			order = append(order, e.GroupID)
		}
		epsByGroup[e.GroupID] = append(epsByGroup[e.GroupID], e)
	}
	lat := latest(run.Results)
	var out []model.Verdict
	for _, gid := range order {
		v := analyzeGroup(gid, groups[gid], epsByGroup[gid], lat, ctx)
		if gid == "anthropic" {
			if v.Code == "ok" || v.Code == "slow" {
				v.Title = i18n.T("Сеть доступна; аккаунт не проверен")
				if !AnthropicNetworkOK(run) {
					v.Title = i18n.T("Частичная проверка сети; аккаунт не проверен")
				}
				v.Explanation = i18n.T("TLS к Claude и ответ API оцениваются отдельно. Ответ 401 с authentication_error означает, что API ответил и требует ключ. Вход в Claude, доступ аккаунта и вызов модели не проверялись.")
				if v.Code == "slow" {
					v.Explanation += i18n.T(" Задержка выше выбранного порога.")
				}
			}
			v.Advice = strings.TrimSpace(v.Advice + i18n.T(" Доступ аккаунта проверяется вручную в Claude; смена IP сама по себе не доказывает блокировку."))
		}
		if sp := run.SplitFor(gid); sp != nil && !(sp.Code == "unknown" && v.Level == model.LevelError) {
			v = splitVerdict(sp, v)
		}
		out = append(out, v)
	}
	return out
}

type obs struct {
	ep  model.Endpoint
	pri *model.ProbeResult
	alt *model.ProbeResult
}

func analyzeGroup(gid, name string, eps []model.Endpoint, lat map[string]map[string]model.ProbeResult, ctx Context) model.Verdict {
	priKey := string(ctx.PrimaryRoute.Mode) + "|" + ctx.PrimaryRoute.ProxyAddr
	altKey := ""
	if ctx.AltRoute != nil {
		altKey = string(ctx.AltRoute.Mode) + "|" + ctx.AltRoute.ProxyAddr
	}
	var list []obs
	for _, e := range eps {
		o := obs{ep: e}
		if m := lat[e.ID]; m != nil {
			if r, ok := m[priKey]; ok {
				rr := r
				o.pri = &rr
			}
			if altKey != "" {
				if r, ok := m[altKey]; ok {
					rr := r
					o.alt = &rr
				}
			}
			// Single-route runs: take whatever route was used.
			if o.pri == nil && altKey == "" {
				for _, r := range m {
					rr := r
					o.pri = &rr
				}
			}
		}
		list = append(list, o)
	}
	v := model.Verdict{GroupID: gid, Group: name, Evidence: []string{}}
	probed := 0
	for _, o := range list {
		if o.pri != nil && !o.pri.Skipped {
			probed++
		}
	}
	if probed == 0 {
		v.Code, v.Level, v.Confidence = "not_probed", model.LevelNeutral, "low"
		v.Title = i18n.T("Группа не проверялась")
		v.Explanation = i18n.T("Нет результатов проб для этой группы (пропущено или отменено).")
		return v
	}

	// 1. Geo-block signatures: the service itself refuses the exit region.
	for _, o := range list {
		for _, r := range []*model.ProbeResult{o.pri, o.alt} {
			if r != nil && r.HTTP != nil && r.HTTP.GeoBlocked {
				v.Code, v.Level, v.Confidence = "geo_block", model.LevelWarn, "high"
				v.Title = i18n.T("Сервис отказывает по стране или IP выхода")
				v.Explanation = i18n.T("Соединение и TLS успешны, но %s отвечает %d с признаком гео-ограничения («%s»). Это решение самого сервиса о стране выхода вашего VPN, а не блокировка на пути.", r.Host, r.HTTP.Status, r.HTTP.GeoSignature)
				v.Evidence = append(v.Evidence, i18n.T("%s %s: HTTP %d, сигнатура «%s»", r.Host, routeName(r.Route), r.HTTP.Status, r.HTTP.GeoSignature))
				if ctx.ExitCountry != "" {
					v.Evidence = append(v.Evidence, i18n.T("страна IP выхода по данным провайдера: ")+ctx.ExitCountry)
				}
				v.Advice = i18n.T("Переключите VPN на сервер в стране, где сервис доступен (для OpenAI/Anthropic — например, ЕС, США, Япония), и повторите проверку.")
				// Geo-refusal on one route while the other route is fine: the fix is routing, not the country.
				var other *model.ProbeResult
				if r == o.pri {
					other = o.alt
				} else {
					other = o.pri
				}
				if other != nil && other.Outcome.Level == model.LevelOK {
					v.Code = "geo_block_route"
					v.Title = i18n.T("По маршруту «%s» сервис отказывает по стране, по маршруту «%s» работает", routeName(r.Route), routeName(other.Route))
					v.Explanation = i18n.T("%s: %s → %d с гео-ограничением («%s»); %s → %s. Значит, по первому маршруту трафик выходит из страны, где сервис недоступен, а по второму — через VPN.", r.Host, routeName(r.Route), r.HTTP.Status, r.HTTP.GeoSignature, routeName(other.Route), other.Outcome.Label)
					v.Evidence = append(v.Evidence, fmt.Sprintf("%s %s: %s", other.Host, routeName(other.Route), other.Outcome.Label))
					if r.Route.Mode == model.RouteSystem {
						v.Advice = i18n.T("Программы без настройки прокси выходят напрямую мимо VPN. Включите в VPN-клиенте режим TUN/системный VPN или настройте приложения на прокси ") + other.Route.ProxyAddr + i18n.T("; в этой программе используйте режим «Прокси».")
					} else {
						v.Advice = i18n.T("Выход через этот прокси попадает в страну, где сервис недоступен; системный маршрут работает. Смените сервер VPN или используйте системный маршрут.")
					}
				}
				return v
			}
		}
	}
	// 2. CAPTCHA / IP reputation.
	for _, o := range list {
		if o.pri != nil && o.pri.HTTP != nil && o.pri.HTTP.Captcha {
			v.Code, v.Level, v.Confidence = "ip_reputation", model.LevelWarn, "medium"
			v.Title = i18n.T("Сервис требует проверку (CAPTCHA/challenge): IP выхода под подозрением")
			v.Explanation = i18n.T("%s отвечает %d с признаками anti-bot проверки. Обычно так реагируют на IP-адреса датацентров и популярных VPN. Сеть при этом работает.", o.pri.Host, o.pri.HTTP.Status)
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s %s: HTTP %d, challenge", o.pri.Host, routeName(o.pri.Route), o.pri.HTTP.Status))
			v.Advice = i18n.T("В браузере проверка обычно проходится вручную. Если она повторяется постоянно, попробуйте другой сервер VPN или другой протокол.")
			return v
		}
	}
	// 3. DNS spoofing / blocked address.
	for _, o := range list {
		if o.pri != nil && o.pri.Transport.ErrorKind == model.ErrBlockedAddr {
			v.Code, v.Level, v.Confidence = "dns_spoof", model.LevelError, "high"
			v.Title = i18n.T("DNS возвращает частный или служебный адрес: подмена DNS")
			v.Explanation = i18n.T("Имя %s разрешилось в адрес, к которому программа отказалась подключаться (%s). Так выглядит подмена ответа DNS провайдером или роутером.", o.pri.Host, o.pri.Transport.ErrorText)
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s: DNS → %s", o.pri.Host, strings.Join(o.pri.Transport.ResolvedAddrs, ", ")))
			v.Advice = i18n.T("Используйте DNS через VPN (режим TUN с DNS туннеля) или DoH/DoT в браузере и системе; в режиме прокси имена должен разрешать прокси (SOCKS5 с удалённым DNS).")
			return v
		}
	}
	// 4. Proxy itself failing.
	for _, o := range list {
		if o.pri != nil && o.pri.Transport.ErrorKind == model.ErrProxy {
			v.Code, v.Level, v.Confidence = "proxy_down", model.LevelError, "high"
			v.Title = i18n.T("Прокси VPN-клиента не отвечает")
			v.Explanation = i18n.T("Ошибка на этапе подключения к прокси: ") + o.pri.Transport.ErrorText + i18n.T(". Целевые серверы не проверялись.")
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s: %s", o.pri.Host, o.pri.Transport.ErrorText))
			v.Advice = i18n.T("Проверьте, что VPN-клиент запущен и подключён, а адрес прокси в настройках совпадает с его портом.")
			return v
		}
	}
	// 5. Certificate errors: interception.
	for _, o := range list {
		if o.pri != nil && o.pri.Transport.ErrorKind == model.ErrTLSCert {
			v.Code, v.Level, v.Confidence = "tls_intercept", model.LevelError, "medium"
			v.Title = i18n.T("Сертификат не прошёл проверку: возможен перехват TLS")
			v.Explanation = i18n.T("TCP-соединение с %s установлено, но сервер предъявил сертификат, которому система не доверяет: %s. Так бывает при корпоративном прокси, «заглушке» провайдера или неверных системных часах.", o.pri.Host, o.pri.Transport.ErrorText)
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s: %s", o.pri.Host, o.pri.Transport.ErrorText))
			v.Advice = i18n.T("Проверьте дату и время системы. Не добавляйте чужие корневые сертификаты; если это корпоративная сеть, обратитесь к администратору.")
			return v
		}
	}
	// 6. Route split: fails on primary, works on alternative (or vice versa).
	if ctx.AltRoute != nil {
		failPri, okAlt, okPri, failAlt := 0, 0, 0, 0
		var ex []string
		for _, o := range list {
			if o.pri == nil || o.alt == nil || o.pri.Skipped || o.alt.Skipped {
				continue
			}
			pOK := o.pri.Outcome.Level == model.LevelOK
			aOK := o.alt.Outcome.Level == model.LevelOK
			switch {
			case !pOK && aOK:
				failPri++
				okAlt++
				ex = append(ex, fmt.Sprintf("%s: %s — %s; %s — %s", o.pri.Host, routeName(o.pri.Route), o.pri.Outcome.Label, routeName(o.alt.Route), o.alt.Outcome.Label))
			case pOK && !aOK:
				okPri++
				failAlt++
				ex = append(ex, fmt.Sprintf("%s: %s — %s; %s — %s", o.pri.Host, routeName(o.pri.Route), o.pri.Outcome.Label, routeName(o.alt.Route), o.alt.Outcome.Label))
			}
		}
		if failPri > 0 && okAlt > 0 && okPri == 0 {
			v.Evidence = ex
			if ctx.PrimaryRoute.Mode == model.RouteSystem && ctx.AltRoute.Mode == model.RouteProxy {
				v.Code, v.Level, v.Confidence = "direct_blocked_proxy_ok", model.LevelWarn, "high"
				v.Title = i18n.T("Напрямую недоступно, через прокси VPN работает: трафик программ идёт мимо VPN")
				v.Explanation = i18n.T("VPN-клиент работает как локальный прокси и не перехватывает трафик всей системы. Программы без настройки прокси (и эта проверка в режиме «Системный маршрут») выходят напрямую и упираются в блокировку.")
				if ctx.SplitTunnel {
					v.Explanation += i18n.T(" Кроме того, обнаружен туннельный адаптер без маршрута по умолчанию (split tunneling).")
				}
				v.Advice = i18n.T("Включите в VPN-клиенте режим TUN (системный прокси/VPN-режим) или настройте нужные программы на прокси. В этой программе выберите режим «Прокси».")
			} else {
				v.Code, v.Level, v.Confidence = "route_dependent", model.LevelWarn, "high"
				v.Title = i18n.T("Доступность зависит от маршрута")
				v.Explanation = i18n.T("По маршруту %s узлы недоступны, по маршруту %s доступны.", routeName(ctx.PrimaryRoute), routeName(*ctx.AltRoute))
				v.Advice = i18n.T("Используйте маршрут, по которому сервис доступен; сравните страны выхода.")
			}
			return v
		}
		if failAlt > 0 && okPri > 0 && failPri == 0 {
			v.Evidence = ex
			v.Code, v.Level, v.Confidence = "route_dependent", model.LevelOK, "high"
			v.Title = i18n.T("По выбранному маршруту доступно, по альтернативному — нет")
			v.Explanation = i18n.T("Маршрут %s работает; %s — нет. Текущие настройки подходят.", routeName(ctx.PrimaryRoute), routeName(*ctx.AltRoute))
			v.Advice = i18n.T("Оставьте текущий маршрут.")
			return v
		}
	}
	// 7. Transport failures by kind on the primary route.
	resets, timeouts, dnsFail, refused := 0, 0, 0, 0
	var ex []string
	okCount := 0
	for _, o := range list {
		r := o.pri
		if r == nil || r.Skipped {
			continue
		}
		if r.Transport.OK {
			if r.Outcome.Level == model.LevelOK {
				okCount++
			}
			continue
		}
		ex = append(ex, i18n.T("%s: этап %s, %s (%s)", r.Host, r.Transport.FailedStage, r.Transport.ErrorKind, r.Transport.ErrorText))
		switch {
		case r.Transport.FailedStage == model.StageDNS:
			dnsFail++
		case r.Transport.ErrorKind == model.ErrReset:
			resets++
		case r.Transport.ErrorKind == model.ErrTimeout:
			timeouts++
		case r.Transport.ErrorKind == model.ErrRefused:
			refused++
		}
	}
	failed := resets + timeouts + dnsFail + refused
	switch {
	case failed > 0 && dnsFail == failed:
		v.Code, v.Level, v.Confidence = "dns_fail", model.LevelError, "medium"
		v.Title = i18n.T("Имена не разрешаются")
		v.Explanation = i18n.T("DNS не отвечает или не находит имена этой группы, при этом соединения не проверялись. Часто это выключенная сеть, недоступный DNS-сервер или блокировка на уровне DNS.")
		v.Advice = i18n.T("Проверьте доступ в интернет и DNS; в режиме прокси используйте SOCKS5 с удалённым DNS.")
	case failed > 0 && resets > 0 && resets >= timeouts:
		v.Code, v.Level, v.Confidence = "dpi_reset", model.LevelError, "medium"
		v.Title = i18n.T("Соединение сбрасывается: похоже на активную блокировку по SNI/IP")
		v.Explanation = i18n.T("Сервер отвечает сбросом (RST) на этапе TCP/TLS вместо нормального рукопожатия. Так ведёт себя оборудование DPI, реагирующее на имя сервера в ClientHello или на адрес. Падение самого сервиса выглядит иначе (тайм-аут или 5xx).")
		v.Advice = i18n.T("Пустите трафик через VPN в режиме TUN или через прокси; убедитесь, что этот маршрут действительно используется программой.")
	case failed > 0 && timeouts > 0:
		v.Code, v.Level, v.Confidence = "drop_timeout", model.LevelError, "medium"
		v.Title = i18n.T("Пакеты отбрасываются: тайм-аут подключения")
		v.Explanation = i18n.T("Ответа нет вообще. Причины: блокировка по IP/порту на пути, нерабочий маршрут VPN (пакеты уходят в туннель, который не отвечает) или отсутствие интернета.")
		if okCount > 0 {
			v.Explanation += i18n.T(" Часть узлов группы при этом доступна, значит сеть в целом работает и блокируются конкретные адреса.")
		}
		v.Advice = i18n.T("Сравните с другим маршрутом (диагностика по двум маршрутам) и с другим сервером VPN.")
	case failed > 0 && refused > 0:
		v.Code, v.Level, v.Confidence = "refused", model.LevelError, "medium"
		v.Title = i18n.T("Подключение отклонено")
		v.Explanation = i18n.T("Удалённая сторона активно отказала в TCP-соединении (RST на SYN). Обычно это подменённый адрес или заглушка.")
		v.Advice = i18n.T("Проверьте DNS-ответы и маршрут.")
	}
	if v.Code != "" {
		v.Evidence = ex
		return v
	}
	// 8. HTTP-level.
	for _, o := range list {
		r := o.pri
		if r == nil || r.HTTP == nil {
			continue
		}
		switch {
		case r.Outcome.Code == "http_429":
			v.Code, v.Level, v.Confidence = "rate_limited", model.LevelWarn, "high"
			v.Title = i18n.T("Сервис ограничивает частоту запросов")
			v.Explanation = i18n.T("%s ответил 429. Сеть работает; лимит может относиться к IP выхода VPN, которым пользуются многие.", r.Host)
			v.Advice = i18n.T("Подождите указанное время; при постоянных 429 смените сервер VPN.")
			v.Evidence = append(v.Evidence, i18n.T("%s: 429, повтор после %s", r.Host, r.HTTP.RateLimitReset))
			return v
		case r.HTTP.Status >= 500:
			v.Code, v.Level, v.Confidence = "service_error", model.LevelWarn, "medium"
			v.Title = i18n.T("Ошибка на стороне сервиса")
			v.Explanation = i18n.T("%s ответил %d: соединение и TLS в порядке, проблема у сервиса или его шлюза.", r.Host, r.HTTP.Status)
			v.Advice = i18n.T("Повторите позже; это не проблема VPN.")
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s: HTTP %d", r.Host, r.HTTP.Status))
			return v
		case r.Outcome.Code == "http_403" || r.Outcome.Code == "http_401":
			v.Code, v.Level, v.Confidence = "http_denied", model.LevelWarn, "low"
			v.Title = i18n.T("Сервер отвечает, но отказывает в доступе")
			v.Explanation = i18n.T("%s ответил %d без известной сигнатуры гео-ограничения. Сеть и TLS работают; причина отказа не установлена.", r.Host, r.HTTP.Status)
			v.Advice = i18n.T("Откройте сервис в браузере через тот же маршрут: текст ошибки на странице подскажет причину.")
			v.Evidence = append(v.Evidence, fmt.Sprintf("%s: HTTP %d %s", r.Host, r.HTTP.Status, r.HTTP.BodySnippet))
			return v
		case r.Outcome.Code == "http_unexpected" || r.Outcome.Code == "http_redirect":
			v.Code, v.Level, v.Confidence = "profile_mismatch", model.LevelWarn, "low"
			v.Title = i18n.T("Сервер отвечает, но не так, как ожидает профиль")
			v.Explanation = i18n.T("%s: %s. Сеть работает; возможно, контрольный адрес изменился.", r.Host, r.Outcome.Label)
			v.Advice = i18n.T("Это не проблема VPN. Сообщите о несоответствии профиля.")
			return v
		}
	}
	slow := 0
	for _, o := range list {
		if o.pri != nil && strings.HasSuffix(o.pri.Outcome.Code, "_slow") {
			slow++
		}
	}
	if slow > 0 {
		v.Code, v.Level, v.Confidence = "slow", model.LevelWarn, "medium"
		v.Title = i18n.T("Доступно, но медленно")
		v.Explanation = i18n.T("Соединения устанавливаются, но время до готовности TLS выше локального порога. Возможен перегруженный сервер VPN или дальний маршрут.")
		v.Advice = i18n.T("Попробуйте другой сервер VPN ближе географически.")
		return v
	}
	v.Code, v.Level, v.Confidence = "ok", model.LevelOK, "high"
	v.Title = i18n.T("Доступно")
	v.Explanation = i18n.T("Все проверенные узлы группы доступны по выбранному маршруту. Это доступность контрольных узлов, а не гарантия работы приложения.")
	v.Advice = ""
	return v
}

// Summary returns a compact, sorted list of problem verdicts first.
func Summary(vs []model.Verdict) []model.Verdict {
	out := append([]model.Verdict(nil), vs...)
	rank := map[model.Level]int{model.LevelError: 0, model.LevelWarn: 1, model.LevelNeutral: 2, model.LevelOK: 3}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Level] < rank[out[j].Level] })
	return out
}
