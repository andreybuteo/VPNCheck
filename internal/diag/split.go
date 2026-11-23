package diag

import (
	"strings"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// splitVerdict turns the split-routing observation into the verdict of the
// "ru-direct" group. The addresses themselves stay in run.Split (redacted in
// reports); the texts here carry no IPs.
func splitVerdict(run *model.Run, base model.Verdict) model.Verdict {
	s := run.Split
	if s == nil {
		return base
	}
	v := model.Verdict{GroupID: base.GroupID, Group: base.Group, Code: splitCode(s.Code), Confidence: "high"}
	fc := s.ForeignCountry
	if fc == "" {
		fc = "?"
	}
	ev := func(items ...string) { v.Evidence = append(v.Evidence, items...) }
	if s.DomesticIP != "" && s.ForeignIP != "" {
		if s.DomesticIP == s.ForeignIP {
			ev(i18n.T("Российский сайт (Яндекс) и зарубежный узел (Cloudflare) видят один и тот же адрес."))
		} else {
			ev(i18n.T("Российский сайт (Яндекс) и зарубежный узел (Cloudflare) видят разные адреса."))
		}
	}
	if s.DomesticCountry != "" {
		ev(i18n.T("Страна адреса, который видит Яндекс: %s.", s.DomesticCountry))
	}
	if s.ForeignCountry != "" {
		ev(i18n.T("Страна выхода к зарубежным сайтам по данным Cloudflare: %s.", s.ForeignCountry))
	}
	if s.DomesticVPN != nil {
		if *s.DomesticVPN {
			ev(i18n.T("Яндекс считает адрес, с которого пришёл запрос, VPN или хостингом."))
		} else {
			ev(i18n.T("Яндекс не считает адрес, с которого пришёл запрос, VPN."))
		}
	}
	switch s.Code {
	case "split_ok":
		v.Level = model.LevelOK
		v.Title = i18n.T("Работает: российские сайты напрямую, остальное через VPN")
		v.Explanation = i18n.T("Российский сайт видит ваш прямой адрес, а зарубежный контрольный узел — адрес VPN в стране %s. Зарубежные сервисы идут через VPN.", fc)
		v.Advice = i18n.T("Ничего менять не нужно. Правила выбирает клиент VPN, программа их только проверяет.")
	case "all_vpn":
		// Not direct: shown in red with the country the Russian sites go through.
		v.Level = model.LevelError
		v.Title = i18n.T("Не напрямую: российские сайты идут через VPN (%s)", fc)
		v.Explanation = i18n.T("Российский и зарубежный узлы видят один и тот же адрес VPN (страна %s). Зарубежные сервисы работают через VPN, но российские сайты видят зарубежный IP: банки, Госуслуги и магазины могут не пускать или просить капчу.", fc)
		v.Advice = i18n.T("Если нужно, добавьте в клиенте VPN правило «прямое подключение» для geosite:category-ru, geoip:ru и доменов .ru и .рф. На зарубежные сервисы это не влияет. После изменения повторите проверку.")
	case "all_direct":
		v.Level = model.LevelError
		v.Title = i18n.T("Весь трафик идёт напрямую, мимо VPN")
		v.Explanation = i18n.T("Российский и зарубежный узлы видят один и тот же российский адрес. Зарубежные сервисы (ChatGPT, Codex, Claude) тоже увидят российский IP и могут отказать.")
		v.Advice = i18n.T("Проверьте, что VPN подключён и в заголовке выбран его маршрут: TUN или локальный прокси клиента. Проверьте, не стоит ли в клиенте режим «всё напрямую».")
	case "same_exit":
		v.Level = model.LevelWarn
		v.Confidence = "medium"
		v.Title = i18n.T("Российские и зарубежные сайты видят один адрес")
		v.Explanation = i18n.T("Разделения нет: весь трафик идёт одним путём. Страна выхода не определена, поэтому неясно, VPN это или прямое подключение.")
		v.Advice = i18n.T("Посмотрите страну в ленте IP выхода или повторите проверку.")
	case "foreign_in_ru":
		v.Level = model.LevelWarn
		v.Title = i18n.T("Зарубежный выход находится в России")
		v.Explanation = i18n.T("Адреса различаются, но зарубежный контрольный узел видит российский адрес. Вероятно, VPN-сервер стоит в России: зарубежные сервисы с ограничениями для России могут отказать.")
		v.Advice = i18n.T("Если нужен зарубежный выход, выберите в клиенте VPN сервер в другой стране.")
	case "domestic_foreign":
		v.Level = model.LevelError
		v.Title = i18n.T("Не напрямую: российские сайты идут через %s", s.DomesticCountry)
		v.Explanation = i18n.T("Яндекс видит адрес в стране %s, а не российский. Российские сайты идут через другой зарубежный сервер или прокси, а не напрямую.", s.DomesticCountry)
		v.Advice = i18n.T("Проверьте в клиенте VPN, куда направлено правило для российских сайтов: должно быть «напрямую» (direct).")
	case "domestic_vpn":
		v.Level = model.LevelError
		v.Confidence = "medium"
		v.Title = i18n.T("Не напрямую: российские сайты идут через другой сервер")
		v.Explanation = i18n.T("Адреса различаются, но Яндекс считает адрес, который видит, VPN или хостингом. Похоже, российские сайты идут не напрямую, а через другой прокси.")
		v.Advice = i18n.T("Проверьте в клиенте VPN, куда направлено правило для российских сайтов: должно быть «напрямую» (direct).")
	default:
		v.Level = model.LevelNeutral
		v.Confidence = "low"
		v.Title = i18n.T("Адрес для российских сайтов не определён")
		v.Explanation = i18n.T("Не удалось сравнить адреса: %s.", firstNonEmpty(s.Error, i18n.T("внешний IP не получен")))
		v.Advice = i18n.T("Повторите проверку позже. Доступность сайтов от этого не зависит.")
	}
	return v
}

func splitCode(c string) string {
	if strings.HasPrefix(c, "split_") {
		return c
	}
	return "split_" + c
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
