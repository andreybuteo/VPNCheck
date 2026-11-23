package diag

import (
	"strings"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// homeSites names the sites of the home country as the subject of a sentence.
func homeSites(home string) string {
	switch home {
	case "CN":
		return i18n.T("китайские сайты")
	case "IR":
		return i18n.T("иранские сайты")
	default:
		return i18n.T("российские сайты")
	}
}

// homeRules are the usual VPN-client rules that send the home country direct.
func homeRules(home string) string {
	switch home {
	case "CN":
		return "geosite:cn, geoip:cn"
	case "IR":
		return i18n.T("geosite:category-ir, geoip:ir и доменов .ir")
	default:
		return i18n.T("geosite:category-ru, geoip:ru и доменов .ru и .рф")
	}
}

// splitVerdict turns a split-routing observation into the verdict of its
// group (ru-direct, cn-direct, ir-direct). The addresses themselves stay in
// run.Splits (redacted in reports); the texts here carry no IPs.
func splitVerdict(s *model.SplitCheck, base model.Verdict) model.Verdict {
	v := model.Verdict{GroupID: base.GroupID, Group: base.Group, Code: splitCode(s.Code), Confidence: "high"}
	home := s.Home
	if home == "" {
		home = "RU"
	}
	sites := homeSites(home)
	src := i18n.T(s.Source)
	fc := s.ForeignCountry
	if fc == "" {
		fc = "?"
	}
	ev := func(items ...string) { v.Evidence = append(v.Evidence, items...) }
	if s.DomesticIP != "" && s.ForeignIP != "" {
		if s.DomesticIP == s.ForeignIP {
			ev(i18n.T("Местный сайт (%s) и зарубежный узел (Cloudflare) видят один и тот же адрес.", src))
		} else {
			ev(i18n.T("Местный сайт (%s) и зарубежный узел (Cloudflare) видят разные адреса.", src))
		}
	}
	if s.DomesticCountry != "" {
		ev(i18n.T("Страна адреса, который видит %s: %s.", src, s.DomesticCountry))
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
	if home == "IR" {
		ev(i18n.T("ifconfig.ir работает через Cloudflare, поэтому проверяется правило по домену .ir; правило только по geoip:ir этот сайт не охватывает."))
	}
	switch s.Code {
	case "split_ok":
		v.Level = model.LevelOK
		v.Title = i18n.T("Работает: %s напрямую, остальное через VPN", sites)
		v.Explanation = i18n.T("%s видит ваш прямой адрес, а зарубежный контрольный узел — адрес VPN в стране %s. Зарубежные сервисы идут через VPN.", src, fc)
		v.Advice = i18n.T("Ничего менять не нужно. Правила выбирает клиент VPN, программа их только проверяет.")
	case "all_vpn":
		// Not direct: shown in red with the country the home sites go through.
		v.Level = model.LevelError
		v.Title = i18n.T("Не напрямую: %s идут через VPN (%s)", sites, fc)
		v.Explanation = i18n.T("%s и зарубежный узел видят один и тот же адрес VPN (страна %s). Зарубежные сервисы работают через VPN, но местные сайты видят зарубежный IP: банки, госуслуги и магазины могут не пускать или просить капчу.", src, fc)
		v.Advice = i18n.T("Если нужно, добавьте в клиенте VPN правило «прямое подключение» для %s. На зарубежные сервисы это не влияет. После изменения повторите проверку.", homeRules(home))
	case "all_direct":
		v.Level = model.LevelError
		v.Title = i18n.T("Весь трафик идёт напрямую, мимо VPN")
		v.Explanation = i18n.T("%s и зарубежный узел видят один и тот же адрес в стране %s. Зарубежные сервисы (ChatGPT, Codex, Claude) тоже увидят его и могут отказать.", src, home)
		v.Advice = i18n.T("Проверьте, что VPN подключён и в заголовке выбран его маршрут: TUN или локальный прокси клиента. Проверьте, не стоит ли в клиенте режим «всё напрямую».")
	case "same_exit":
		v.Level = model.LevelWarn
		v.Confidence = "medium"
		v.Title = i18n.T("Местные и зарубежные сайты видят один адрес")
		v.Explanation = i18n.T("Разделения нет: весь трафик идёт одним путём. Страна выхода не определена, поэтому неясно, VPN это или прямое подключение.")
		v.Advice = i18n.T("Посмотрите страну в ленте IP выхода или повторите проверку.")
	case "foreign_in_home", "foreign_in_ru":
		v.Level = model.LevelWarn
		v.Title = i18n.T("Зарубежный выход в той же стране (%s)", home)
		v.Explanation = i18n.T("Адреса различаются, но зарубежный контрольный узел видит адрес в стране %s. Вероятно, VPN-сервер стоит в этой же стране: зарубежные сервисы с ограничениями для неё могут отказать.", home)
		v.Advice = i18n.T("Если нужен зарубежный выход, выберите в клиенте VPN сервер в другой стране.")
	case "domestic_foreign":
		v.Level = model.LevelError
		v.Title = i18n.T("Не напрямую: %s идут через %s", sites, s.DomesticCountry)
		v.Explanation = i18n.T("%s видит адрес в стране %s, а не в стране %s. Местные сайты идут через другой зарубежный сервер или прокси, а не напрямую.", src, s.DomesticCountry, home)
		v.Advice = i18n.T("Проверьте в клиенте VPN, куда направлено правило для местных сайтов (%s): должно быть «напрямую» (direct).", homeRules(home))
	case "domestic_vpn":
		v.Level = model.LevelError
		v.Confidence = "medium"
		v.Title = i18n.T("Не напрямую: %s идут через другой сервер", sites)
		v.Explanation = i18n.T("Адреса различаются, но %s считает адрес, который видит, VPN или хостингом. Похоже, местные сайты идут не напрямую, а через другой прокси.", src)
		v.Advice = i18n.T("Проверьте в клиенте VPN, куда направлено правило для местных сайтов (%s): должно быть «напрямую» (direct).", homeRules(home))
	default:
		v.Level = model.LevelNeutral
		v.Confidence = "low"
		v.Title = i18n.T("Адрес для местных сайтов не определён")
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
