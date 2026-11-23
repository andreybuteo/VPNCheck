package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"

	"vpncheck/internal/i18n"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
)

// SplitProfile is one "home country direct" check: a registry group whose
// selection turns it on, and a page inside that country that shows the
// visitor's address. The check compares that address with the foreign exit.
type SplitProfile struct {
	Group   string // registry group ID
	Country string // home country, ISO code
	Name    string // source name (Russian source text, translated in the UI)
	URL     string
	Host    string
	Limit   int64
}

// SplitProfiles are the built-in profiles, in the order the checks run.
//   - RU: the public Yandex Internetometer page (~110 KB); the address and Yandex's own isVpn flag.
//   - CN: Bilibili's zone API (Chinese servers, a domain in geosite:cn), JSON with "addr".
//   - IR: ifconfig.ir, JSON with "ip". It sits behind Cloudflare, so it tests a rule
//     by domain (.ir, geosite:category-ir); a rule only by geoip:ir sends it through the VPN.
var SplitProfiles = []SplitProfile{
	{Group: "ru-direct", Country: "RU", Name: "Яндекс Интернетометр", URL: "https://yandex.ru/internet", Host: "yandex.ru", Limit: 256 << 10},
	{Group: "cn-direct", Country: "CN", Name: "Bilibili", URL: "https://api.bilibili.com/x/web-interface/zone", Host: "api.bilibili.com", Limit: 16 << 10},
	{Group: "ir-direct", Country: "IR", Name: "ifconfig.ir", URL: "https://ifconfig.ir", Host: "ifconfig.ir", Limit: 16 << 10},
}

// SplitGroup is the Russian profile's group (kept for callers and tests).
const SplitGroup = "ru-direct"

var (
	reYandexIP     = regexp.MustCompile(`"ip"\s*:\s*(\{[^{}]*\})`)
	reIsVPN        = regexp.MustCompile(`"isVpn"\s*:\s*(true|false)`)
	reYandexRegion = regexp.MustCompile(`"clientRegion"\s*:\s*(\{[^{}]*\})`)
)

// ParseSplitPage reads the observed address and location from the site's own
// response. Yandex embeds these fields in HTML. Bilibili and ifconfig.ir use JSON.
func ParseSplitPage(body []byte) (ip string, vpn *bool, country string) {
	if m := reYandexIP.FindSubmatch(body); m != nil {
		var addr struct{ V4, V6 string }
		if json.Unmarshal(m[1], &addr) == nil {
			ip = addr.V4
			if net.ParseIP(ip) == nil {
				ip = addr.V6
			}
		}
		if m := reIsVPN.FindSubmatch(body); m != nil {
			v := string(m[1]) == "true"
			vpn = &v
		}
		if m := reYandexRegion.FindSubmatch(body); m != nil {
			var region struct{ IP, Name string }
			if json.Unmarshal(m[1], &region) == nil {
				name := region.IP
				if name == "" {
					name = region.Name
				}
				country = CountryOfCity(name)
			}
		}
	} else if plain := strings.Trim(strings.TrimSpace(string(body)), `"`); net.ParseIP(plain) != nil {
		ip = plain
	} else {
		type location struct{ IP, Addr, Country, Province string }
		var page struct {
			location
			Data *location
		}
		if json.Unmarshal(body, &page) == nil {
			loc := page.location
			if page.Data != nil {
				loc = *page.Data
			}
			ip = loc.IP
			if ip == "" {
				ip = loc.Addr
			}
			if isISOCode(loc.Country) {
				country = strings.ToUpper(loc.Country)
			} else {
				country = CountryOfZh(loc.Country, loc.Province)
			}
		}
	}
	addr := net.ParseIP(ip)
	if addr == nil || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return "", vpn, ""
	}
	return addr.String(), vpn, country
}

// ClassifySplit sets s.Code from the two observed addresses. s.Home is the
// home country (RU when empty, as in runs of version 4.3).
func ClassifySplit(s *model.SplitCheck) {
	home := s.Home
	if home == "" {
		home = "RU"
	}
	switch {
	case s.DomesticIP == "" || s.ForeignIP == "":
		s.Code = "unknown"
	case s.DomesticIP == s.ForeignIP && s.ForeignCountry == home:
		s.Code = "all_direct"
	case s.DomesticIP == s.ForeignIP && s.ForeignCountry == "":
		s.Code = "same_exit"
	case s.DomesticIP == s.ForeignIP:
		s.Code = "all_vpn"
	case s.ForeignCountry == home:
		s.Code = "foreign_in_home"
	case s.DomesticCountry != "" && s.DomesticCountry != home:
		s.Code = "domestic_foreign"
	case s.DomesticVPN != nil && *s.DomesticVPN:
		s.Code = "domestic_vpn"
	case s.ForeignCountry == "" || (s.DomesticCountry == "" && s.DomesticVPN == nil) ||
		(net.ParseIP(s.DomesticIP).To4() == nil) != (net.ParseIP(s.ForeignIP).To4() == nil):
		s.Code = "unknown"
	default:
		s.Code = "split_ok"
	}
}

func hasGroup(eps []model.Endpoint, gid string) bool {
	for _, e := range eps {
		if e.GroupID == gid {
			return true
		}
	}
	return false
}

// selectedSplits returns the profiles whose group is part of the run.
func selectedSplits(eps []model.Endpoint) []SplitProfile {
	var out []SplitProfile
	for _, p := range SplitProfiles {
		if hasGroup(eps, p.Group) {
			out = append(out, p)
		}
	}
	return out
}

// splitCheck asks the home-country page which address it sees, through the
// same route and limiter as the probes, and compares it with the foreign exit
// IP observed by the Cloudflare trace. It sends requests only; it never
// changes routes, proxy settings or the VPN client.
func (r *Runner) splitCheck(ctx context.Context, run *model.Run, req Request, p SplitProfile) {
	s := &model.SplitCheck{Group: p.Group, Home: p.Country, Source: p.Name, SourceURL: p.URL}
	defer func() {
		r.mu.Lock()
		if x := run.ExternalIP; x != nil {
			s.ForeignIP, s.ForeignCountry = x.Latest()
		}
		if s.DomesticIP != "" && s.DomesticIP == s.ForeignIP && s.DomesticCountry == "" {
			s.DomesticCountry = s.ForeignCountry
		}
		ClassifySplit(s)
		run.Splits = append(run.Splits, s)
		r.mu.Unlock()
	}()
	if ctx.Err() != nil {
		s.Error = i18n.T("проверка остановлена")
		return
	}
	reply, body, err := r.observe(ctx, req, p.Host, p.Group, p.URL, p.Limit)
	status := reply.Status
	var blocked *limiter.Allowance
	switch {
	case errors.As(err, &blocked):
		s.Error = i18n.T("запрос пропущен: ") + blocked.Reason
	case ctx.Err() != nil:
		s.Error = i18n.T("проверка остановлена")
	case err != nil:
		s.Error = err.Error()
	case status == 429 || status == 403 || (status >= 300 && status < 400) || reply.Captcha:
		s.Error = i18n.T("сайт ответил проверкой на робота или отказом (статус %d)", status)
	case status != 200:
		s.Error = i18n.T("статус %d", status)
	default:
		s.DomesticIP, s.DomesticVPN, s.DomesticCountry = ParseSplitPage(body)
		if s.DomesticIP == "" {
			s.Error = i18n.T("адрес на странице не найден")
		}
	}
}
