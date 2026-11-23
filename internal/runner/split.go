package runner

import (
	"context"
	"net"
	"regexp"
	"strings"

	"vpncheck/internal/i18n"
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
	reYandexIP = regexp.MustCompile(`"ip":\{"v4":"([0-9.]{7,15})"`)
	reIsVPN    = regexp.MustCompile(`"isVpn":(true|false)`)
	reJSONIP   = regexp.MustCompile(`"(?:ip|addr)"\s*:\s*"([0-9a-fA-F:.]{3,45})"`)
	// Yandex: the region detected by the address ("ip"), else the region shown ("name").
	reYandexRegionIP   = regexp.MustCompile(`"clientRegion":\{[^}]*"ip":"([^"]+)"`)
	reYandexRegionName = regexp.MustCompile(`"clientRegion":\{"name":"([^"]+)"`)
	reJSONCountry      = regexp.MustCompile(`"country"\s*:\s*"([^"]{1,40})"`)
	reJSONProvince     = regexp.MustCompile(`"province"\s*:\s*"([^"]{1,40})"`)
)

// ParseSplitPage extracts the visitor's address, the VPN flag and the country
// from the local site's answer: the Internetometer page (city -> country by the
// built-in table), JSON with "ip"/"addr" and "country" (Bilibili in Chinese,
// ifconfig.ir as an ISO code) or a plain-text address. Nothing is looked up
// elsewhere; an unknown country is "".
func ParseSplitPage(body []byte) (ip string, vpn *bool, country string) {
	s := string(body)
	if m := reYandexIP.FindStringSubmatch(s); m != nil && net.ParseIP(m[1]) != nil {
		ip = m[1]
	} else if t := strings.Trim(strings.TrimSpace(s), `"`); net.ParseIP(t) != nil {
		ip = t
	} else if m := reJSONIP.FindStringSubmatch(s); m != nil && net.ParseIP(m[1]) != nil {
		ip = m[1]
	}
	if net.ParseIP(ip).IsLoopback() {
		ip = ""
	}
	if m := reIsVPN.FindStringSubmatch(s); m != nil {
		v := m[1] == "true"
		vpn = &v
	}
	switch {
	case reYandexRegionIP.MatchString(s):
		country = CountryOfCity(reYandexRegionIP.FindStringSubmatch(s)[1])
	case reYandexRegionName.MatchString(s):
		country = CountryOfCity(reYandexRegionName.FindStringSubmatch(s)[1])
	case reJSONCountry.MatchString(s):
		c := reJSONCountry.FindStringSubmatch(s)[1]
		if isISOCode(c) {
			country = strings.ToUpper(c)
		} else {
			prov := ""
			if m := reJSONProvince.FindStringSubmatch(s); m != nil {
				prov = m[1]
			}
			country = CountryOfZh(c, prov)
		}
	}
	if ip == "" {
		country = ""
	}
	return ip, vpn, country
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
			s.ForeignIP = x.After
			if s.ForeignIP == "" {
				s.ForeignIP = x.Before
			}
			s.ForeignCountry = x.AfterCountry
			if s.ForeignCountry == "" {
				s.ForeignCountry = x.Country
			}
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
	if a := r.d.Limiter.Allowance(p.Host); !a.OK {
		s.Error = i18n.T("запрос пропущен: ") + a.Reason
		return
	}
	release, err := r.d.Limiter.Acquire(ctx, p.Host, p.Group)
	if err != nil {
		s.Error = err.Error()
		return
	}
	status, body, err := r.proberFor(req, nil).FetchSmall(ctx, p.URL, p.Limit)
	release()
	switch {
	case err != nil:
		s.Error = err.Error()
	case status == 429 || status == 403 || (status >= 300 && status < 400) || strings.Contains(string(body), "showcaptcha"):
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
