package runner

import (
	"context"
	"net"
	"regexp"
	"strings"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// SplitGroup is the registry group whose selection turns the split-routing
// check on: "Russian sites direct, everything else through the VPN".
const SplitGroup = "ru-direct"

// SplitProvider is the Russian page that shows the visitor's address. It is
// the public Yandex Internetometer page; one GET per run, about 110 KB.
var SplitProvider = struct {
	Name, URL, Host, Group string
}{Name: "Яндекс Интернетометр", URL: "https://yandex.ru/internet", Host: "yandex.ru", Group: SplitGroup}

const splitBodyLimit = 256 << 10

// GeoProvider tells the country of the address the Russian page saw: the
// RIPE NCC RIPEstat geolocation data call (no key). One small GET, only when
// the two addresses differ; the request goes through the same route.
var GeoProvider = struct {
	Name, URL, Host string
}{Name: "RIPEstat", URL: "https://stat.ripe.net/data/maxmind-geo-lite/data.json?sourceapp=vpncheck&resource=", Host: "stat.ripe.net"}

var reGeoCountry = regexp.MustCompile(`"country"\s*:\s*"([A-Za-z]{2})"`)

// ParseGeoCountry reads the first country code of a RIPEstat answer.
func ParseGeoCountry(body []byte) string {
	if m := reGeoCountry.FindSubmatch(body); m != nil {
		return strings.ToUpper(string(m[1]))
	}
	return ""
}

var (
	reYandexIP = regexp.MustCompile(`"ip":\{"v4":"([0-9.]{7,15})"`)
	reIsVPN    = regexp.MustCompile(`"isVpn":(true|false)`)
	reJSONIP   = regexp.MustCompile(`"ip"\s*:\s*"([0-9a-fA-F:.]{3,45})"`)
)

// ParseSplitPage extracts the visitor's IPv4 address and the VPN flag from the
// Internetometer page. A plain-text or {"ip": "..."} answer (an own echo
// script) is understood as well.
func ParseSplitPage(body []byte) (ip string, vpn *bool) {
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
	return ip, vpn
}

// ClassifySplit sets s.Code from the two observed addresses.
func ClassifySplit(s *model.SplitCheck) {
	switch {
	case s.DomesticIP == "" || s.ForeignIP == "":
		s.Code = "unknown"
	case s.DomesticIP == s.ForeignIP && s.ForeignCountry == "RU":
		s.Code = "all_direct"
	case s.DomesticIP == s.ForeignIP && s.ForeignCountry == "":
		s.Code = "same_exit"
	case s.DomesticIP == s.ForeignIP:
		s.Code = "all_vpn"
	case s.ForeignCountry == "RU":
		s.Code = "foreign_in_ru"
	case s.DomesticCountry != "" && s.DomesticCountry != "RU":
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

// splitCheck asks the Russian page which address it sees, through the same
// route and limiter as the probes, and compares it with the foreign exit IP
// observed by the Cloudflare trace. It sends requests only; it never changes
// routes, proxy settings or the VPN client.
func (r *Runner) splitCheck(ctx context.Context, run *model.Run, req Request) {
	s := &model.SplitCheck{Source: SplitProvider.Name, SourceURL: SplitProvider.URL}
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
		if s.DomesticIP != "" && s.DomesticIP == s.ForeignIP {
			s.DomesticCountry = s.ForeignCountry
		}
		ClassifySplit(s)
		run.Split = s
		r.mu.Unlock()
	}()
	if ctx.Err() != nil {
		s.Error = i18n.T("проверка остановлена")
		return
	}
	if a := r.d.Limiter.Allowance(SplitProvider.Host); !a.OK {
		s.Error = i18n.T("запрос пропущен: ") + a.Reason
		return
	}
	release, err := r.d.Limiter.Acquire(ctx, SplitProvider.Host, SplitProvider.Group)
	if err != nil {
		s.Error = err.Error()
		return
	}
	status, body, err := r.proberFor(req, nil).FetchSmall(ctx, SplitProvider.URL, splitBodyLimit)
	release()
	switch {
	case err != nil:
		s.Error = err.Error()
	case status == 429 || status == 403 || (status >= 300 && status < 400) || strings.Contains(string(body), "showcaptcha"):
		s.Error = i18n.T("Яндекс ответил проверкой на робота (статус %d)", status)
	case status != 200:
		s.Error = i18n.T("статус %d", status)
	default:
		s.DomesticIP, s.DomesticVPN = ParseSplitPage(body)
		if s.DomesticIP == "" {
			s.Error = i18n.T("адрес на странице не найден")
		}
	}
	if s.DomesticIP == "" || ctx.Err() != nil {
		return
	}
	r.mu.Lock()
	same := run.ExternalIP != nil && (run.ExternalIP.After == s.DomesticIP || run.ExternalIP.Before == s.DomesticIP)
	r.mu.Unlock()
	if !same {
		s.DomesticCountry = r.geoCountry(ctx, req, s.DomesticIP)
	}
}

// geoCountry asks RIPEstat for the country of ip; "" when unknown.
func (r *Runner) geoCountry(ctx context.Context, req Request, ip string) string {
	if a := r.d.Limiter.Allowance(GeoProvider.Host); !a.OK {
		return ""
	}
	release, err := r.d.Limiter.Acquire(ctx, GeoProvider.Host, SplitGroup)
	if err != nil {
		return ""
	}
	status, body, err := r.proberFor(req, nil).FetchSmall(ctx, GeoProvider.URL+ip, 32<<10)
	release()
	if err != nil || status != 200 {
		return ""
	}
	return ParseGeoCountry(body)
}
