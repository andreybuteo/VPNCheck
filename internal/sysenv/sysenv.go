// Package sysenv builds the "network passport" of the machine: which VPN
// clients are running, whether a TUN adapter carries the default route, what
// local proxies are listening, which DNS servers are configured and which
// proxies are set at the user level. Everything is read locally, without
// administrator rights and without any network request.
package sysenv

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
	"vpncheck/internal/sysproxy"
)

// Adapter describes one network interface.
type Adapter struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Up          bool     `json:"up"`
	TunLike     bool     `json:"tunLike"`
	IfType      uint32   `json:"ifType"`
	IPv4        []string `json:"ipv4"`
	IPv6        []string `json:"ipv6"`
	DNS         []string `json:"dns"`
	Gateway     []string `json:"gateway"`
	Metric      uint32   `json:"ipv4Metric"`
}

// Route is the IPv4 default route.
type Route struct {
	Known     bool   `json:"known"`
	IfIndex   int    `json:"ifIndex"`
	IfName    string `json:"ifName"`
	IfDesc    string `json:"ifDescription"`
	NextHop   string `json:"nextHop"`
	ViaTunnel bool   `json:"viaTunnel"`
	Note      string `json:"note,omitempty"`
}

// Listener is a TCP port listening on this machine.
type Listener struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Process string `json:"process"`
	Guess   string `json:"guess,omitempty"` // "http", "socks5", "http/socks"
}

// Client is a recognised VPN/proxy client process.
type Client struct {
	Name      string     `json:"name"`
	Process   string     `json:"process"`
	PID       int        `json:"pid"`
	Kind      string     `json:"kind"` // "proxy-client", "vpn-client", "dpi-bypass", "proxifier"
	Listening []Listener `json:"listening"`
}

// Verdict is the conclusion about how traffic leaves this machine.
type Verdict struct {
	Mode           string             `json:"mode"` // "tun", "proxy", "client-no-proxy", "none", "unknown"
	Title          string             `json:"title"`
	Text           string             `json:"text"`
	SuggestedRoute *model.RouteConfig `json:"suggestedRoute,omitempty"`
	Confidence     string             `json:"confidence"` // "high", "medium", "low"
}

// Passport is the whole environment snapshot.
type Passport struct {
	CollectedAt  time.Time     `json:"collectedAt"`
	OS           string        `json:"os"`
	Adapters     []Adapter     `json:"adapters"`
	DefaultRoute Route         `json:"defaultRoute"`
	Proxies      sysproxy.Hint `json:"proxies"`
	Clients      []Client      `json:"vpnClients"`
	LocalProxies []Listener    `json:"localProxyListeners"`
	Verdict      Verdict       `json:"verdict"`
	Errors       []string      `json:"errors"`
}

// knownClient maps a lower-case process name to a client.
type knownClient struct {
	name string
	kind string
}

var knownClients = map[string]knownClient{
	"v2rayn.exe":              {"v2rayN", "proxy-client"},
	"v2ray.exe":               {"v2ray-core", "proxy-client"},
	"xray.exe":                {"Xray-core", "proxy-client"},
	"xraycore.exe":            {"Xray-core", "proxy-client"},
	"wxray.exe":               {"Xray-core", "proxy-client"},
	"sing-box-core.exe":       {"sing-box", "proxy-client"},
	"sing-box.exe":            {"sing-box", "proxy-client"},
	"clash.exe":               {"Clash", "proxy-client"},
	"clash-win64.exe":         {"Clash", "proxy-client"},
	"clash-verge.exe":         {"Clash Verge", "proxy-client"},
	"clash-meta.exe":          {"Clash Meta", "proxy-client"},
	"mihomo.exe":              {"mihomo (Clash Meta)", "proxy-client"},
	"verge-mihomo.exe":        {"Clash Verge (mihomo)", "proxy-client"},
	"clashn.exe":              {"ClashN", "proxy-client"},
	"nekobox.exe":             {"NekoBox", "proxy-client"},
	"nekoray.exe":             {"NekoRay", "proxy-client"},
	"nekobox_core.exe":        {"NekoBox core", "proxy-client"},
	"hiddify.exe":             {"Hiddify", "proxy-client"},
	"hiddifycli.exe":          {"Hiddify CLI", "proxy-client"},
	"throne.exe":              {"Throne", "proxy-client"},
	"husi.exe":                {"Husi", "proxy-client"},
	"karing.exe":              {"Karing", "proxy-client"},
	"flclash.exe":             {"FlClash", "proxy-client"},
	"invisibleman.xray.exe":   {"InvisibleMan XRay", "proxy-client"},
	"shadowsocks.exe":         {"Shadowsocks", "proxy-client"},
	"ss-local.exe":            {"shadowsocks-libev", "proxy-client"},
	"sslocal.exe":             {"shadowsocks-rust", "proxy-client"},
	"outline.exe":             {"Outline", "vpn-client"},
	"outline-client.exe":      {"Outline", "vpn-client"},
	"outlineservice.exe":      {"Outline service", "vpn-client"},
	"amneziavpn.exe":          {"AmneziaVPN", "vpn-client"},
	"amnezia-vpn-service.exe": {"AmneziaVPN service", "vpn-client"},
	"wireguard.exe":           {"WireGuard", "vpn-client"},
	"wg.exe":                  {"WireGuard tools", "vpn-client"},
	"openvpn.exe":             {"OpenVPN", "vpn-client"},
	"openvpn-gui.exe":         {"OpenVPN GUI", "vpn-client"},
	"openvpnserv.exe":         {"OpenVPN service", "vpn-client"},
	"openvpnconnect.exe":      {"OpenVPN Connect", "vpn-client"},
	"tor.exe":                 {"Tor", "proxy-client"},
	"firefox.exe":             {"", ""},
	"psiphon3.exe":            {"Psiphon", "vpn-client"},
	"psiphon-tunnel-core.exe": {"Psiphon core", "vpn-client"},
	"nordvpn.exe":             {"NordVPN", "vpn-client"},
	"nordvpn-service.exe":     {"NordVPN service", "vpn-client"},
	"expressvpn.exe":          {"ExpressVPN", "vpn-client"},
	"expressvpnd.exe":         {"ExpressVPN daemon", "vpn-client"},
	"protonvpn.exe":           {"Proton VPN", "vpn-client"},
	"protonvpnservice.exe":    {"Proton VPN service", "vpn-client"},
	"surfshark.exe":           {"Surfshark", "vpn-client"},
	"windscribe.exe":          {"Windscribe", "vpn-client"},
	"windscribeservice.exe":   {"Windscribe service", "vpn-client"},
	"mullvad vpn.exe":         {"Mullvad", "vpn-client"},
	"mullvad-daemon.exe":      {"Mullvad daemon", "vpn-client"},
	"hotspotshield.exe":       {"Hotspot Shield", "vpn-client"},
	"cyberghost.exe":          {"CyberGhost", "vpn-client"},
	"pia-client.exe":          {"Private Internet Access", "vpn-client"},
	"proxifier.exe":           {"Proxifier", "proxifier"},
	"goodbyedpi.exe":          {"GoodbyeDPI", "dpi-bypass"},
	"winws.exe":               {"zapret (winws)", "dpi-bypass"},
	"ciadpi.exe":              {"ByeDPI", "dpi-bypass"},
	"byedpi.exe":              {"ByeDPI", "dpi-bypass"},
	"spoofdpi.exe":            {"SpoofDPI", "dpi-bypass"},
	"zapret.exe":              {"zapret", "dpi-bypass"},

	// Linux process names (/proc/<pid>/comm or the executable name).
	"v2ray":               {"v2ray-core", "proxy-client"},
	"xray":                {"Xray-core", "proxy-client"},
	"v2raya":              {"v2rayA", "proxy-client"},
	"v2rayn":              {"v2rayN", "proxy-client"},
	"sing-box":            {"sing-box", "proxy-client"},
	"clash":               {"Clash", "proxy-client"},
	"clash-meta":          {"Clash Meta", "proxy-client"},
	"clash-verge":         {"Clash Verge", "proxy-client"},
	"verge-mihomo":        {"Clash Verge (mihomo)", "proxy-client"},
	"mihomo":              {"mihomo (Clash Meta)", "proxy-client"},
	"flclash":             {"FlClash", "proxy-client"},
	"nekoray":             {"NekoRay", "proxy-client"},
	"nekobox":             {"NekoBox", "proxy-client"},
	"nekobox_core":        {"NekoBox core", "proxy-client"},
	"throne":              {"Throne", "proxy-client"},
	"hiddify":             {"Hiddify", "proxy-client"},
	"hiddifycli":          {"Hiddify CLI", "proxy-client"},
	"karing":              {"Karing", "proxy-client"},
	"ss-local":            {"shadowsocks-libev", "proxy-client"},
	"sslocal":             {"shadowsocks-rust", "proxy-client"},
	"tor":                 {"Tor", "proxy-client"},
	"outline-client":      {"Outline", "vpn-client"},
	"amneziavpn":          {"AmneziaVPN", "vpn-client"},
	"amneziavpn-service":  {"AmneziaVPN service", "vpn-client"},
	"amneziawg-go":        {"AmneziaWG", "vpn-client"},
	"wireguard-go":        {"WireGuard (userspace)", "vpn-client"},
	"openvpn":             {"OpenVPN", "vpn-client"},
	"openconnect":         {"OpenConnect", "vpn-client"},
	"psiphon-tunnel-core": {"Psiphon core", "vpn-client"},
	"nordvpnd":            {"NordVPN daemon", "vpn-client"},
	"expressvpnd":         {"ExpressVPN daemon", "vpn-client"},
	"mullvad-daemon":      {"Mullvad daemon", "vpn-client"},
	"protonvpn-app":       {"Proton VPN", "vpn-client"},
	"windscribe":          {"Windscribe", "vpn-client"},
	"piactl":              {"Private Internet Access", "vpn-client"},
	"pia-daemon":          {"Private Internet Access", "vpn-client"},
	"proxychains4":        {"proxychains", "proxifier"},
	"ciadpi":              {"ByeDPI", "dpi-bypass"},
	"byedpi":              {"ByeDPI", "dpi-bypass"},
	"spoofdpi":            {"SpoofDPI", "dpi-bypass"},
	"nfqws":               {"zapret (nfqws)", "dpi-bypass"},
	"tpws":                {"zapret (tpws)", "dpi-bypass"},
}

// tunMarkers are substrings of adapter descriptions that indicate a tunnel.
var tunMarkers = []string{"wintun", "wireguard", "tap-windows", "tap adapter", "amnezia", "openvpn", "tunnel", "vpn", "sing-box", "clash", "hiddify", "nekoray", "nekobox", "outline", "mullvad", "proton", "nord", "express", "surfshark", "windscribe", "psiphon", "tun", "ppp", "wan miniport (ikev2)", "wan miniport (l2tp)", "wan miniport (sstp)", "wan miniport (pptp)"}

const (
	ifTypeTunnel = 131
	ifTypePPP    = 23
)

// IsTunLike classifies an adapter by its description and type.
func IsTunLike(description string, ifType uint32) bool {
	d := strings.ToLower(description)
	if strings.Contains(d, "wan miniport") && !strings.Contains(d, "ikev2") && !strings.Contains(d, "l2tp") && !strings.Contains(d, "sstp") && !strings.Contains(d, "pptp") {
		return false
	}
	if ifType == ifTypeTunnel || ifType == ifTypePPP {
		return true
	}
	for _, m := range tunMarkers {
		if strings.Contains(d, m) {
			return true
		}
	}
	return false
}

// GuessProxyKind maps a local listening port to a likely proxy protocol.
func GuessProxyKind(port int) string {
	switch port {
	case 1080, 1081, 10808, 2080, 7891, 9050, 9150:
		return "socks5"
	case 10809, 8080, 8118, 3128, 2081, 7890, 7897, 7892, 8888:
		return "http"
	}
	return ""
}

// Collect gathers the passport. It never fails hard: partial data with errors.
func Collect() Passport {
	p := Passport{CollectedAt: time.Now().UTC(), OS: osVersion(), Errors: []string{}, Clients: []Client{}, LocalProxies: []Listener{}}
	var err error
	p.Adapters, err = adapters()
	if err != nil {
		p.Errors = append(p.Errors, i18n.T("адаптеры: ")+err.Error())
	}
	p.DefaultRoute = defaultRoute(p.Adapters)
	p.Proxies = sysproxy.Detect()
	procs, err := processes()
	if err != nil {
		p.Errors = append(p.Errors, i18n.T("процессы: ")+err.Error())
	}
	listeners, err := tcpListeners()
	if err != nil {
		p.Errors = append(p.Errors, i18n.T("порты: ")+err.Error())
	}
	p.Clients, p.LocalProxies = classify(procs, listeners)
	p.Verdict = verdict(&p)
	return p
}

// classify matches processes and listeners into clients and local proxies.
func classify(procs map[int]string, listeners []Listener) ([]Client, []Listener) {
	byPID := map[int][]Listener{}
	for i := range listeners {
		l := &listeners[i]
		l.Process = procs[l.PID]
		if l.Addr == "127.0.0.1" || l.Addr == "0.0.0.0" || l.Addr == "::" || l.Addr == "::1" {
			l.Guess = GuessProxyKind(l.Port)
		}
		byPID[l.PID] = append(byPID[l.PID], *l)
	}
	var clients []Client
	seen := map[string]bool{}
	for pid, name := range procs {
		kc, ok := knownClients[strings.ToLower(name)]
		if !ok || kc.name == "" {
			continue
		}
		c := Client{Name: kc.name, Process: name, PID: pid, Kind: kc.kind, Listening: byPID[pid]}
		if c.Listening == nil {
			c.Listening = []Listener{}
		}
		sort.Slice(c.Listening, func(i, j int) bool { return c.Listening[i].Port < c.Listening[j].Port })
		clients = append(clients, c)
		seen[strings.ToLower(name)] = true
	}
	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Name != clients[j].Name {
			return clients[i].Name < clients[j].Name
		}
		return clients[i].PID < clients[j].PID
	})
	var proxies []Listener
	for _, l := range listeners {
		if l.Guess == "" {
			continue
		}
		lower := strings.ToLower(l.Process)
		if _, known := knownClients[lower]; known || l.Addr == "127.0.0.1" {
			proxies = append(proxies, l)
		}
	}
	sort.Slice(proxies, func(i, j int) bool { return proxies[i].Port < proxies[j].Port })
	if clients == nil {
		clients = []Client{}
	}
	if proxies == nil {
		proxies = []Listener{}
	}
	return clients, proxies
}

// verdict derives the traffic mode.
func verdict(p *Passport) Verdict {
	r := p.DefaultRoute
	split := splitTunnels(p)
	if r.Known && r.ViaTunnel {
		v := Verdict{Mode: "tun", Confidence: "high", Title: i18n.T("VPN в режиме TUN: маршрут по умолчанию идёт через туннель"),
			Text: i18n.T("Маршрут по умолчанию через адаптер «%s» (%s). Трафик всех программ, включая эту, идёт через VPN. Подходит режим «Системный маршрут».", r.IfName, r.IfDesc)}
		v.SuggestedRoute = &model.RouteConfig{Mode: model.RouteSystem}
		return v
	}
	_ = split
	// A local proxy that the system proxy points to, or a known client's listener.
	var best *Listener
	if p.Proxies.Suggested != nil {
		host, port := splitAddr(p.Proxies.Suggested.ProxyAddr)
		for i := range p.LocalProxies {
			l := &p.LocalProxies[i]
			if (host == "127.0.0.1" || host == "localhost") && fmt.Sprint(l.Port) == port {
				best = l
				break
			}
		}
	}
	if best == nil {
		for i := range p.LocalProxies {
			l := &p.LocalProxies[i]
			if _, known := knownClients[strings.ToLower(l.Process)]; known && l.Guess != "" {
				if best == nil || (best.Guess != "http" && l.Guess == "http") {
					best = l
				}
			}
		}
	}
	if best != nil {
		kind := model.ProxyHTTP
		if best.Guess == "socks5" {
			kind = model.ProxySOCKS5
		}
		sysNote := i18n.T("Системный прокси не указывает на него, поэтому браузер может идти иначе.")
		if p.Proxies.Suggested != nil && strings.HasSuffix(p.Proxies.Suggested.ProxyAddr, fmt.Sprintf(":%d", best.Port)) {
			sysNote = i18n.T("Системный прокси указывает на этот порт: браузер идёт через него.")
		}
		clientName := best.Process
		if kc, ok := knownClients[strings.ToLower(best.Process)]; ok && kc.name != "" {
			clientName = kc.name
		}
		return Verdict{Mode: "proxy", Confidence: "high",
			Title:          i18n.T("VPN-клиент %s работает как локальный прокси, TUN-адаптера с маршрутом по умолчанию нет", clientName),
			Text:           i18n.T("Порт 127.0.0.1:%d (%s) слушает процесс %s. Программы, не настроенные на прокси, идут напрямую мимо VPN. %s Для проверки через VPN выберите режим «Прокси».", best.Port, best.Guess, best.Process, sysNote),
			SuggestedRoute: &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: kind, ProxyAddr: fmt.Sprintf("127.0.0.1:%d", best.Port)}}
	}
	if p.Proxies.Suggested != nil {
		return Verdict{Mode: "proxy", Confidence: "medium", Title: i18n.T("Системный прокси задан, но слушающий процесс на нём не найден"),
			Text:           i18n.T("Системный прокси ") + p.Proxies.Suggested.ProxyAddr + i18n.T(" задан; проверьте, запущен ли VPN-клиент. Режим «Прокси» будет работать только если порт отвечает."),
			SuggestedRoute: p.Proxies.Suggested}
	}
	if len(p.Clients) > 0 {
		names := make([]string, 0, len(p.Clients))
		for _, c := range p.Clients {
			names = append(names, c.Name)
		}
		return Verdict{Mode: "client-no-proxy", Confidence: "medium", Title: i18n.T("VPN-клиент запущен, но ни TUN-маршрут, ни локальный прокси не обнаружены"),
			Text:           i18n.T("Обнаружены процессы: ") + strings.Join(names, ", ") + i18n.T(". Возможно, VPN выключен в клиенте или использует нестандартный порт. Сейчас трафик программы идёт напрямую."),
			SuggestedRoute: &model.RouteConfig{Mode: model.RouteSystem}}
	}
	if !r.Known {
		return Verdict{Mode: "unknown", Confidence: "low", Title: i18n.T("Не удалось определить маршрут по умолчанию"), Text: strings.Join(p.Errors, "; ")}
	}
	return Verdict{Mode: "none", Confidence: "medium", Title: i18n.T("VPN или прокси не обнаружены: трафик идёт напрямую"),
		Text:           i18n.T("Маршрут по умолчанию через «%s» (%s), локальных прокси и известных VPN-клиентов нет.", r.IfName, r.IfDesc),
		SuggestedRoute: &model.RouteConfig{Mode: model.RouteSystem}}
}

func splitAddr(s string) (string, string) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// Short returns a one-line description for the UI status line.
func (p Passport) Short() string {
	parts := []string{}
	for _, c := range p.Clients {
		parts = append(parts, c.Name)
	}
	s := p.Verdict.Title
	if len(parts) > 0 {
		s += i18n.T(" · клиенты: ") + strings.Join(parts, ", ")
	}
	return s
}

// splitTunnels lists tunnel adapters that are up but do not carry the default
// route: a sign of split tunnelling (only some traffic goes through the VPN).
func splitTunnels(p *Passport) []string {
	var out []string
	for _, a := range p.Adapters {
		if a.TunLike && a.Up && len(a.IPv4)+len(a.IPv6) > 0 && a.Index != p.DefaultRoute.IfIndex {
			out = append(out, fmt.Sprintf("%s (%s, %s)", a.Name, a.Description, strings.Join(a.IPv4, ", ")))
		}
	}
	return out
}

// SplitTunnelNote describes split-tunnel adapters for the UI, or "".
func (p Passport) SplitTunnelNote() string {
	s := splitTunnels(&p)
	if len(s) == 0 {
		return ""
	}
	return i18n.T("Есть активный VPN/туннельный адаптер без маршрута по умолчанию (split tunneling): ") + strings.Join(s, "; ") + i18n.T(". Через него идёт только часть трафика, поэтому доступность сервисов может различаться.")
}
