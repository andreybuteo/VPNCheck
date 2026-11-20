// Package sysproxy reads the Windows user proxy settings (WinINET, the ones
// browsers use) and the proxy environment variables. The result is a hint for
// the user only: the application never applies it automatically, and
// net/http's ProxyFromEnvironment is never used for probes.
package sysproxy

import (
	"net/url"
	"os"
	"strconv"
	"strings"

	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// Hint is what was detected.
type Hint struct {
	Found     bool               `json:"found"`
	Sources   []string           `json:"sources"`
	Enabled   bool               `json:"enabled"`
	Server    string             `json:"server,omitempty"`
	PAC       string             `json:"pac,omitempty"`
	Env       map[string]string  `json:"env,omitempty"`
	Suggested *model.RouteConfig `json:"suggested,omitempty"`
	Notes     []string           `json:"notes"`
}

// Short returns a one-line description without credentials.
func (h Hint) Short() string {
	if !h.Found {
		return ""
	}
	parts := []string{}
	if h.Enabled && h.Server != "" {
		parts = append(parts, "WinINET: "+h.Server)
	}
	if h.PAC != "" {
		parts = append(parts, "PAC")
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"} {
		if v := h.Env[k]; v != "" {
			parts = append(parts, k+"="+v)
			break
		}
	}
	return strings.Join(parts, "; ")
}

// Detect reads WinINET (registry) and environment variables.
func Detect() Hint {
	h := Hint{Env: map[string]string{}, Notes: []string{}}
	enabled, server, pac, err := readWinINET()
	if err == nil && (server != "" || pac != "") {
		h.Found = true
		h.Sources = append(h.Sources, i18n.T("Настройки прокси Windows (WinINET, HKCU)"))
		h.Enabled = enabled
		h.Server = sanitize(server)
		h.PAC = sanitize(pac)
		if pac != "" {
			h.Notes = append(h.Notes, i18n.T("Обнаружен PAC/автоконфигурация (")+h.PAC+i18n.T("): в этой версии не поддерживается; укажите прокси вручную."))
		}
		if enabled && server != "" {
			if rc := parseWinINET(server); rc != nil {
				h.Suggested = rc
			} else {
				h.Notes = append(h.Notes, i18n.T("Формат системного прокси не распознан; укажите адрес вручную."))
			}
		}
		if !enabled && server != "" {
			h.Notes = append(h.Notes, i18n.T("Системный прокси задан, но выключен."))
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"} {
		v := firstEnv(k)
		if v == "" {
			continue
		}
		h.Found = true
		clean, hadCreds, rc := parseEnvProxy(v)
		h.Env[k] = clean
		if hadCreds {
			h.Notes = append(h.Notes, i18n.T("Переменная ")+k+i18n.T(" содержит учётные данные; они скрыты и не поддерживаются."))
		}
		if h.Suggested == nil && rc != nil && k != "NO_PROXY" {
			h.Suggested = rc
		}
	}
	if len(h.Env) > 0 {
		h.Sources = append(h.Sources, i18n.T("Переменные окружения"))
	}
	if h.Found {
		h.Notes = append(h.Notes, i18n.T("Это только подсказка: приложение не применяет системный прокси автоматически. Путь браузера (через системный прокси) и путь программы в режиме «Системный маршрут» могут различаться."))
	}
	return h
}

func firstEnv(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return os.Getenv(strings.ToLower(k))
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
}

// parseWinINET handles "host:port" and "http=host:port;https=host:port;socks=host:port".
func parseWinINET(server string) *model.RouteConfig {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil
	}
	if !strings.Contains(server, "=") {
		if addr := cleanAddr(server); addr != "" {
			return &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: addr}
		}
		return nil
	}
	entries := map[string]string{}
	for _, part := range strings.Split(server, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			entries[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	for _, k := range []string{"https", "http"} {
		if addr := cleanAddr(entries[k]); addr != "" {
			return &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: addr}
		}
	}
	if addr := cleanAddr(entries["socks"]); addr != "" {
		return &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxySOCKS5, ProxyAddr: addr}
	}
	return nil
}

// cleanAddr accepts host:port with an optional scheme prefix and rejects credentials.
func cleanAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if strings.Contains(s, "@") {
		return ""
	}
	s = strings.TrimSuffix(s, "/")
	host, port, err := splitHostPort(s)
	if err != nil || host == "" {
		return ""
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return ""
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + port
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", errNoPort
	}
	host := s[:i]
	port := s[i+1:]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	return host, port, nil
}

type strErr string

func (e strErr) Error() string { return string(e) }

const errNoPort = strErr("no port")

// parseEnvProxy parses a proxy URL from the environment, hides credentials and
// suggests a route where the scheme is supported.
func parseEnvProxy(v string) (clean string, hadCreds bool, rc *model.RouteConfig) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false, nil
	}
	if !strings.Contains(v, "://") {
		// NO_PROXY lists or bare host:port.
		if strings.Contains(v, ",") || strings.Contains(v, "@") {
			return sanitize(strings.ReplaceAll(v, "@", "["+i18n.T("скрыто")+"]@")), strings.Contains(v, "@"), nil
		}
		if addr := cleanAddr(v); addr != "" {
			return addr, false, &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: addr}
		}
		return sanitize(v), false, nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return sanitize(v), false, nil
	}
	if u.User != nil {
		hadCreds = true
		u.User = nil
	}
	clean = sanitize(u.String())
	addr := cleanAddr(u.Host)
	if addr == "" {
		return clean, hadCreds, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		rc = &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxyHTTP, ProxyAddr: addr}
	case "socks5", "socks5h", "socks":
		rc = &model.RouteConfig{Mode: model.RouteProxy, ProxyKind: model.ProxySOCKS5, ProxyAddr: addr}
	}
	if hadCreds {
		rc = nil // authenticated proxies are not supported; do not suggest
	}
	return clean, hadCreds, rc
}
