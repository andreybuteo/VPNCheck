package sysproxy

// Parsers for the Linux desktop proxy settings (GNOME gsettings, KDE
// kioslaverc). No build tag, so the tests run everywhere.

import (
	"strconv"
	"strings"
)

// gnomeValue strips the GVariant quoting of `gsettings get` output: 'manual' -> manual.
func gnomeValue(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "@") { // "@as []" and similar typed empties
		return ""
	}
	return strings.Trim(s, `'"`)
}

// gnomeProxy builds the WinINET-style server string from GNOME settings.
// get returns the raw `gsettings get <schema> <key>` output.
func gnomeProxy(get func(schema, key string) string) systemProxy {
	sp := systemProxy{System: "GNOME"}
	mode := gnomeValue(get("org.gnome.system.proxy", "mode"))
	sp.Enabled = mode == "manual"
	if mode == "auto" {
		sp.PAC = gnomeValue(get("org.gnome.system.proxy", "autoconfig-url"))
		sp.Enabled = sp.PAC != ""
	}
	var parts []string
	for _, kind := range []string{"http", "https", "socks"} {
		schema := "org.gnome.system.proxy." + kind
		host := gnomeValue(get(schema, "host"))
		port, _ := strconv.Atoi(gnomeValue(get(schema, "port")))
		if host != "" && port > 0 {
			parts = append(parts, kind+"="+host+":"+strconv.Itoa(port))
		}
	}
	sp.Server = strings.Join(parts, ";")
	return sp
}

// kdeProxy reads the [Proxy Settings] group of ~/.config/kioslaverc.
// ProxyType: 0 none, 1 manual, 2 PAC script, 3 auto-detect, 4 environment.
func kdeProxy(text string) systemProxy {
	sp := systemProxy{System: "KDE"}
	vals := map[string]string{}
	inGroup := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inGroup = line == "[Proxy Settings]"
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && inGroup {
			vals[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	switch vals["ProxyType"] {
	case "1":
		sp.Enabled = true
	case "2":
		sp.PAC = vals["Proxy Config Script"]
		sp.Enabled = sp.PAC != ""
	}
	var parts []string
	for _, kind := range []string{"http", "https", "socks"} {
		if addr := kdeAddr(vals[kind+"Proxy"]); addr != "" {
			parts = append(parts, kind+"="+addr)
		}
	}
	sp.Server = strings.Join(parts, ";")
	return sp
}

// kdeAddr turns "http://127.0.0.1 10809" or "socks://host:1080" into host:port.
func kdeAddr(v string) string {
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	v = strings.TrimSpace(v)
	if host, port, ok := strings.Cut(v, " "); ok {
		v = strings.TrimSpace(host) + ":" + strings.TrimSpace(port)
	}
	if v == "" || !strings.Contains(v, ":") {
		return ""
	}
	return v
}
