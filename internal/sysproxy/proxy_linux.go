//go:build linux

package sysproxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"vpncheck/internal/i18n"
)

// readSystemProxy reads the desktop proxy settings: GNOME (and desktops that
// use its schema: Cinnamon, Budgie, Unity) through gsettings, then KDE from
// kioslaverc. Nothing is changed.
func readSystemProxy() (systemProxy, error) {
	if path, err := exec.LookPath("gsettings"); err == nil {
		get := func(schema, key string) string {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, path, "get", schema, key).Output()
			if err != nil {
				return ""
			}
			return string(out)
		}
		sp := gnomeProxy(get)
		if sp.Server != "" || sp.PAC != "" {
			sp.Source = i18n.T("Настройки прокси GNOME (gsettings)")
			return sp, nil
		}
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".config")
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "kioslaverc")); err == nil {
		sp := kdeProxy(string(b))
		if sp.Server != "" || sp.PAC != "" {
			sp.Source = i18n.T("Настройки прокси KDE (kioslaverc)")
			return sp, nil
		}
	}
	return systemProxy{}, errors.New(i18n.T("системный прокси рабочего стола не задан"))
}
