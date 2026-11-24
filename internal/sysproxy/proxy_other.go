//go:build !windows && !linux

package sysproxy

import (
	"errors"

	"vpncheck/internal/i18n"
)

func readSystemProxy() (systemProxy, error) {
	return systemProxy{}, errors.New(i18n.T("системные настройки прокси этой ОС не читаются"))
}
