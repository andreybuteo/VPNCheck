//go:build !windows

package sysproxy

import (
	"errors"

	"vpncheck/internal/i18n"
)

func readWinINET() (bool, string, string, error) {
	return false, "", "", errors.New(i18n.T("WinINET доступен только в Windows"))
}
