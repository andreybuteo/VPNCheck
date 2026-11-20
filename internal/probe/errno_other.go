//go:build !windows

package probe

import (
	"errors"
	"syscall"

	"vpncheck/internal/model"
)

func errnoKind(err error) (model.ErrorKind, bool) {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return "", false
	}
	switch e {
	case syscall.ECONNREFUSED:
		return model.ErrRefused, true
	case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE:
		return model.ErrReset, true
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EADDRNOTAVAIL:
		return model.ErrUnreachable, true
	case syscall.ETIMEDOUT:
		return model.ErrTimeout, true
	}
	return "", false
}
