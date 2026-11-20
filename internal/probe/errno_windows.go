//go:build windows

package probe

import (
	"errors"
	"syscall"

	"vpncheck/internal/model"
)

// Winsock error codes (WSAE*), see https://learn.microsoft.com/windows/win32/winsock/windows-sockets-error-codes-2
const (
	wsaENETDOWN      = 10050
	wsaENETUNREACH   = 10051
	wsaECONNABORTED  = 10053
	wsaECONNRESET    = 10054
	wsaETIMEDOUT     = 10060
	wsaECONNREFUSED  = 10061
	wsaEHOSTUNREACH  = 10065
	wsaHOSTNOTFOUND  = 11001
	wsaTRYAGAIN      = 11002
	wsaNODATA        = 11004
	wsaEADDRNOTAVAIL = 10049
)

func errnoKind(err error) (model.ErrorKind, bool) {
	var e syscall.Errno
	if !errors.As(err, &e) {
		return "", false
	}
	switch uintptr(e) {
	case wsaECONNREFUSED:
		return model.ErrRefused, true
	case wsaECONNRESET, wsaECONNABORTED:
		return model.ErrReset, true
	case wsaENETUNREACH, wsaEHOSTUNREACH, wsaENETDOWN, wsaEADDRNOTAVAIL:
		return model.ErrUnreachable, true
	case wsaETIMEDOUT:
		return model.ErrTimeout, true
	case wsaHOSTNOTFOUND, wsaTRYAGAIN, wsaNODATA:
		return model.ErrDNS, true
	}
	return "", false
}
