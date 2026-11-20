package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"unicode"

	"vpncheck/internal/guard"
	"vpncheck/internal/i18n"
	"vpncheck/internal/model"
)

// proxyError is an error reported by or about the configured proxy.
type proxyError struct {
	msg    string
	status int
}

func (e *proxyError) Error() string { return e.msg }

// classifyErr maps a Go error to a coarse kind and a safe text.
func classifyErr(err error) (model.ErrorKind, string) {
	if err == nil {
		return model.ErrNone, ""
	}
	text := sanitizeText(err.Error(), 300)

	if errors.Is(err, context.Canceled) {
		return model.ErrCancelled, i18n.T("операция отменена")
	}
	var be *guard.BlockedError
	if errors.As(err, &be) {
		return model.ErrBlockedAddr, sanitizeText(be.Error(), 300)
	}
	var pe *proxyError
	if errors.As(err, &pe) {
		return model.ErrProxy, sanitizeText(pe.msg, 300)
	}
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsTimeout {
			return model.ErrTimeout, i18n.T("тайм-аут DNS: ") + text
		}
		if de.IsNotFound {
			return model.ErrDNS, i18n.T("имя не найдено: ") + sanitizeText(de.Name, 253)
		}
		return model.ErrDNS, text
	}
	var (
		unknownAuth x509.UnknownAuthorityError
		certInvalid x509.CertificateInvalidError
		hostErr     x509.HostnameError
		sysRoots    x509.SystemRootsError
		verifyErr   *tls.CertificateVerificationError
	)
	if errors.As(err, &unknownAuth) || errors.As(err, &certInvalid) || errors.As(err, &hostErr) || errors.As(err, &sysRoots) || errors.As(err, &verifyErr) {
		return model.ErrTLSCert, text
	}
	var rhe tls.RecordHeaderError
	var alert tls.AlertError
	if errors.As(err, &rhe) || errors.As(err, &alert) {
		return model.ErrTLSHandshake, text
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.ErrTimeout, i18n.T("превышен тайм-аут")
	}
	if kind, ok := errnoKind(err); ok {
		return kind, text
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return model.ErrTimeout, i18n.T("превышен тайм-аут: ") + text
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return model.ErrReset, i18n.T("соединение закрыто удалённой стороной")
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "tls:") || strings.Contains(lower, "handshake"):
		return model.ErrTLSHandshake, text
	case strings.Contains(lower, "forcibly closed") || strings.Contains(lower, "connection reset"):
		return model.ErrReset, text
	case strings.Contains(lower, "refused"):
		return model.ErrRefused, text
	case strings.Contains(lower, "malformed") || strings.Contains(lower, "http:"):
		return model.ErrHTTPProtocol, text
	}
	return model.ErrOther, text
}

// sanitizeText removes control characters and caps the length. It is used for
// everything that came from the network or from error strings before it is
// stored or displayed (always as text, never as HTML).
func sanitizeText(s string, max int) string {
	var b strings.Builder
	b.Grow(len(s))
	n := 0
	lastSpace := false
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			continue
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteRune(r)
		n++
		if n >= max {
			b.WriteString("…")
			break
		}
	}
	return strings.TrimSpace(b.String())
}
