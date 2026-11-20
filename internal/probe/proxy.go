package probe

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strconv"

	"vpncheck/internal/i18n"
)

// httpConnect issues an HTTP/1.1 CONNECT over conn and returns the tunnel.
// Proxy authentication is not supported in this version: a 407 is reported as
// a clear error and no credentials are ever sent.
func httpConnect(conn net.Conn, host, port, userAgent string) (net.Conn, error) {
	target := net.JoinHostPort(host, port)
	req := "CONNECT " + target + " HTTP/1.1\r\n" +
		"Host: " + target + "\r\n" +
		"User-Agent: " + userAgent + "\r\n" +
		"Proxy-Connection: keep-alive\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(io.LimitReader(conn, 64*1024), 4096)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, &proxyError{msg: i18n.T("прокси вернул некорректный ответ на CONNECT: ") + sanitizeText(err.Error(), 200)}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return nil, &proxyError{status: 407, msg: i18n.T("прокси требует авторизацию (407); авторизация прокси в этой версии не поддерживается")}
	case resp.StatusCode/100 != 2:
		return nil, &proxyError{status: resp.StatusCode, msg: i18n.T("прокси отклонил CONNECT: %d %s", resp.StatusCode, sanitizeText(http.StatusText(resp.StatusCode), 60))}
	}
	if br.Buffered() > 0 {
		// Bytes after the CONNECT response belong to the tunnel; keep them.
		buffered, _ := br.Peek(br.Buffered())
		return &prefixConn{Conn: conn, prefix: append([]byte(nil), buffered...)}, nil
	}
	return conn, nil
}

// prefixConn replays bytes that were read ahead of the tunnel payload.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// socks5Connect performs the RFC 1928 handshake with "no authentication" and a
// CONNECT request using the domain-name address type, so name resolution
// happens on the proxy side.
func socks5Connect(conn net.Conn, host, port string) (net.Conn, error) {
	pnum, err := strconv.Atoi(port)
	if err != nil || pnum < 1 || pnum > 65535 {
		return nil, &proxyError{msg: i18n.T("некорректный порт назначения")}
	}
	if len(host) == 0 || len(host) > 255 {
		return nil, &proxyError{msg: i18n.T("некорректное имя назначения")}
	}
	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, &proxyError{msg: i18n.T("SOCKS5: нет ответа на приветствие")}
	}
	if reply[0] != 0x05 {
		return nil, &proxyError{msg: i18n.T("SOCKS5: неверная версия протокола в ответе")}
	}
	switch reply[1] {
	case 0x00:
	case 0x02:
		return nil, &proxyError{msg: i18n.T("SOCKS5: прокси требует логин/пароль; авторизация прокси в этой версии не поддерживается")}
	case 0xff:
		return nil, &proxyError{msg: i18n.T("SOCKS5: прокси не принимает подключение без авторизации")}
	default:
		return nil, &proxyError{msg: i18n.T("SOCKS5: неподдерживаемый метод аутентификации 0x%02x", reply[1])}
	}
	// Request: VER CMD=CONNECT RSV ATYP=DOMAIN LEN NAME PORT.
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(pnum))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return nil, &proxyError{msg: i18n.T("SOCKS5: нет ответа на CONNECT")}
	}
	if head[0] != 0x05 {
		return nil, &proxyError{msg: i18n.T("SOCKS5: неверная версия протокола в ответе")}
	}
	if head[1] != 0x00 {
		return nil, &proxyError{msg: "SOCKS5: " + socksReplyText(head[1])}
	}
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, &proxyError{msg: i18n.T("SOCKS5: усечённый ответ")}
		}
		skip = int(l[0])
	default:
		return nil, &proxyError{msg: i18n.T("SOCKS5: неизвестный тип адреса в ответе")}
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		return nil, &proxyError{msg: i18n.T("SOCKS5: усечённый ответ")}
	}
	return conn, nil
}

func socksReplyText(code byte) string {
	switch code {
	case 0x01:
		return i18n.T("общая ошибка SOCKS-сервера")
	case 0x02:
		return i18n.T("подключение запрещено правилами прокси")
	case 0x03:
		return i18n.T("сеть недоступна (со стороны прокси)")
	case 0x04:
		return i18n.T("узел недоступен (со стороны прокси)")
	case 0x05:
		return i18n.T("подключение отклонено (со стороны прокси)")
	case 0x06:
		return i18n.T("TTL истёк (со стороны прокси)")
	case 0x07:
		return i18n.T("команда не поддерживается")
	case 0x08:
		return i18n.T("тип адреса не поддерживается")
	}
	return i18n.T("ошибка ") + strconv.Itoa(int(code))
}
