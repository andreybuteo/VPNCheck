//go:build windows

package sysproxy

import (
	"syscall"
	"unsafe"

	"vpncheck/internal/i18n"
)

func readSystemProxy() (systemProxy, error) {
	enabled, server, pac, err := readWinINET()
	return systemProxy{System: "WinINET", Source: i18n.T("Настройки прокси Windows (WinINET, HKCU)"), Enabled: enabled, Server: server, PAC: pac}, err
}

// readWinINET reads HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings.
func readWinINET() (enabled bool, server, pac string, err error) {
	var k syscall.Handle
	path, _ := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err = syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, path, 0, syscall.KEY_READ, &k); err != nil {
		return false, "", "", err
	}
	defer syscall.RegCloseKey(k)
	enabled = regDWORD(k, "ProxyEnable") == 1
	server = regString(k, "ProxyServer")
	pac = regString(k, "AutoConfigURL")
	return enabled, server, pac, nil
}

func regString(k syscall.Handle, name string) string {
	n, _ := syscall.UTF16PtrFromString(name)
	var typ uint32
	var buf [2048]uint16
	size := uint32(len(buf) * 2)
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return ""
	}
	if typ != syscall.REG_SZ && typ != syscall.REG_EXPAND_SZ {
		return ""
	}
	return syscall.UTF16ToString(buf[:size/2])
}

func regDWORD(k syscall.Handle, name string) uint32 {
	n, _ := syscall.UTF16PtrFromString(name)
	var typ uint32
	var val uint32
	size := uint32(4)
	if err := syscall.RegQueryValueEx(k, n, nil, &typ, (*byte)(unsafe.Pointer(&val)), &size); err != nil || typ != syscall.REG_DWORD {
		return 0
	}
	return val
}
