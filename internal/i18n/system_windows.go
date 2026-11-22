//go:build windows

package i18n

import (
	"syscall"
	"unsafe"
)

// SystemLocale returns the Windows regional format of the user ("ru-RU"),
// which often differs from the display language (many people keep an English
// Windows with Russian formats).
func SystemLocale() string {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	if proc.Find() != nil {
		return ""
	}
	buf := make([]uint16, 85) // LOCALE_NAME_MAX_LENGTH
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}
