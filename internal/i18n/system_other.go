//go:build !windows

package i18n

import "os"

// SystemLocale returns the locale from the environment (LC_ALL, LC_MESSAGES,
// LANG) as a BCP 47 tag: "ru_RU.UTF-8" becomes "ru-RU".
func SystemLocale() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := posixToBCP47(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
