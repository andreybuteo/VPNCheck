package i18n

import "strings"

// posixToBCP47 converts a POSIX locale name (language_TERRITORY.codeset@modifier)
// to a BCP 47 tag; "C", "POSIX" and "C.UTF-8" give "".
func posixToBCP47(v string) string {
	if i := strings.IndexAny(v, ".@"); i >= 0 {
		v = v[:i]
	}
	if v == "" || v == "C" || v == "POSIX" {
		return ""
	}
	return strings.ReplaceAll(v, "_", "-")
}
