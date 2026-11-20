// Package i18n translates user-facing text. The Russian source text is the
// key (gettext style): with the Russian interface, or when a translation is
// missing, the source is returned unchanged. Catalogs are embedded JSON files,
// one per language, shared with the web interface (served at /i18n/<lang>.json).
//
// VPN Check is a single-user local application, so the current language is a
// process-wide setting, updated from the interface on every API request.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// Source is the language of the keys.
const Source = "ru"

// Languages lists the supported interface languages in menu order.
var Languages = []Language{
	{Code: "ru", Name: "Русский"},
	{Code: "en", Name: "English"},
	{Code: "de", Name: "Deutsch"},
	{Code: "zh", Name: "中文"},
	{Code: "fa", Name: "فارسی", RTL: true},
	{Code: "ar", Name: "العربية", RTL: true},
}

// Language describes one interface language.
type Language struct {
	Code string `json:"code"`
	Name string `json:"name"`
	RTL  bool   `json:"rtl,omitempty"`
}

//go:embed locales/*.json
var files embed.FS

var (
	current  atomic.Value // string
	loadOnce sync.Once
	catalogs map[string]map[string]string
)

func load() {
	catalogs = map[string]map[string]string{}
	for _, l := range Languages {
		if l.Code == Source {
			continue
		}
		data, err := files.ReadFile("locales/" + l.Code + ".json")
		if err != nil {
			continue
		}
		m := map[string]string{}
		if json.Unmarshal(data, &m) == nil {
			catalogs[l.Code] = m
		}
	}
}

// Supported reports whether code is an interface language.
func Supported(code string) bool {
	for _, l := range Languages {
		if l.Code == code {
			return true
		}
	}
	return false
}

// Normalize maps "de-AT", "zh_CN", "fa-IR" and the like to a supported code,
// or returns "" when nothing matches.
func Normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i > 0 {
		tag = tag[:i]
	}
	if Supported(tag) {
		return tag
	}
	return ""
}

// Set changes the current language; unsupported codes select the source language.
func Set(code string) {
	if !Supported(code) {
		code = Source
	}
	current.Store(code)
}

// Lang returns the current language code.
func Lang() string {
	if v, ok := current.Load().(string); ok && v != "" {
		return v
	}
	return Source
}

// Lookup returns the translation of src for lang, or src itself.
func Lookup(lang, src string) string {
	if lang == Source || src == "" {
		return src
	}
	loadOnce.Do(load)
	cat := catalogs[lang]
	if t, ok := cat[src]; ok && t != "" {
		return t
	}
	// Keys are stored trimmed; fragments glued to other text keep their spaces.
	core := strings.TrimSpace(src)
	if core != src && core != "" {
		if t, ok := cat[core]; ok && t != "" {
			i := strings.Index(src, core)
			return src[:i] + t + src[i+len(core):]
		}
	}
	return src
}

// T translates src into the current language and, when args are given,
// formats it like fmt.Sprintf. Translations keep the verbs of the source.
func T(src string, args ...any) string {
	s := Lookup(Lang(), src)
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

// Errorf is fmt.Errorf with a translated format (%w keeps working).
func Errorf(src string, args ...any) error {
	return fmt.Errorf(Lookup(Lang(), src), args...)
}

// Plural picks a Russian plural form and translates it. Other languages use
// the "one" form for n == 1 and the "many" form otherwise (Chinese has no
// plural, so "many" is written there as the neutral form).
func Plural(n int, one, few, many string) string {
	lang := Lang()
	if lang == Source {
		m10, m100 := n%10, n%100
		switch {
		case m10 == 1 && m100 != 11:
			return one
		case m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14):
			return few
		}
		return many
	}
	if n == 1 && lang != "zh" {
		return Lookup(lang, one)
	}
	return Lookup(lang, many)
}

// Catalog returns the raw catalog of a language (for the web interface).
func Catalog(lang string) map[string]string {
	loadOnce.Do(load)
	if c, ok := catalogs[lang]; ok {
		return c
	}
	return map[string]string{}
}

// File returns the embedded catalog file of a language.
func File(lang string) ([]byte, error) {
	return files.ReadFile("locales/" + lang + ".json")
}
