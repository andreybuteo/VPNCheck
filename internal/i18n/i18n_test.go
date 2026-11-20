package i18n

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Only real fmt verbs count, so text such as %LOCALAPPDATA% is not a placeholder.
var verbRe = regexp.MustCompile(`%[-+# 0]*\d*(?:\.\d+)?[vTtbcdoOqxXUeEfFgGspw%]`)

func verbs(s string) string {
	v := verbRe.FindAllString(s, -1)
	sort.Strings(v)
	return strings.Join(v, " ")
}

// TestCatalogsComplete checks that every source key (keys.json, produced by
// go run ./tools/i18nkeys) is translated in every language and that each
// translation keeps exactly the printf verbs of its source.
func TestCatalogsComplete(t *testing.T) {
	data, err := os.ReadFile("keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatal(err)
	}
	for _, l := range Languages {
		if l.Code == Source {
			continue
		}
		raw, err := os.ReadFile("locales/" + l.Code + ".json")
		if err != nil {
			t.Fatalf("%s: %v", l.Code, err)
		}
		var cat map[string]string
		if err := json.Unmarshal(raw, &cat); err != nil {
			t.Fatalf("%s: invalid JSON: %v", l.Code, err)
		}
		missing, bad := 0, 0
		for _, k := range keys {
			v, ok := cat[k]
			if !ok || strings.TrimSpace(v) == "" {
				missing++
				if missing <= 5 {
					t.Errorf("%s: missing translation for %q", l.Code, k)
				}
				continue
			}
			if verbs(k) != verbs(v) {
				bad++
				if bad <= 5 {
					t.Errorf("%s: verbs differ for %q: %q vs %q", l.Code, k, verbs(k), verbs(v))
				}
			}
		}
		if missing > 5 || bad > 5 {
			t.Errorf("%s: %d missing, %d with wrong verbs (of %d keys)", l.Code, missing, bad, len(keys))
		}
	}
}

func TestLookupFallbackAndPlural(t *testing.T) {
	Set("ru")
	if T("проба %d", 3) != "проба 3" {
		t.Fatal("source formatting")
	}
	if Plural(1, "узел", "узла", "узлов") != "узел" || Plural(3, "узел", "узла", "узлов") != "узла" || Plural(11, "узел", "узла", "узлов") != "узлов" {
		t.Fatal("russian plural")
	}
	Set("xx")
	if Lang() != Source {
		t.Fatal("unsupported language must fall back to the source")
	}
	if Normalize("de-AT") != "de" || Normalize("zh_CN") != "zh" || Normalize("pt") != "" {
		t.Fatal("normalize")
	}
	Set("en")
	loadOnce.Do(load)
	if catalogs["en"] == nil {
		catalogs["en"] = map[string]string{}
	}
	catalogs["en"]["(до"] = "(until"
	if got := T(" (до "); got != " (until " {
		t.Fatalf("padded fragment: %q", got)
	}
	if T("нет такого ключа в каталоге") != "нет такого ключа в каталоге" {
		t.Fatal("missing key must return the source")
	}
	Set("ru")
}
