// Command i18nkeys collects every translatable Russian source string into
// internal/i18n/keys.json: string literals in Go code (outside tests), the
// group/label/note texts of the built-in registry, the keys of t("…") and
// tp(n, "…", "…", "…") in the web scripts, and Cyrillic text and title,
// placeholder and aria-label attributes in web/index.html.
//
//	go run ./tools/i18nkeys          # rewrite keys.json
//	go run ./tools/i18nkeys -check   # exit 1 if keys.json is out of date
//
// Translators then fill internal/i18n/locales/<lang>.json (source -> text);
// the i18n package test checks that every key is translated in every language
// with the same printf verbs.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const out = "internal/i18n/keys.json"

func cyr(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

func main() {
	check := flag.Bool("check", false, "only verify that keys.json is up to date")
	flag.Parse()
	keys := map[string]bool{}
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" && cyr(s) {
			keys[s] = true
		}
	}
	// Go literals
	for _, dir := range []string{"internal", "cmd"} {
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if err != nil {
				fail("%s: %v", p, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if s, err := strconv.Unquote(lit.Value); err == nil {
						add(s)
					}
				}
				return true
			})
			return nil
		})
	}
	// built-in registry
	var reg struct {
		Endpoints []struct{ Group, Label, Note string } `json:"endpoints"`
	}
	if data, err := os.ReadFile("internal/registry/default.json"); err == nil {
		if json.Unmarshal(data, &reg) != nil {
			fail("default.json is not valid JSON")
		}
		for _, e := range reg.Endpoints {
			add(e.Group)
			add(e.Label)
			add(e.Note)
		}
	}
	// web scripts
	jsStr := `"((?:[^"\\]|\\.)*)"`
	tRe := regexp.MustCompile(`\bt\(\s*` + jsStr)
	tpRe := regexp.MustCompile(`\btp\([^,()]+(?:\([^()]*\))?,\s*` + jsStr + `\s*,\s*` + jsStr + `\s*,\s*` + jsStr)
	unq := func(s string) string {
		var v string
		if json.Unmarshal([]byte(`"`+s+`"`), &v) != nil {
			fail("cannot decode JS string %q", s)
		}
		return v
	}
	jsFiles, _ := filepath.Glob("web/*.js")
	for _, p := range jsFiles {
		src, _ := os.ReadFile(p)
		for _, m := range tRe.FindAllSubmatch(src, -1) {
			add(unq(string(m[1])))
		}
		for _, m := range tpRe.FindAllSubmatch(src, -1) {
			for _, g := range m[1:] {
				add(unq(string(g)))
			}
		}
	}
	// static HTML: text between tags and translatable attributes
	if src, err := os.ReadFile("web/index.html"); err == nil {
		src = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<!--.*?-->`).ReplaceAll(src, nil)
		ws := regexp.MustCompile(`\s+`)
		for _, m := range regexp.MustCompile(`>([^<>]+)<`).FindAllSubmatch(src, -1) {
			add(ws.ReplaceAllString(html.UnescapeString(string(m[1])), " "))
		}
		for _, m := range regexp.MustCompile(`\b(?:title|placeholder|aria-label)="([^"]*)"`).FindAllSubmatch(src, -1) {
			add(ws.ReplaceAllString(html.UnescapeString(string(m[1])), " "))
		}
	}
	list := make([]string, 0, len(keys))
	for k := range keys {
		list = append(list, k)
	}
	sort.Strings(list)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(list)
	if *check {
		old, _ := os.ReadFile(out)
		if !bytes.Equal(bytes.ReplaceAll(old, []byte("\r\n"), []byte("\n")), buf.Bytes()) {
			fail("%s is out of date: run go run ./tools/i18nkeys", out)
		}
		fmt.Printf("%s is up to date (%d keys)\n", out, len(list))
		return
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		fail("%v", err)
	}
	fmt.Printf("%s: %d keys\n", out, len(list))
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "i18nkeys: "+f+"\n", a...)
	os.Exit(1)
}
