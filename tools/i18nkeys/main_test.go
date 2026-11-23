package main

import "testing"

func TestSkipDirective(t *testing.T) {
	for comment, want := range map[string]bool{"//i18nkeys:skip": true, "//i18nkeys:skip — data": true, "//i18nkeys:skipped": false, "// see //i18nkeys:skip": false} {
		if isSkipDirective(comment) != want {
			t.Errorf("unexpected decision for %q", comment)
		}
	}
}
