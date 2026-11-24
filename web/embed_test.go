package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Every script and stylesheet next to index.html must be embedded: a file
// missing from the //go:embed list loads as 404 and the page stays blank.
func TestAllAssetsEmbedded(t *testing.T) {
	for _, pattern := range []string{"*.js", "*.css", "*.html", "*.svg"} {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			if _, err := fs.Stat(FS(), f); err != nil {
				t.Errorf("%s is not in the //go:embed list of embed.go", f)
			}
		}
	}
	if _, err := os.Stat("index.html"); err != nil {
		t.Fatal("run from the web directory")
	}
}
