// Package web embeds the static UI (plain HTML/CSS/JS, no external resources).
package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html app.css app.js core.js i18n.js header.js run.js speed.js ipstrip.js history.js drawer.js flags.js favicon.svg
var files embed.FS

// FS returns the UI file system with index.html at its root.
func FS() fs.FS { return files }
