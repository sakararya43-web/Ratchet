// Package webassets embeds the console built by scripts/core-web-build.py.
package webassets

import (
	"embed"
	"io/fs"
)

//go:embed assets
var built embed.FS

func Files() fs.FS { result, _ := fs.Sub(built, "assets"); return result }
