// Package webassets embeds the console built by scripts/core-web-build.py.
package webassets

import (
	"embed"
	"io/fs"
)

// Include valid bundler chunks whose filenames begin with underscores.
//go:embed all:assets
var built embed.FS

func Files() fs.FS { result, _ := fs.Sub(built, "assets"); return result }
