package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// NewSPA requires a complete, hash-verified real build. Missing assets never
// become a placeholder page. The API/health namespace is always reserved.
func NewSPA(files fs.FS) (http.Handler, error) {
	raw, err := fs.ReadFile(files, "manifest.json")
	if err != nil {
		return nil, errors.New("web build manifest required")
	}
	var manifest struct {
		Files map[string]string `json:"files"`
	}
	if json.Unmarshal(raw, &manifest) != nil || len(manifest.Files) == 0 {
		return nil, errors.New("invalid web manifest")
	}
	if _, ok := manifest.Files["index.html"]; !ok {
		return nil, errors.New("built index required")
	}
	for name, digest := range manifest.Files {
		if !fs.ValidPath(name) {
			return nil, errors.New("invalid built path")
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return nil, errors.New("web asset commitment mismatch")
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		first, _, _ := strings.Cut(name, "/")
		if first == "api" || first == "readyz" || first == "livez" || first == "metrics" || strings.HasPrefix(first, "ratchet.") {
			http.NotFound(w, r)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		if name == "" {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		if _, ok := manifest.Files[name]; !ok {
			if path.Ext(name) != "" || !strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		data, err := fs.ReadFile(files, name)
		if err != nil {
			http.Error(w, "built asset unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		if r.Method != "HEAD" {
			_, _ = w.Write(data)
		}
	}), nil
}
