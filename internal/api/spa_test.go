package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/sakararya43-web/Ratchet/internal/webassets"
)

func TestActualWebAssetsAndReservedRoutes(t *testing.T) {
	handler, err := NewSPA(webassets.Files())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		code int
	}{{"/", 200}, {"/changes/review", 200}, {"/api", 404}, {"/api/unknown", 404}, {"/readyz", 404}, {"/livez", 404}, {"/metrics", 404}, {"/ratchet.v1.ChangeService/GetChange", 404}, {"/missing.js", 404}, {"/../index.html", 404}} {
		r := httptest.NewRequest("GET", test.path, nil)
		r.Header.Set("Accept", "text/html")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.code {
			t.Errorf("%s: %d", test.path, w.Code)
		}
	}
}
func TestSPARefusesMissingOrCorruptBuild(t *testing.T) {
	sum := sha256.Sum256([]byte("real build"))
	manifest, _ := json.Marshal(map[string]any{"files": map[string]string{"index.html": hex.EncodeToString(sum[:])}})
	for _, files := range []fstest.MapFS{{}, {"manifest.json": {Data: manifest}}, {"manifest.json": {Data: manifest}, "index.html": {Data: []byte("substitute")}}} {
		if _, err := NewSPA(files); err == nil {
			t.Fatal("accepted missing/corrupt build")
		}
	}
}
