package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
)

// DemoLogin explicitly enables only the fixed local prototype requester. The
// normal password verifier, disabled-account checks, rate limit and cookies run.
func (s *Sessions) DemoLogin(password string) (http.Handler, error) {
	return newDemoLogin(s.origin, password, http.HandlerFunc(s.login))
}

func newDemoLogin(origin, password string, login http.Handler) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || (u.Hostname() != "localhost" && !net.ParseIP(u.Hostname()).IsLoopback()) || len(password) < 16 || len(password) > 256 {
		return nil, errors.New("demo login requires a loopback HTTPS origin and a provisioned requester password")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if r.TLS == nil || r.Header.Get("Origin") != origin {
			http.Error(w, "same-origin HTTPS required", http.StatusForbidden)
			return
		}
		if decodeBody(r, &struct{}{}) != nil {
			http.Error(w, "empty demo request required", http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(struct {
			Tenant   string `json:"tenant_id"`
			Actor    string `json:"actor_id"`
			Password string `json:"password"`
		}{"tenant-exchange-demo", "user:rahul-assistant", password})
		local := r.Clone(r.Context())
		local.Body = io.NopCloser(bytes.NewReader(body))
		local.ContentLength = int64(len(body))
		login.ServeHTTP(w, local)
	}), nil
}
