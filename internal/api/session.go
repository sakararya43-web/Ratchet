package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

type Principal struct {
	TenantID string `json:"tenant_id"`
	ActorID  string `json:"actor_id"`
}
type principalKey struct{}

func SessionPrincipal(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

var tenantSyntax = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

const sessionCookie = "__Host-ratchet"

type rateEntry struct {
	at    time.Time
	count int
}
type Sessions struct {
	pool         *pgxpool.Pool
	origin       string
	key          []byte
	ttl          time.Duration
	mu           sync.Mutex
	attempts     map[[32]byte]rateEntry
	passwordWork chan struct{}
}

func NewSessions(pool *pgxpool.Pool, origin string, key []byte, ttl time.Duration) (*Sessions, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || pool == nil || len(key) != 32 || ttl < time.Minute || ttl > 24*time.Hour {
		return nil, errors.New("sessions require a canonical HTTPS origin, pool, key and bounded lifetime")
	}
	return &Sessions{pool: pool, origin: origin, key: append([]byte(nil), key...), ttl: ttl, attempts: map[[32]byte]rateEntry{}, passwordWork: make(chan struct{}, 4)}, nil
}
func (s *Sessions) csrf(token string) string {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte("RATCHET_CSRF_V1:" + token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func authJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func decodeBody(r *http.Request, value any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 16385))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	var more any
	if d.Decode(&more) != io.EOF {
		return errors.New("one JSON value required")
	}
	return nil
}
func authTx(ctx context.Context, pool *pgxpool.Pool, tenant string, fn func(pgx.Tx) error) error {
	if !tenantSyntax.MatchString(tenant) {
		return errors.New("invalid tenant")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err = tx.Exec(ctx, `SELECT set_config('ratchet.tenant_id',$1,true)`, tenant); err != nil {
		return err
	}
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ProvisionUser runs through the explicit migration/admin command; the runtime
// role has SELECT only on accounts. Passwords are never checked into fixtures.
func ProvisionUser(ctx context.Context, pool *pgxpool.Pool, p Principal, password string) error {
	if !tenantSyntax.MatchString(p.TenantID) || p.ActorID == "" || len(p.ActorID) > 256 || len(password) < 16 || len(password) > 256 {
		return errors.New("invalid account or password length")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 64*1024, 1, 32)
	return authTx(ctx, pool, p.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO ratchet.console_users(tenant_id,actor_id,salt,password_hash) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,actor_id) DO UPDATE SET salt=excluded.salt,password_hash=excluded.password_hash,disabled=false`, p.TenantID, p.ActorID, salt, hash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM ratchet.console_sessions WHERE tenant_id=$1 AND actor_id=$2`, p.TenantID, p.ActorID)
		return err
	})
}
func (s *Sessions) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.login)
	mux.Handle("GET /session", s.Require(http.HandlerFunc(s.current)))
	mux.Handle("POST /logout", s.Require(http.HandlerFunc(s.logout)))
	return mux
}
func (s *Sessions) login(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.Header.Get("Origin") != s.origin {
		http.Error(w, "same-origin HTTPS required", http.StatusForbidden)
		return
	}
	// Bound both online guessing and concurrent Argon2 memory use. No passwords
	// or bearer tokens appear in the rate-limit map or log output.
	address := strings.Split(r.RemoteAddr, ":")[0]
	bucket := sha256.Sum256([]byte(address))
	s.mu.Lock()
	entry := s.attempts[bucket]
	now := time.Now()
	if now.Sub(entry.at) > time.Minute {
		entry = rateEntry{at: now}
	}
	entry.count++
	s.attempts[bucket] = entry
	if len(s.attempts) > 10000 {
		for k, v := range s.attempts {
			if now.Sub(v.at) > time.Minute {
				delete(s.attempts, k)
			}
		}
	}
	refused := entry.count > 5 || len(s.attempts) > 10000
	s.mu.Unlock()
	if refused {
		http.Error(w, "login rate limit", http.StatusTooManyRequests)
		return
	}
	select {
	case s.passwordWork <- struct{}{}:
		defer func() { <-s.passwordWork }()
	default:
		http.Error(w, "login capacity", http.StatusTooManyRequests)
		return
	}
	var in struct {
		TenantID string `json:"tenant_id"`
		ActorID  string `json:"actor_id"`
		Password string `json:"password"`
	}
	if decodeBody(r, &in) != nil || !tenantSyntax.MatchString(in.TenantID) || in.ActorID == "" || len(in.ActorID) > 256 || len(in.Password) > 256 {
		http.Error(w, "invalid login", http.StatusBadRequest)
		return
	}
	var salt, expected []byte
	var disabled bool
	err := authTx(r.Context(), s.pool, in.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `SELECT salt,password_hash,disabled FROM ratchet.console_users WHERE tenant_id=$1 AND actor_id=$2`, in.TenantID, in.ActorID).Scan(&salt, &expected, &disabled)
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "login unavailable", http.StatusServiceUnavailable)
		return
	}
	if len(salt) != 16 {
		salt = make([]byte, 16)
		expected = make([]byte, 32)
	}
	computed := argon2.IDKey([]byte(in.Password), salt, 2, 64*1024, 1, 32)
	if err != nil || disabled || subtle.ConstantTimeCompare(expected, computed) != 1 {
		http.Error(w, "invalid login", http.StatusUnauthorized)
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		http.Error(w, "login unavailable", 503)
		return
	}
	token := in.TenantID + "." + base64.RawURLEncoding.EncodeToString(secret)
	hash := sha256.Sum256([]byte(token))
	var expires time.Time
	err = authTx(r.Context(), s.pool, in.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `INSERT INTO ratchet.console_sessions(tenant_id,token_hash,actor_id,expires_at) SELECT $1,$2,$3,clock_timestamp()+$4*interval '1 second' FROM ratchet.console_users WHERE tenant_id=$1 AND actor_id=$3 AND NOT disabled RETURNING expires_at`, in.TenantID, hash[:], in.ActorID, s.ttl.Seconds()).Scan(&expires)
	})
	if err != nil {
		http.Error(w, "login unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(s.ttl.Seconds()), Expires: expires})
	authJSON(w, 200, map[string]any{"principal": Principal{in.TenantID, in.ActorID}, "csrf_token": s.csrf(token), "expires_at": expires})
}
func (s *Sessions) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS required", 401)
			return
		}
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || len(cookie.Value) > 200 {
			http.Error(w, "session required", 401)
			return
		}
		tenant, _, ok := strings.Cut(cookie.Value, ".")
		if !ok || !tenantSyntax.MatchString(tenant) {
			http.Error(w, "invalid session", 401)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != s.origin || !hmac.Equal([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.csrf(cookie.Value))) {
				http.Error(w, "CSRF validation failed", 403)
				return
			}
		}
		hash := sha256.Sum256([]byte(cookie.Value))
		p := Principal{TenantID: tenant}
		err = authTx(r.Context(), s.pool, tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(), `SELECT s.actor_id FROM ratchet.console_sessions s JOIN ratchet.console_users u USING(tenant_id,actor_id) WHERE s.tenant_id=$1 AND s.token_hash=$2 AND s.expires_at>clock_timestamp() AND NOT u.disabled`, tenant, hash[:]).Scan(&p.ActorID)
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "session expired or revoked", 401)
			} else {
				http.Error(w, "session unavailable", 503)
			}
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}
func (s *Sessions) current(w http.ResponseWriter, r *http.Request) {
	p, _ := SessionPrincipal(r.Context())
	cookie, _ := r.Cookie(sessionCookie)
	authJSON(w, 200, map[string]any{"principal": p, "csrf_token": s.csrf(cookie.Value)})
}
func (s *Sessions) logout(w http.ResponseWriter, r *http.Request) {
	p, _ := SessionPrincipal(r.Context())
	cookie, _ := r.Cookie(sessionCookie)
	hash := sha256.Sum256([]byte(cookie.Value))
	err := authTx(r.Context(), s.pool, p.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(r.Context(), `DELETE FROM ratchet.console_sessions WHERE tenant_id=$1 AND token_hash=$2`, p.TenantID, hash[:])
		return err
	})
	if err != nil {
		http.Error(w, "logout unavailable", 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
