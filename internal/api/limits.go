package api

import (
	"crypto/sha256"
	"net"
	"net/http"
	"sync"
	"time"
)

const RequestBodyLimit int64 = 1 << 20

type requestBucket struct {
	tokens float64
	at     time.Time
	active int
}

// RequestLimits bounds expensive work without retaining raw actor/IP identifiers.
// It never trusts Forwarded headers or caller-supplied tenant fields.
type RequestLimits struct {
	mu      sync.Mutex
	buckets map[[32]byte]*requestBucket
	active  chan struct{}
}

func NewRequestLimits() *RequestLimits {
	return &RequestLimits{buckets: map[[32]byte]*requestBucket{}, active: make(chan struct{}, 64)}
}
func (l *RequestLimits) Wrap(next http.Handler) http.Handler {
	return l.capacity(l.identities(next))
}

// WrapSessions resolves a real session within the global work/body bound before
// assigning its rate bucket. Successful users behind one NAT must not share an
// anonymous peer bucket. Identification grants no route or CSRF authorization.
func (l *RequestLimits) WrapSessions(sessions *Sessions, next http.Handler) http.Handler {
	return l.capacity(sessions.identify(l.identities(next)))
}

func (l *RequestLimits) capacity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.ContentLength > RequestBodyLimit {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, RequestBodyLimit)
		select {
		case l.active <- struct{}{}:
			defer func() { <-l.active }()
		default:
			refuseCapacity(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func refuseCapacity(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	http.Error(w, "request capacity exceeded", http.StatusTooManyRequests)
}

func (l *RequestLimits) identities(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "peer:"
		if p, ok := SessionPrincipal(r.Context()); ok {
			key = "actor:" + p.TenantID + ":" + p.ActorID
		} else if p, ok := identifiedPrincipal(r); ok {
			key = "actor:" + p.TenantID + ":" + p.ActorID
		} else if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
			key = "certificate:" + string(r.TLS.VerifiedChains[0][0].Raw)
		} else {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			key += host
		}
		hash := sha256.Sum256([]byte(key))
		now := time.Now()
		l.mu.Lock()
		bucket := l.buckets[hash]
		if bucket == nil {
			if len(l.buckets) >= 10000 {
				for k, b := range l.buckets {
					if b.active == 0 && now.Sub(b.at) > 2*time.Minute {
						delete(l.buckets, k)
					}
				}
			}
			if len(l.buckets) >= 10000 {
				l.mu.Unlock()
				refuseCapacity(w)
				return
			}
			bucket = &requestBucket{tokens: 60, at: now}
			l.buckets[hash] = bucket
		}
		bucket.tokens = min(60, bucket.tokens+now.Sub(bucket.at).Seconds()*10)
		bucket.at = now
		if bucket.tokens < 1 || bucket.active >= 8 {
			l.mu.Unlock()
			refuseCapacity(w)
			return
		}
		bucket.tokens--
		bucket.active++
		l.mu.Unlock()
		defer func() { l.mu.Lock(); bucket.active--; l.mu.Unlock() }()
		next.ServeHTTP(w, r)
	})
}
