package authority

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/canon"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

type Identity struct {
	Tenant, Actor, Method, Path string
	Body                        ports.Digest
	Expires                     int64
}

func identityDigest(identity Identity) (ports.Digest, error) {
	return canon.New().Digest(struct {
		Domain   string
		Identity Identity
	}{"RATCHET_AUTHORITY_GATEWAY_V1", identity})
}

type Client struct {
	URL, Tenant string
	Key         ed25519.PrivateKey
	HTTP        *http.Client
}

func NewClient(address, tenant string, key ed25519.PrivateKey) (*Client, error) {
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || len(key) != 64 || tenant == "" {
		return nil, ErrRefused
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "https" && (!local || u.Scheme != "http") {
		return nil, ErrRefused
	}
	return &Client{URL: address, Tenant: tenant, Key: append(ed25519.PrivateKey(nil), key...), HTTP: &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}, nil
}
func (c *Client) Do(ctx context.Context, actor, path string, input *Input, out any) error {
	method := http.MethodGet
	var body []byte
	var err error
	if input != nil {
		method = http.MethodPost
		body, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, c.URL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hash, err := canon.New().Digest(string(body))
	if err != nil {
		return err
	}
	identity := Identity{c.Tenant, actor, method, path, hash, time.Now().Add(30 * time.Second).Unix()}
	raw, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	digest, err := identityDigest(identity)
	if err != nil {
		return err
	}
	request.Header.Set("X-Ratchet-Authority-Identity", base64.RawURLEncoding.EncodeToString(raw))
	request.Header.Set("X-Ratchet-Authority-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.Key, digest[:])))
	request.Header.Set("Content-Type", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return ErrRefused
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
	if err = decoder.Decode(out); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrRefused
	}
	return nil
}

func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		identityRaw, e1 := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Ratchet-Authority-Identity"))
		signature, e2 := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Ratchet-Authority-Signature"))
		var identity Identity
		if e1 != nil || e2 != nil || len(identityRaw) > 4096 || json.Unmarshal(identityRaw, &identity) != nil {
			http.Error(w, "authenticated gateway required", http.StatusUnauthorized)
			return
		}
		digest, err := identityDigest(identity)
		bodyHash, e := canon.New().Digest(string(raw))
		now := time.Now().Unix()
		if err != nil || e != nil || identity.Tenant != s.Bootstrap.Tenant || identity.Actor == "" || identity.Method != r.Method || identity.Path != r.URL.RequestURI() || bodyHash != identity.Body || identity.Expires < now || identity.Expires > now+60 || !ed25519.Verify(s.Bootstrap.CorePublic, digest[:], signature) {
			http.Error(w, "gateway context refused", http.StatusForbidden)
			return
		}
		var result any
		if r.Method == "GET" && (r.URL.Path == "/v1/state" || r.URL.Path == "/v1/enrollment-state") {
			state, readErr := s.State(r.Context())
			if readErr != nil {
				http.Error(w, "Authority unavailable", http.StatusServiceUnavailable)
				return
			}
			if r.URL.Path == "/v1/enrollment-state" {
				result = s.enrollmentState(identity.Actor, state)
			} else if !s.canView(identity.Actor, state) {
				http.Error(w, "Authority member required", http.StatusForbidden)
				return
			} else {
				result = state
			}
		} else if r.Method == "POST" && (r.URL.Path == "/v1/prepare" || r.URL.Path == "/v1/apply") {
			var input Input
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
				http.Error(w, "exact input required", http.StatusBadRequest)
				return
			}
			if r.URL.Path == "/v1/prepare" {
				result, err = s.Prepare(r.Context(), identity.Actor, input)
			} else {
				var state State
				state, err = s.Apply(r.Context(), identity.Actor, input)
				if err == nil && !s.canView(identity.Actor, state) {
					result = s.enrollmentState(identity.Actor, state)
				} else {
					result = state
				}
			}
			if err != nil {
				http.Error(w, "Authority action or context refused", http.StatusConflict)
				return
			}
		} else {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(result); err != nil {
			return
		}
	})
}

func (s *Service) enrollmentState(actor string, state State) State {
	minimal := map[string]any{}
	store, err := trust.Import(state.Authority)
	if err == nil {
		if genesis, e := store.GetGenesis(); e == nil {
			minimal["genesis"] = map[string]any{"epoch": genesis.Epoch, "threshold_m": genesis.ThresholdM, "members": []trust.AuthorityMember{}, "genesis_digest": genesis.GenesisDigest}
		}
	}
	raw, _ := json.Marshal(minimal)
	candidates := map[string]trust.AuthorityMember{}
	if candidate, ok := state.Candidates[actor]; ok {
		candidates[actor] = candidate
	}
	return State{Candidates: candidates, Authority: raw}
}
func (s *Service) canView(actor string, state State) bool {
	store, err := trust.Import(state.Authority)
	if err != nil {
		return false
	}
	genesis, err := store.GetGenesis()
	if err != nil {
		for _, id := range s.Bootstrap.Actors {
			if id == actor {
				return true
			}
		}
		return false
	}
	for _, member := range genesis.Members {
		if member.ActorID == actor && member.IsActive {
			return true
		}
	}
	return false
}
