package kubernetes

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/sakararya43-web/Ratchet/internal/ports"
)

var ErrAuthentication = errors.New("native connector authentication failed")
var connectorToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type KubernetesConnectorKey struct {
	Tenant, Connector, Cluster string
	PublicKey                  ed25519.PublicKey
}

type SignedKubernetesAdmission struct {
	SchemaVersion int       `json:"schema_version"`
	Admission     Admission `json:"admission"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Signature     []byte    `json:"signature"`
}

func KubernetesAdmissionSigningDigest(d ports.Digester, message SignedKubernetesAdmission) (ports.Digest, error) {
	if d == nil {
		return ports.Digest{}, ErrInvalid
	}
	message.Signature = nil
	return d.Digest(struct {
		Domain string                    `json:"domain"`
		Body   SignedKubernetesAdmission `json:"body"`
	}{"RATCHET_KUBERNETES_ADMISSION_V1", message})
}

// VerifyKubernetesAdmission authenticates connector evidence using a key pinned
// outside the request. Its result conveys no execution permit: policy, current
// approvals, target preconditions and atomic one-use consumption remain required
// through DecisionService. A signature is never a second grant path.
func VerifyKubernetesAdmission(d ports.Digester, pin KubernetesConnectorKey, message SignedKubernetesAdmission, now time.Time) (Admission, error) {
	if !connectorToken.MatchString(pin.Tenant) || !connectorToken.MatchString(pin.Connector) || pin.Cluster == "" || len(pin.PublicKey) != ed25519.PublicKeySize || message.SchemaVersion != 1 || message.Admission.Tenant != pin.Tenant || message.Admission.Mutation.Connector != pin.Connector || message.Admission.Mutation.Cluster != pin.Cluster || len(message.Signature) != ed25519.SignatureSize || message.IssuedAt.IsZero() || now.Before(message.IssuedAt) || !now.Before(message.ExpiresAt) || message.ExpiresAt.Sub(message.IssuedAt) > 30*time.Second || !message.ExpiresAt.After(message.IssuedAt) {
		return Admission{}, ErrAuthentication
	}
	digest, err := KubernetesAdmissionSigningDigest(d, message)
	if err != nil || !ed25519.Verify(pin.PublicKey, digest[:], message.Signature) {
		return Admission{}, ErrAuthentication
	}
	if err := message.Admission.Validate(); err != nil {
		return Admission{}, err
	}
	// Detach all nested maps/slices/pointers before passing verified evidence on.
	raw, err := json.Marshal(message.Admission)
	if err != nil {
		return Admission{}, err
	}
	var out Admission
	if err := json.Unmarshal(raw, &out); err != nil {
		return Admission{}, err
	}
	return out, nil
}
