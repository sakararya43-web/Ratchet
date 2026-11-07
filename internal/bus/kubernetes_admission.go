package bus

import (
	"errors"
	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"time"
)

type KubernetesConnectorKey = kube.KubernetesConnectorKey
type SignedKubernetesAdmission = kube.SignedKubernetesAdmission

func KubernetesAdmissionSigningDigest(d ports.Digester, message SignedKubernetesAdmission) (ports.Digest, error) {
	return kube.KubernetesAdmissionSigningDigest(d, message)
}
func VerifyKubernetesAdmission(d ports.Digester, pin KubernetesConnectorKey, message SignedKubernetesAdmission, now time.Time) (kube.Admission, error) {
	admission, err := kube.VerifyKubernetesAdmission(d, pin, message, now)
	if errors.Is(err, kube.ErrAuthentication) {
		return kube.Admission{}, ErrAuthentication
	}
	return admission, err
}
