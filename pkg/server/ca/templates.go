package ca

import (
	"crypto"
	"crypto/x509"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
)

func CreateX509SVIDTemplate(spiffeID spiffeid.ID, publicKey crypto.PublicKey, trustDomain spiffeid.TrustDomain, notBefore, notAfter time.Time, serialNumber *big.Int) (*x509.Certificate, error) {
	if err := api.VerifyTrustDomainMemberID(trustDomain, spiffeID); err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		URIs:         []*url.URL{spiffeID.URL()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageKeyAgreement |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		PublicKey:             publicKey,
	}, nil
}
