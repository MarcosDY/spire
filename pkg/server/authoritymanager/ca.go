package authoritymanager

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/x509util"
)

type X509CA struct {
	// Signer is used to sign child certificates.
	Signer crypto.Signer

	// Certificate is the CA certificate.
	Certificate *x509.Certificate

	// UpstreamChain contains the CA certificate and intermediates necessary to
	// chain back to the upstream trust bundle. It is only set if the CA is
	// signed by an UpstreamCA.
	UpstreamChain []*x509.Certificate
}

type JWTKey struct {
	// The signer used to sign keys
	Signer crypto.Signer

	// Kid is the JWT key ID (i.e. "kid" claim)
	Kid string

	// NotAfter is the expiration time of the JWT key.
	NotAfter time.Time
}

func UpstreamSignX509CA(ctx context.Context, signer crypto.Signer, trustDomain spiffeid.TrustDomain, subject pkix.Name, upstreamClient *UpstreamClient, caTTL time.Duration) (*X509CA, error) {
	csr, err := GenerateServerCACSR(signer, trustDomain, subject)
	if err != nil {
		return nil, err
	}

	validator := X509CAValidator{
		TrustDomain: trustDomain,
		Signer:      signer,
	}

	caChain, err := upstreamClient.MintX509CA(ctx, csr, caTTL, validator.ValidateUpstreamX509CA)
	if err != nil {
		return nil, err
	}

	return &X509CA{
		Signer:        signer,
		Certificate:   caChain[0],
		UpstreamChain: caChain,
	}, nil
}

func GenerateServerCACSR(signer crypto.Signer, trustDomain spiffeid.TrustDomain, subject pkix.Name) ([]byte, error) {
	// SignatureAlgorithm is not provided. The crypto/x509 package will
	// select the algorithm appropriately based on the signer key type.
	template := x509.CertificateRequest{
		Subject: subject,
		URIs:    []*url.URL{trustDomain.ID().URL()},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return nil, err
	}

	return csr, nil
}

func SelfSignX509CA(ctx context.Context, signer crypto.Signer, trustDomain spiffeid.TrustDomain, subject pkix.Name, notBefore, notAfter time.Time) (*X509CA, []*x509.Certificate, error) {
	serialNumber, err := x509util.NewSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	template, err := CreateServerCATemplate(trustDomain.ID(), signer.Public(), trustDomain, notBefore, notAfter, serialNumber, subject)
	if err != nil {
		return nil, nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	trustBundle := []*x509.Certificate{cert}

	return &X509CA{
		Signer:      signer,
		Certificate: cert,
	}, trustBundle, nil
}

func CreateServerCATemplate(spiffeID spiffeid.ID, publicKey crypto.PublicKey, trustDomain spiffeid.TrustDomain, notBefore, notAfter time.Time, serialNumber *big.Int, subject pkix.Name) (*x509.Certificate, error) {
	if err := verifySameTrustDomain(trustDomain, spiffeID); err != nil {
		return nil, err
	}

	keyID, err := x509util.GetSubjectKeyID(publicKey)
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		URIs:         []*url.URL{spiffeID.URL()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		SubjectKeyId: keyID,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		PublicKey:             publicKey,
	}, nil
}

func verifySameTrustDomain(td spiffeid.TrustDomain, id spiffeid.ID) error {
	if !id.MemberOf(td) {
		return fmt.Errorf("%q is not a member of trust domain %q", id, td)
	}
	return nil
}
