package x509

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	pkgtls "github.com/linkerd/linkerd2/pkg/tls"
)

func GenerateAnchor(identity string, validity time.Duration, pathlen int) (*CertAndKey, error) {
	// Generate private key
	key, err := pkgtls.GenerateKey()

	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	notBefore := now.Add(-1 * time.Hour) // backdated by 1 hour for clock skew
	notAfter := now.Add(validity)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: identity,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathlen,
		MaxPathLenZero:        pathlen == 0,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)

	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	ck := &CertAndKey{
		Certificate: cert,
		PrivateKey:  key,
	}

	return ck, nil
}

func GenerateIssuer(anchor *CertAndKey, identity string, validity time.Duration, pathlen int) (*CertAndKey, error) {
	// Generate private key
	key, err := pkgtls.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	notBefore := now.Add(-1 * time.Hour) // backdated by 1 hour for clock skew
	notAfter := now.Add(validity)

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: identity,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathlen,
		MaxPathLenZero:        pathlen == 0,
	}

	// Sign the identity issuer certificate with the anchor CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, anchor.Certificate, key.Public(), anchor.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	ck := &CertAndKey{
		Certificate: cert,
		PrivateKey:  key,
	}

	return ck, nil
}
