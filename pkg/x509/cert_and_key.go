package x509

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
)

// PrivateKey represents a private key (RSA or ECDSA).
type PrivateKey interface{}

// CertAndKey represents an X.509 certificate and its associated private key.
// The private key is optional and may be nil.
type CertAndKey struct {
	Certificate *x509.Certificate
	PrivateKey  PrivateKey // *rsa.PrivateKey, *ecdsa.PrivateKey, or nil
}

// NewCertAndKey creates a new CertAndKey with the given certificate and optional private key.
func NewCertAndKey(cert *x509.Certificate, key PrivateKey) *CertAndKey {
	return &CertAndKey{
		Certificate: cert,
		PrivateKey:  key,
	}
}

// NewCertAndKeyFromFiles loads a certificate and optional private key from PEM files.
// If keyPath is empty, only the certificate is loaded.
func NewCertAndKeyFromFiles(certPath, keyPath string) (*CertAndKey, error) {
	ck := &CertAndKey{}

	if err := ck.LoadCertFromFile(certPath); err != nil {
		return nil, err
	}

	if keyPath != "" {
		if err := ck.LoadKeyFromFile(keyPath); err != nil {
			return nil, err
		}
	}

	return ck, nil
}

// NewCertAndKeyFromPEM loads a certificate and optional private key from PEM-encoded strings.
// If keyPEM is empty, only the certificate is loaded.
func NewCertAndKeyFromPEM(certPEM, keyPEM string) (*CertAndKey, error) {
	ck := &CertAndKey{}

	if err := ck.LoadCertFromPEM(certPEM); err != nil {
		return nil, err
	}

	if keyPEM != "" {
		if err := ck.LoadKeyFromPEM(keyPEM); err != nil {
			return nil, err
		}
	}

	return ck, nil
}

// NewCertAndKeyFromSecret loads a certificate and optional private key from a Kubernetes Secret.
// It looks for certificate and key data in standard keys:
// - Certificate: tls.crt, crt.pem, or custom certKey
// - Private key: tls.key, key.pem, or custom keyKey
// If keyKey is empty or the key is not found, only the certificate is loaded.
func NewCertAndKeyFromSecret(secret *corev1.Secret, certKey, keyKey string) (*CertAndKey, error) {
	ck := &CertAndKey{}

	if err := ck.LoadFromSecret(secret, certKey, keyKey); err != nil {
		return nil, err
	}

	return ck, nil
}

// LoadCertFromFile loads a certificate from a PEM file.
func (ck *CertAndKey) LoadCertFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}

	return ck.LoadCertFromPEM(string(data))
}

// LoadCertFromPEM loads a certificate from PEM-encoded data.
func (ck *CertAndKey) LoadCertFromPEM(pemData string) error {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	ck.Certificate = cert
	return nil
}

// LoadKeyFromFile loads a private key from a PEM file.
func (ck *CertAndKey) LoadKeyFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	return ck.LoadKeyFromPEM(string(data))
}

// LoadKeyFromPEM loads a private key from PEM-encoded data.
// Supports RSA and ECDSA private keys.
func (ck *CertAndKey) LoadKeyFromPEM(pemData string) error {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Try different key formats
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		ck.PrivateKey = key
		return nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse EC private key: %w", err)
		}
		ck.PrivateKey = key
		return nil

	case "PRIVATE KEY":
		// PKCS#8 format
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}

		// Validate key type
		switch k := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			ck.PrivateKey = k
			return nil
		default:
			return fmt.Errorf("unsupported private key type: %T", key)
		}

	default:
		return fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// LoadFromSecret loads a certificate and optional private key from a Kubernetes Secret.
// If certKey is empty, it tries common certificate keys: tls.crt, crt.pem
// If keyKey is empty, it tries common key keys: tls.key, key.pem
// The key is optional - if not found, only the certificate is loaded.
func (ck *CertAndKey) LoadFromSecret(secret *corev1.Secret, certKey, keyKey string) error {
	// Load certificate
	var certData []byte
	var ok bool

	type possibility struct{ certKey, keyKey string }

	possibles := []possibility{
		possibility{certKey: "tls.crt", keyKey: "tls.key"},
		possibility{certKey: "crt.pem", keyKey: "key.pem"},
	}

	whichPossible := -1

	if certKey != "" {
		certData, ok = secret.Data[certKey]
		if !ok {
			return fmt.Errorf("certificate key %s not found in Secret", certKey)
		}
	} else {
		// Try common keys
		for i, p := range possibles {
			certData, ok = secret.Data[p.certKey]
			if ok {
				whichPossible = i
				break
			}
		}
	}

	if err := ck.LoadCertFromPEM(string(certData)); err != nil {
		return err
	}

	// Load private key (optional)
	var keyData []byte

	if keyKey != "" {
		keyData, ok = secret.Data[keyKey]
		if !ok {
			// Key was specified but not found - this is an error
			return fmt.Errorf("key %s not found in Secret", keyKey)
		}
	} else if whichPossible < 0 {
		return fmt.Errorf("no key specified and no matching certificate key found in Secret")
	} else {
		// Try whichever possibility matches the cert.
		keyData, ok = secret.Data[possibles[whichPossible].keyKey]

		if !ok {
			// Key not found - this is okay, key is optional
			keyData = nil
		}
	}

	if len(keyData) > 0 {
		if err := ck.LoadKeyFromPEM(string(keyData)); err != nil {
			return err
		}
	}

	return nil
}

// HasKey returns true if the CertAndKey has a private key.
func (ck *CertAndKey) HasKey() bool {
	return ck.PrivateKey != nil
}

// CertPEM returns the certificate as PEM-encoded data.
func (ck *CertAndKey) CertPEM() (string, error) {
	if ck.Certificate == nil {
		return "", fmt.Errorf("no certificate loaded")
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ck.Certificate.Raw,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// KeyPEM returns the private key as PEM-encoded data.
// Returns an error if no private key is present.
func (ck *CertAndKey) KeyPEM() (string, error) {
	if ck.PrivateKey == nil {
		return "", fmt.Errorf("no private key loaded")
	}

	var block *pem.Block

	switch key := ck.PrivateKey.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}
	case *ecdsa.PrivateKey:
		bytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bytes,
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", key)
	}

	return string(pem.EncodeToMemory(block)), nil
}

// WriteCertToFile writes the certificate to a PEM file.
func (ck *CertAndKey) WriteCertToFile(path string) error {
	pemData, err := ck.CertPEM()
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(pemData), 0644); err != nil {
		return fmt.Errorf("failed to write certificate file: %w", err)
	}

	return nil
}

// WriteKeyToFile writes the private key to a PEM file with 0600 permissions.
func (ck *CertAndKey) WriteKeyToFile(path string) error {
	pemData, err := ck.KeyPEM()
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(pemData), 0600); err != nil {
		return fmt.Errorf("failed to write key file: %w", err)
	}

	return nil
}

// WriteToFiles writes both the certificate and private key to separate files.
// Returns an error if no private key is present.
func (ck *CertAndKey) WriteToFiles(certPath, keyPath string) error {
	if err := ck.WriteCertToFile(certPath); err != nil {
		return err
	}

	if err := ck.WriteKeyToFile(keyPath); err != nil {
		return err
	}

	return nil
}
