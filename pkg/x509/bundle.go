package x509

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"iter"
	"os"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Bundle represents a collection of X.509 certificates.
// It preserves certificate ordering to ensure that loading and dumping produces
// identical output (when using the same ordering).
type Bundle struct {
	// certs stores the certificates in order
	certs []*x509.Certificate
}

// NewBundle creates a new empty Bundle.
func NewBundle() *Bundle {
	return &Bundle{
		certs: []*x509.Certificate{},
	}
}

// NewBundleFromFile creates a new Bundle by loading certificates from
// the given file path.
func NewBundleFromFile(path string) (*Bundle, error) {
	b := NewBundle()

	err := b.LoadFromFile(path)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// NewBundleFromPEM creates a new Bundle by loading certificates from
// the given PEM-encoded string.
func NewBundleFromPEM(pemData string) (*Bundle, error) {
	b := NewBundle()

	err := b.LoadFromPEM(pemData)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// NewBundleFromConfigMap creates a new Bundle by loading certificates from
// the specified Kubernetes ConfigMap.

func NewBundleFromConfigMap(configMap *corev1.ConfigMap, key string) (*Bundle, error) {
	b := NewBundle()

	err := b.LoadFromConfigMap(configMap, key)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// NewBundleFromSecret creates a new Bundle by loading certificates from
// the specified Kubernetes Secret.
func NewBundleFromSecret(secret *corev1.Secret, key string) (*Bundle, error) {
	b := NewBundle()

	err := b.LoadFromSecret(secret, key)

	if err != nil {
		return nil, err
	}

	return b, nil
}

// LoadFromFile loads certificates from a PEM file into the bundle.
// The file must contain one or more PEM-encoded certificates.
func (b *Bundle) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	return b.LoadFromPEM(string(data))
}

// LoadFromPEM loads certificates from a PEM-encoded string into the bundle.
// This preserves the ordering of certificates in the PEM data.
func (b *Bundle) LoadFromPEM(pemData string) error {
	if pemData == "" {
		return nil
	}

	// Reset the bundle
	b.certs = []*x509.Certificate{}

	// Parse PEM blocks
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}

		b.certs = append(b.certs, cert)
	}

	if len(b.certs) == 0 {
		return fmt.Errorf("no valid certificates found in PEM data")
	}

	return nil
}

// LoadFromSecret loads certificates from a Kubernetes Secret.
// It looks for certificate data in the following keys (in order):
// - tls.crt (standard kubernetes.io/tls)
// - crt.pem (linkerd.io/tls)
func (b *Bundle) LoadFromSecret(secret *corev1.Secret, key string) error {
	// If a key is specified, use it. If not, try the common keys.
	var certData []byte
	var ok bool

	if key != "" {
		certData, ok = secret.Data[key]
		if !ok {
			return fmt.Errorf("key %s not found in Secret", key)
		}
	} else {
		// Try common keys
		for _, k := range []string{"tls.crt", "crt.pem"} {
			certData, ok = secret.Data[k]
			if ok {
				break
			}
		}
		if !ok {
			return fmt.Errorf("no certificate data found in Secret (tried keys: tls.crt, crt.pem)")
		}
	}

	return b.LoadFromPEM(string(certData))
}

// LoadFromConfigMap loads certificates from a Kubernetes ConfigMap.
// If key is empty, it defaults to "ca-bundle.crt".
func (b *Bundle) LoadFromConfigMap(configMap *corev1.ConfigMap, key string) error {
	if key == "" {
		key = "ca-bundle.crt"
	}

	certData, ok := configMap.Data[key]
	if !ok {
		return fmt.Errorf("key %s not found in ConfigMap", key)
	}

	return b.LoadFromPEM(certData)
}

// Add adds a certificate to the bundle.
// Returns an error if the certificate is already present (based on Subject Key ID).
func (b *Bundle) Add(cert *x509.Certificate) error {
	ski := getSubjectKeyID(cert)

	// Check if already present
	for _, existing := range b.certs {
		if getSubjectKeyID(existing) == ski {
			return fmt.Errorf("certificate with Subject Key ID %s already exists in bundle", ski)
		}
	}

	b.certs = append(b.certs, cert)
	return nil
}

// Remove removes a certificate from the bundle by Subject Key ID.
// Returns an error if the certificate is not found.
func (b *Bundle) Remove(ski string) error {
	ski = strings.ToLower(strings.ReplaceAll(ski, ":", ""))

	for i, cert := range b.certs {
		if getSubjectKeyID(cert) == ski {
			// Remove from slice
			b.certs = append(b.certs[:i], b.certs[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("certificate with Subject Key ID %s not found in bundle", ski)
}

// RemoveCert removes a certificate from the bundle.
// Returns an error if the certificate is not found.
func (b *Bundle) RemoveCert(cert *x509.Certificate) error {
	return b.Remove(getSubjectKeyID(cert))
}

// Contains checks if a certificate is present in the bundle (by Subject Key ID).
func (b *Bundle) Contains(cert *x509.Certificate) bool {
	ski := getSubjectKeyID(cert)
	for _, existing := range b.certs {
		if getSubjectKeyID(existing) == ski {
			return true
		}
	}
	return false
}

// ContainsSKI checks if a certificate with the given Subject Key ID is present.
func (b *Bundle) ContainsSKI(ski string) bool {
	ski = strings.ToLower(strings.ReplaceAll(ski, ":", ""))
	for _, cert := range b.certs {
		if getSubjectKeyID(cert) == ski {
			return true
		}
	}
	return false
}

// Certificates returns all certificates in the bundle.
func (b *Bundle) Certificates() []*x509.Certificate {
	// Return a copy to prevent external modification
	result := make([]*x509.Certificate, len(b.certs))
	copy(result, b.certs)
	return result
}

// All returns an iterator over all certificates in the bundle.
// This allows using range loops with Go 1.23+ syntax:
//
//	for cert := range bundle.All() {
//		// use cert
//	}
func (b *Bundle) All() iter.Seq[*x509.Certificate] {
	return func(yield func(*x509.Certificate) bool) {
		for _, cert := range b.certs {
			if !yield(cert) {
				return
			}
		}
	}
}

// Len returns the number of certificates in the bundle.
func (b *Bundle) Len() int {
	return len(b.certs)
}

// PEM returns the PEM-encoded representation of the bundle.
// Certificates are encoded in the same order they were loaded or added.
func (b *Bundle) PEM() string {
	if len(b.certs) == 0 {
		return ""
	}

	var result strings.Builder
	for _, cert := range b.certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		result.Write(pem.EncodeToMemory(pemBlock))
	}

	return result.String()
}

// WriteTo writes the bundle to a file in PEM format.
func (b *Bundle) WriteTo(path string) error {
	pemData := b.PEM()
	if pemData == "" {
		return fmt.Errorf("bundle is empty")
	}

	if err := os.WriteFile(path, []byte(pemData), 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// getSubjectKeyID returns the Subject Key ID of a certificate as a hex string.
// If the certificate has a SubjectKeyId extension, it uses that.
// Otherwise, it calculates it from the public key.
func getSubjectKeyID(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) > 0 {
		return fmt.Sprintf("%x", cert.SubjectKeyId)
	}
	// If no SubjectKeyId, calculate from public key
	// This is a simplified version - in production you might want to use SHA-1 hash
	if len(cert.RawSubjectPublicKeyInfo) >= 20 {
		return fmt.Sprintf("%x", cert.RawSubjectPublicKeyInfo[:20])
	}
	return fmt.Sprintf("%x", cert.RawSubjectPublicKeyInfo)
}
