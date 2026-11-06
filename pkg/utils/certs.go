package utils

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/linkerd/linkerd2/pkg/k8s"
	pkgtls "github.com/linkerd/linkerd2/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	TrustRootsConfigMapName  = "linkerd-identity-trust-roots"
	TrustRootsDataKey        = "ca-bundle.crt"
	IdentityIssuerSecretName = "linkerd-identity-issuer"
)

func LoadCertsFromFile(filePath string) ([]*x509.Certificate, error) {
	// Read and parse the certificate
	certData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	newCerts, err := pkgtls.DecodePEMCertificates(string(certData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if len(newCerts) == 0 {
		return nil, fmt.Errorf("no valid certificates found in %s", filePath)
	}

	return newCerts, nil
}

func LoadCertsFromBundle(configMap *corev1.ConfigMap) (string, []*x509.Certificate, error) {
	// Get existing trust bundle
	existingBundle := configMap.Data[TrustRootsDataKey]
	if existingBundle == "" {
		return "", nil, fmt.Errorf("trust bundle is empty")
	}

	existingCerts, err := pkgtls.DecodePEMCertificates(existingBundle)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse existing trust bundle: %w", err)
	}

	return existingBundle, existingCerts, nil
}

func LoadCertAndKeyFromPaths(certPath, keyPath string) (*pkgtls.Cred, string, string, error) {
	// Read certificate file
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to read key file: %w", err)
	}

	// Parse certificate and key
	cred, err := pkgtls.ValidateAndCreateCreds(string(certData), string(keyData))
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to validate certificate and key: %w", err)
	}

	return cred, string(certData), string(keyData), nil
}

// LoadIssuerChainFromPaths loads an identity issuer chain from one or more
// certificate files plus a single key file. The certificate files may each
// hold a single certificate or a multi-certificate bundle, in any order: the
// leaf certificate is the one whose public key matches the key file, and its
// issuers are ordered into a chain by verifying signatures.
//
// Certificates outside the leaf's chain are not an error here: during issuer
// rotation, both the current and the next generation's certificates must be
// present until the control plane can be restarted. They are returned as
// allCerts so the caller can validate them against the trust bundle (see
// ValidateRotationCerts).
//
// It returns the leaf-first chain (the leaf to install is chain[0], and
// this is what gets written to the Secret), the chain as canonical PEM,
// the key PEM, and every certificate that was given.
func LoadIssuerChainFromPaths(certPaths []string, keyPath string) ([]*x509.Certificate, string, string, []*x509.Certificate, error) {
	if len(certPaths) == 0 {
		return nil, "", "", nil, fmt.Errorf("at least one certificate file is required")
	}
	for _, certPath := range certPaths {
		if strings.HasSuffix(certPath, ".key") {
			return nil, "", "", nil, fmt.Errorf("%s: only one key file may be given, as the last argument", certPath)
		}
	}

	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("failed to read key file: %w", err)
	}
	privateKey, err := parsePrivateKeyPEM(string(keyData))
	if err != nil {
		return nil, "", "", nil, fmt.Errorf("failed to parse key file %s: %w", keyPath, err)
	}

	// Load all certificates from all files.
	var certs []*x509.Certificate
	for _, certPath := range certPaths {
		fileCerts, err := LoadCertsFromFile(certPath)
		if err != nil {
			return nil, "", "", nil, err
		}
		certs = append(certs, fileCerts...)
	}

	// The leaf certificate is the one matching the key.
	var leaf *x509.Certificate
	for _, cert := range certs {
		if publicKeyMatches(cert, privateKey) {
			if leaf != nil {
				return nil, "", "", nil, fmt.Errorf("the key matches more than one certificate (%s and %s)", leaf.Subject.CommonName, cert.Subject.CommonName)
			}
			leaf = cert
		}
	}
	if leaf == nil {
		return nil, "", "", nil, fmt.Errorf("the key in %s does not match any of the given certificates (the key must go with the leaf certificate)", keyPath)
	}

	chain := AssembleIssuerChain(leaf, certs)

	// This is what gets written to the Secret: the chain, leaf first.
	certData := pkgtls.EncodeCertificatesPEM(chain...)

	return chain, certData, string(keyData), certs, nil
}

// parsePrivateKeyPEM parses an EC, RSA, or PKCS#8 private key from PEM.
func parsePrivateKeyPEM(pemData string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM data found")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q (want EC PRIVATE KEY, RSA PRIVATE KEY, or PRIVATE KEY)", block.Type)
	}
}

// publicKeyMatches reports whether the private key is the counterpart of the
// certificate's public key.
func publicKeyMatches(cert *x509.Certificate, privateKey crypto.PrivateKey) bool {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return false
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return false
	}
	keyPub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(certPub, keyPub)
}

// CertIDsMatch is gone: identifier matching (issuer/subject DNs and key IDs)
// is ambiguous during rotation, when an old and a replacement certificate
// share a subject. Chain assembly verifies signatures instead.

// canSignCerts reports whether cert may act as a CA in an issuer chain: it
// must assert basicConstraints CA:TRUE and, if it declares any key usage,
// that usage must include certificate signing. This mirrors the constraints
// the identity controller places on chain intermediates, so that chains
// routed through non-CA certificates -- e.g. workload certificates, which
// every mesh participant holds -- are rejected by the CLI instead of by the
// control plane at startup.
func canSignCerts(cert *x509.Certificate) bool {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return false
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return false
	}
	return true
}

// AssembleIssuerChain orders certificates into a leaf-first issuer chain
// starting at leaf, by verifying that each certificate is signed by the one
// above it. Only certificates that may act as CAs (see canSignCerts) are
// followed upward. The chain ends when no given certificate signs the
// current head (the trust bundle takes over above that point). Certificates
// outside the chain -- e.g. the next generation's material during rotation
// -- are simply not included; the caller validates them with
// ValidateRotationCerts. Duplicate certificates are collapsed.
func AssembleIssuerChain(leaf *x509.Certificate, certs []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	inChain := map[string]bool{string(leaf.Raw): true}

	for {
		current := chain[len(chain)-1]

		var next *x509.Certificate
		for _, cert := range certs {
			if inChain[string(cert.Raw)] {
				continue
			}
			if !canSignCerts(cert) {
				continue
			}
			if VerifyCertSignedBy(current, cert) {
				next = cert
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		inChain[string(next.Raw)] = true
	}

	return chain
}

// ValidateRotationCerts checks the invariant that lets `identity update`
// accept a directory holding two generations of certificates: every given
// certificate must be signed by another given certificate or by a
// certificate in the trust bundle -- and following those links must
// eventually reach the trust bundle. The single key file must belong with
// one of the certificates (the leaf to install); that's checked at load
// time.
func ValidateRotationCerts(certs, trustBundle []*x509.Certificate) error {
	for _, cert := range certs {
		if err := certReachesTrustBundle(cert, certs, trustBundle); err != nil {
			return err
		}
	}
	return nil
}

// certReachesTrustBundle walks up from cert through the given certificates
// by signature, and succeeds as soon as it reaches a certificate signed by
// (or identical to) a trust bundle certificate.
func certReachesTrustBundle(cert *x509.Certificate, certs, trustBundle []*x509.Certificate) error {
	current := cert

	// At most len(certs) upward hops are meaningful; more means a loop.
	for step := 0; step <= len(certs); step++ {
		for _, trustCert := range trustBundle {
			if current.Equal(trustCert) || VerifyCertSignedBy(current, trustCert) {
				return nil
			}
		}

		var next *x509.Certificate
		for _, c := range certs {
			if bytes.Equal(c.Raw, current.Raw) {
				continue
			}
			// Only CA certificates may vouch for another certificate; a
			// non-CA certificate (e.g. a workload certificate) signing
			// something is not a link in an issuer chain.
			if !canSignCerts(c) {
				continue
			}
			if VerifyCertSignedBy(current, c) {
				next = c
				break
			}
		}
		if next == nil {
			return fmt.Errorf("%s (SKI %s) is neither signed by another given certificate nor by a certificate in the trust bundle", current.Subject.CommonName, GetSubjectKeyID(current))
		}
		current = next
	}

	return fmt.Errorf("certificate loop detected while walking up from %s (SKI %s)", cert.Subject.CommonName, GetSubjectKeyID(cert))
}

func GetSubjectKeyID(cert *x509.Certificate) string {
	if cert.SubjectKeyId != nil {
		return hex.EncodeToString(cert.SubjectKeyId)
	}
	// Calculate SKI using SHA-1 hash of the public key
	hash := sha1.Sum(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(hash[:])
}

func GetAuthorityKeyID(cert *x509.Certificate) string {
	if cert.AuthorityKeyId != nil {
		return hex.EncodeToString(cert.AuthorityKeyId)
	}
	return "none"
}

func GetTrustBundleCerts(ctx context.Context, k8sAPI *k8s.KubernetesAPI, namespace, configMapName string) ([]*x509.Certificate, error) {
	configMap, err := k8sAPI.CoreV1().ConfigMaps(namespace).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get ConfigMap %s/%s: %w", namespace, configMapName, err)
	}

	trustBundle := configMap.Data[TrustRootsDataKey]
	if trustBundle == "" {
		return nil, fmt.Errorf("trust bundle data key %s is empty in ConfigMap", TrustRootsDataKey)
	}

	certs, err := pkgtls.DecodePEMCertificates(trustBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trust bundle: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in trust bundle")
	}

	return certs, nil
}

func GetCertFromSecret(ctx context.Context, k8sAPI *k8s.KubernetesAPI, namespace string, secretName string) (*x509.Certificate, error) {
	certs, err := GetCertsFromSecret(ctx, k8sAPI, namespace, secretName)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// GetCertsFromSecret reads all certificates from a Secret's certificate
// data. For a classic identity issuer this is a single certificate; for a
// federated identity issuer it is a bundle containing the issuer
// certificate followed by one or more intermediate CA certificates, ordered
// leaf to root.
func GetCertsFromSecret(ctx context.Context, k8sAPI *k8s.KubernetesAPI, namespace string, secretName string) ([]*x509.Certificate, error) {
	secret, err := k8sAPI.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Secret %s/%s: %w", namespace, secretName, err)
	}

	// Try linkerd.io/tls scheme first
	certData, ok := secret.Data[k8s.IdentityIssuerCrtName]
	if !ok {
		// Try kubernetes.io/tls scheme
		certData, ok = secret.Data[corev1.TLSCertKey]
		if !ok {
			return nil, fmt.Errorf("neither %s nor %s key found in Secret", k8s.IdentityIssuerCrtName, corev1.TLSCertKey)
		}
	}

	certs, err := pkgtls.DecodePEMCertificates(string(certData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity issuer certificate: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in identity issuer secret")
	}

	return certs, nil
}

// FindIssuerChain takes the certificates from the identity issuer Secret
// and a workload certificate, and returns the chain of issuer certificates
// that links the issuer that signs the workload to the topmost certificate
// reachable within the Secret's certificates.
//
// The returned chain is ordered from the workload-signing issuer (chain[0])
// to the topmost certificate (chain[len(chain)-1]). The order of the input
// certificates doesn't matter, so both leaf-first and root-first bundles
// work. For a classic (non-federated) issuer Secret containing a single
// certificate, the chain has exactly one element.
func FindIssuerChain(workloadCert *x509.Certificate, issuerCerts []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(issuerCerts) == 0 {
		return nil, fmt.Errorf("no certificates in identity issuer secret")
	}

	// Find the certificate that signs the workload: the identity issuer.
	var chain []*x509.Certificate
	for _, cert := range issuerCerts {
		if VerifyCertSignedBy(workloadCert, cert) {
			chain = []*x509.Certificate{cert}
			break
		}
	}

	if chain == nil {
		return nil, fmt.Errorf("no certificate in the identity issuer Secret signs the workload certificate (SKI: %s)", GetSubjectKeyID(workloadCert))
	}

	// Walk upward from the issuer through the Secret's certificates until
	// we reach a self-signed certificate or run out of issuers. Only
	// certificates that may act as CAs (see canSignCerts) are followed.
	for len(chain) < len(issuerCerts) {
		current := chain[len(chain)-1]

		// A self-signed certificate is the top of the chain.
		if current.CheckSignatureFrom(current) == nil {
			break
		}

		found := false
		for _, cert := range issuerCerts {
			if cert.Equal(current) {
				continue
			}
			if !canSignCerts(cert) {
				continue
			}
			if VerifyCertSignedBy(current, cert) {
				chain = append(chain, cert)
				found = true
				break
			}
		}

		if !found {
			// No certificate in the Secret signs the current one, so the
			// chain ends here. The trust bundle is responsible for the rest.
			break
		}
	}

	return chain, nil
}

// VerifyChainAnchored verifies that a leaf-to-root certificate chain is
// internally consistent (each certificate is signed by the one after it)
// and that its topmost certificate is signed by a certificate in the trust
// bundle. It returns the trust bundle certificate that anchors the chain.
//
// Beyond the signature checks, the chain is verified exactly as the
// identity controller verifies the issuer Secret at startup: the chain
// above the leaf is used as intermediates and the trust bundle as roots.
// This enforces the X.509 constraints that signature checks alone miss --
// intermediates must be CA certificates with the certificate-signing key
// usage, certificates must be within their validity period, and path
// length constraints must hold -- so that chains the control plane would
// reject fail here, at input time, instead of at rollout.
//
// For a classic identity issuer the chain is a single certificate signed
// directly by a trust anchor; for a federated issuer it is the issuer
// certificate followed by one or more intermediate CA certificates, with
// the trust bundle anchoring the topmost intermediate.
func VerifyChainAnchored(chain, trustBundle []*x509.Certificate) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	// Each certificate must be signed by the one after it.
	for i := 0; i < len(chain)-1; i++ {
		if !VerifyCertSignedBy(chain[i], chain[i+1]) {
			return nil, fmt.Errorf("certificate %s is not signed by %s", chain[i].Subject.CommonName, chain[i+1].Subject.CommonName)
		}
	}

	leaf := chain[0]

	// Run the control plane's verification: the chain above the leaf as
	// intermediates, the trust bundle as roots.
	roots := x509.NewCertPool()
	for _, trustCert := range trustBundle {
		roots.AddCert(trustCert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("certificate chain for %s is not valid against the trust bundle (the identity controller would reject it): %w", leaf.Subject.CommonName, err)
	}

	// The leaf is installed as the identity issuer; the control plane
	// requires the issuer to be a CA.
	if !leaf.BasicConstraintsValid || !leaf.IsCA {
		return nil, fmt.Errorf("certificate %s is not a CA, but the identity issuer must be a CA", leaf.Subject.CommonName)
	}

	// Identify the trust bundle certificate that anchors the chain, for
	// reporting.
	top := chain[len(chain)-1]
	for _, trustCert := range trustBundle {
		if top.Equal(trustCert) || VerifyCertSignedBy(top, trustCert) {
			return trustCert, nil
		}
	}

	return nil, fmt.Errorf("no certificate in the trust bundle signs %s (the top of the certificate chain)", top.Subject.CommonName)
}

func VerifyCertSignedBy(cert, issuer *x509.Certificate) bool {
	// Check if the Authority Key ID matches the issuer's Subject Key ID
	if cert.AuthorityKeyId != nil && issuer.SubjectKeyId != nil {
		issuerSKI := GetSubjectKeyID(issuer)
		certAKI := hex.EncodeToString(cert.AuthorityKeyId)
		if issuerSKI != certAKI {
			return false
		}
	}

	// Verify the signature
	return cert.CheckSignatureFrom(issuer) == nil
}
