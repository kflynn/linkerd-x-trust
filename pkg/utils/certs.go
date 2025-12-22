package utils

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"

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

	return certs[0], nil
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
