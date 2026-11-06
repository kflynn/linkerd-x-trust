package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ourx509 "github.com/linkerd/linkerd-trust/v2/pkg/x509"
	pkgtls "github.com/linkerd/linkerd2/pkg/tls"
)

// keyToPEM encodes a CertAndKey's private key as PEM.
func keyToPEM(ck *ourx509.CertAndKey) (string, error) {
	switch key := ck.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", err
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})), nil
	case *rsa.PrivateKey:
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil
	default:
		return "", fmt.Errorf("unsupported private key type %T", ck.PrivateKey)
	}
}

// buildFederatedChainCK builds a federated trust hierarchy:
// root anchor (pathlen 2) -> cluster anchor (pathlen 1) -> identity issuer
// (pathlen 0) -> workload leaf. Returns the workload certificate and the
// CA certificates with their keys.
func buildFederatedChainCK(t *testing.T) (workload *x509.Certificate, issuerCK, clusterCK, rootCK *ourx509.CertAndKey) {
	t.Helper()

	validity := 24 * time.Hour

	var err error
	rootCK, err = ourx509.GenerateAnchor("root.linkerd.cluster.local", validity, 2)
	if err != nil {
		t.Fatalf("failed to generate root anchor: %v", err)
	}

	clusterCK, err = ourx509.GenerateIssuer(rootCK, "cluster-anchor.linkerd.cluster.local", validity, 1)
	if err != nil {
		t.Fatalf("failed to generate cluster anchor: %v", err)
	}

	issuerCK, err = ourx509.GenerateIssuer(clusterCK, "identity.linkerd.cluster.local", validity, 0)
	if err != nil {
		t.Fatalf("failed to generate identity issuer: %v", err)
	}

	workload, err = signLeaf(issuerCK, "web.default.serviceaccount.identity.linkerd.cluster.local")
	if err != nil {
		t.Fatalf("failed to generate workload certificate: %v", err)
	}

	return workload, issuerCK, clusterCK, rootCK
}

// buildFederatedChain is buildFederatedChainCK without the private keys.
func buildFederatedChain(t *testing.T) (workload, issuer, clusterAnchor, root *x509.Certificate) {
	t.Helper()

	workload, issuerCK, clusterCK, rootCK := buildFederatedChainCK(t)
	return workload, issuerCK.Certificate, clusterCK.Certificate, rootCK.Certificate
}

// signLeaf creates a workload-style leaf certificate signed by the given CA.
func signLeaf(ca *ourx509.CertAndKey, identity string) (*x509.Certificate, error) {
	// Generate a throwaway keypair for the leaf; only its public key is used.
	kp, err := ourx509.GenerateAnchor("leaf-key", time.Hour, 0)
	if err != nil {
		return nil, err
	}

	signer, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key is not a crypto.Signer (%T)", ca.PrivateKey)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse("spiffe://cluster.local/" + identity)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: identity,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, kp.Certificate.PublicKey, signer)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(der)
}

func TestFindIssuerChainFederatedLeafFirst(t *testing.T) {
	workload, issuer, clusterAnchor, _ := buildFederatedChain(t)

	// Leaf-first bundle, as written by federate.sh.
	bundle := []*x509.Certificate{issuer, clusterAnchor}

	chain, err := FindIssuerChain(workload, bundle)
	if err != nil {
		t.Fatalf("FindIssuerChain failed: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("expected chain of length 2, got %d", len(chain))
	}
	if !chain[0].Equal(issuer) {
		t.Errorf("chain[0] should be the identity issuer, got %s", chain[0].Subject.CommonName)
	}
	if !chain[1].Equal(clusterAnchor) {
		t.Errorf("chain[1] should be the cluster anchor, got %s", chain[1].Subject.CommonName)
	}
}

func TestFindIssuerChainFederatedRootFirst(t *testing.T) {
	workload, issuer, clusterAnchor, _ := buildFederatedChain(t)

	// Root-first bundle: ordering must not matter.
	bundle := []*x509.Certificate{clusterAnchor, issuer}

	chain, err := FindIssuerChain(workload, bundle)
	if err != nil {
		t.Fatalf("FindIssuerChain failed: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("expected chain of length 2, got %d", len(chain))
	}
	if !chain[0].Equal(issuer) {
		t.Errorf("chain[0] should be the identity issuer, got %s", chain[0].Subject.CommonName)
	}
	if !chain[1].Equal(clusterAnchor) {
		t.Errorf("chain[1] should be the cluster anchor, got %s", chain[1].Subject.CommonName)
	}
}

func TestFindIssuerChainFederatedWithRootInBundle(t *testing.T) {
	workload, issuer, clusterAnchor, root := buildFederatedChain(t)

	// Bundle that includes the root anchor as well: the chain should walk
	// all the way to the self-signed root.
	bundle := []*x509.Certificate{issuer, clusterAnchor, root}

	chain, err := FindIssuerChain(workload, bundle)
	if err != nil {
		t.Fatalf("FindIssuerChain failed: %v", err)
	}

	if len(chain) != 3 {
		t.Fatalf("expected chain of length 3, got %d", len(chain))
	}
	if !chain[2].Equal(root) {
		t.Errorf("chain[2] should be the root anchor, got %s", chain[2].Subject.CommonName)
	}
}

func TestFindIssuerChainClassic(t *testing.T) {
	workload, issuer, _, _ := buildFederatedChain(t)

	// Classic single-certificate issuer Secret.
	chain, err := FindIssuerChain(workload, []*x509.Certificate{issuer})
	if err != nil {
		t.Fatalf("FindIssuerChain failed: %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("expected chain of length 1, got %d", len(chain))
	}
	if !chain[0].Equal(issuer) {
		t.Errorf("chain[0] should be the identity issuer, got %s", chain[0].Subject.CommonName)
	}
}

func TestFindIssuerChainNoSigner(t *testing.T) {
	workload, _, clusterAnchor, root := buildFederatedChain(t)

	// Neither the cluster anchor nor the root signs the workload directly.
	_, err := FindIssuerChain(workload, []*x509.Certificate{clusterAnchor, root})
	if err == nil {
		t.Fatal("expected an error when no certificate in the Secret signs the workload")
	}
}

func TestFindIssuerChainEmpty(t *testing.T) {
	workload, _, _, _ := buildFederatedChain(t)

	_, err := FindIssuerChain(workload, nil)
	if err == nil {
		t.Fatal("expected an error for an empty certificate list")
	}
}

func TestVerifyChainAnchoredClassic(t *testing.T) {
	// Classic case: a single certificate signed directly by the trust
	// anchor. (The cluster anchor plays that role in the test hierarchy,
	// since it's one hop below the root.)
	_, _, clusterAnchor, root := buildFederatedChain(t)

	anchor, err := VerifyChainAnchored([]*x509.Certificate{clusterAnchor}, []*x509.Certificate{root})
	if err != nil {
		t.Fatalf("VerifyChainAnchored failed: %v", err)
	}
	if !anchor.Equal(root) {
		t.Errorf("expected the root anchor, got %s", anchor.Subject.CommonName)
	}
}

func TestVerifyChainAnchoredFederated(t *testing.T) {
	_, issuer, clusterAnchor, root := buildFederatedChain(t)

	// Leaf-first federated chain, anchored by the shared root.
	anchor, err := VerifyChainAnchored([]*x509.Certificate{issuer, clusterAnchor}, []*x509.Certificate{root})
	if err != nil {
		t.Fatalf("VerifyChainAnchored failed: %v", err)
	}
	if !anchor.Equal(root) {
		t.Errorf("expected the root anchor, got %s", anchor.Subject.CommonName)
	}
}

func TestVerifyChainAnchoredFederatedWithRoot(t *testing.T) {
	_, issuer, clusterAnchor, root := buildFederatedChain(t)

	// Chain that includes the root itself: the root is self-signed, so it
	// anchors its own chain.
	anchor, err := VerifyChainAnchored([]*x509.Certificate{issuer, clusterAnchor, root}, []*x509.Certificate{root})
	if err != nil {
		t.Fatalf("VerifyChainAnchored failed: %v", err)
	}
	if !anchor.Equal(root) {
		t.Errorf("expected the root anchor, got %s", anchor.Subject.CommonName)
	}
}

func TestVerifyChainAnchoredBrokenChain(t *testing.T) {
	_, issuer, _, root := buildFederatedChain(t)

	// The issuer is signed by the cluster anchor, not by the root, so this
	// chain is internally inconsistent.
	_, err := VerifyChainAnchored([]*x509.Certificate{issuer, root}, []*x509.Certificate{root})
	if err == nil {
		t.Fatal("expected an error for a broken chain")
	}
}

func TestVerifyChainAnchoredNotAnchored(t *testing.T) {
	_, issuer, clusterAnchor, _ := buildFederatedChain(t)

	// A different root that has nothing to do with this chain.
	otherRootCK, err := ourx509.GenerateAnchor("other.root.linkerd.cluster.local", 24*time.Hour, 2)
	if err != nil {
		t.Fatalf("failed to generate other root: %v", err)
	}

	_, err = VerifyChainAnchored([]*x509.Certificate{issuer, clusterAnchor}, []*x509.Certificate{otherRootCK.Certificate})
	if err == nil {
		t.Fatal("expected an error when the trust bundle doesn't anchor the chain")
	}
}

func TestLoadIssuerChainFromPathsBundleFile(t *testing.T) {
	// A federated issuer "cert file" is a leaf-first bundle; loading it
	// with the key must succeed with the leaf as the chain's first
	// certificate.
	_, issuerCK, clusterCK, _ := buildFederatedChainCK(t)
	issuer, clusterAnchor := issuerCK.Certificate, clusterCK.Certificate

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "issuer-bundle.crt")
	keyPath := filepath.Join(dir, "issuer.key")

	bundlePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clusterAnchor.Raw}))
	if err := os.WriteFile(bundlePath, []byte(bundlePEM), 0644); err != nil {
		t.Fatalf("failed to write bundle: %v", err)
	}

	keyPEM, err := keyToPEM(issuerCK)
	if err != nil {
		t.Fatalf("failed to encode issuer key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	chain, certData, _, _, err := LoadIssuerChainFromPaths([]string{bundlePath}, keyPath)
	if err != nil {
		t.Fatalf("LoadIssuerChainFromPaths failed on a bundle file: %v", err)
	}
	if len(chain) != 2 || !chain[0].Equal(issuer) || !chain[1].Equal(clusterAnchor) {
		t.Errorf("chain should be issuer then cluster anchor, got %d certificate(s)", len(chain))
	}

	// The written chain must round-trip leaf-first.
	decoded, err := pkgtls.DecodePEMCertificates(certData)
	if err != nil {
		t.Fatalf("failed to decode chain PEM: %v", err)
	}
	if len(decoded) != 2 || !decoded[0].Equal(issuer) || !decoded[1].Equal(clusterAnchor) {
		t.Errorf("chain PEM should be issuer then cluster anchor, got %d certificate(s)", len(decoded))
	}
}

// writeCert writes a certificate to a PEM file.
func writeCert(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
}

func TestLoadIssuerChainFromPathsMultiFile(t *testing.T) {
	// Multiple .crt files plus the leaf's key: the leaf is found by key
	// match, and the chain is assembled from the files regardless of the
	// order they were given in.
	_, issuerCK, clusterCK, _ := buildFederatedChainCK(t)
	issuer, clusterAnchor := issuerCK.Certificate, clusterCK.Certificate

	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "issuer.crt")
	clusterPath := filepath.Join(dir, "cluster-anchor.crt")
	keyPath := filepath.Join(dir, "issuer.key")

	writeCert(t, issuerPath, issuer)
	writeCert(t, clusterPath, clusterAnchor)

	keyPEM, err := keyToPEM(issuerCK)
	if err != nil {
		t.Fatalf("failed to encode issuer key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Scrambled file order: the leaf is not the first file given.
	chain, certData, keyData, _, err := LoadIssuerChainFromPaths([]string{clusterPath, issuerPath}, keyPath)
	if err != nil {
		t.Fatalf("LoadIssuerChainFromPaths failed: %v", err)
	}

	if len(chain) != 2 || !chain[0].Equal(issuer) || !chain[1].Equal(clusterAnchor) {
		t.Errorf("chain should be issuer then cluster anchor, got %d certificate(s)", len(chain))
	}
	if keyData != keyPEM {
		t.Error("key data should be returned unchanged")
	}

	// The written chain must be leaf-first regardless of input order.
	decoded, err := pkgtls.DecodePEMCertificates(certData)
	if err != nil {
		t.Fatalf("failed to decode chain PEM: %v", err)
	}
	if len(decoded) != 2 || !decoded[0].Equal(issuer) || !decoded[1].Equal(clusterAnchor) {
		t.Errorf("chain PEM should be issuer then cluster anchor, got %d certificate(s)", len(decoded))
	}
}

func TestLoadIssuerChainFromPathsSingleFile(t *testing.T) {
	// Backward compatibility: one .crt file plus the key.
	_, issuerCK, _, _ := buildFederatedChainCK(t)

	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "issuer.crt")
	keyPath := filepath.Join(dir, "issuer.key")

	writeCert(t, issuerPath, issuerCK.Certificate)

	keyPEM, err := keyToPEM(issuerCK)
	if err != nil {
		t.Fatalf("failed to encode issuer key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	chain, _, _, _, err := LoadIssuerChainFromPaths([]string{issuerPath}, keyPath)
	if err != nil {
		t.Fatalf("LoadIssuerChainFromPaths failed: %v", err)
	}
	if len(chain) != 1 || !chain[0].Equal(issuerCK.Certificate) {
		t.Errorf("chain should hold just the issuer, got %d certificate(s)", len(chain))
	}
}

func TestLoadIssuerChainFromPathsKeyMatchesNothing(t *testing.T) {
	// A key that matches none of the certificates.
	_, issuerCK, clusterCK, _ := buildFederatedChainCK(t)

	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "issuer.crt")
	clusterPath := filepath.Join(dir, "cluster-anchor.crt")
	keyPath := filepath.Join(dir, "unrelated.key")

	writeCert(t, issuerPath, issuerCK.Certificate)
	writeCert(t, clusterPath, clusterCK.Certificate)

	strayCK, err := ourx509.GenerateAnchor("stray", time.Hour, 0)
	if err != nil {
		t.Fatalf("failed to generate stray key: %v", err)
	}
	strayKeyPEM, err := keyToPEM(strayCK)
	if err != nil {
		t.Fatalf("failed to encode stray key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(strayKeyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	_, _, _, _, err = LoadIssuerChainFromPaths([]string{issuerPath, clusterPath}, keyPath)
	if err == nil {
		t.Fatal("expected an error when the key matches no certificate")
	}
	if !strings.Contains(err.Error(), "does not match any") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadIssuerChainFromPathsKeySelectsIntermediate(t *testing.T) {
	// The key goes with the cluster anchor rather than the identity issuer:
	// the key selects which certificate gets installed, so this is legal.
	// The issuer certificate is still accepted as rotation material, as
	// long as it chains to the trust bundle (it does: issuer <- anchor <-
	// root).
	_, issuerCK, clusterCK, rootCK := buildFederatedChainCK(t)

	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "issuer.crt")
	clusterPath := filepath.Join(dir, "cluster-anchor.crt")
	keyPath := filepath.Join(dir, "cluster-anchor.key")

	writeCert(t, issuerPath, issuerCK.Certificate)
	writeCert(t, clusterPath, clusterCK.Certificate)

	keyPEM, err := keyToPEM(clusterCK)
	if err != nil {
		t.Fatalf("failed to encode cluster anchor key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	chain, _, _, allCerts, err := LoadIssuerChainFromPaths([]string{issuerPath, clusterPath}, keyPath)
	if err != nil {
		t.Fatalf("LoadIssuerChainFromPaths failed: %v", err)
	}
	if len(chain) != 1 || !chain[0].Equal(clusterCK.Certificate) {
		t.Errorf("the key should select the cluster anchor, got a chain of %d certificate(s)", len(chain))
	}

	// Both certs must still be connected to the trust bundle.
	if err := ValidateRotationCerts(allCerts, []*x509.Certificate{rootCK.Certificate}); err != nil {
		t.Errorf("ValidateRotationCerts failed: %v", err)
	}
}

func TestLoadIssuerChainFromPathsUnrelatedCert(t *testing.T) {
	// A certificate signed by nothing given and by nothing in the trust
	// bundle. Loading is fine; the rotation invariant is what rejects it.
	_, issuerCK, clusterCK, rootCK := buildFederatedChainCK(t)

	dir := t.TempDir()
	issuerPath := filepath.Join(dir, "issuer.crt")
	clusterPath := filepath.Join(dir, "cluster-anchor.crt")
	strayPath := filepath.Join(dir, "stray.crt")
	keyPath := filepath.Join(dir, "issuer.key")

	writeCert(t, issuerPath, issuerCK.Certificate)
	writeCert(t, clusterPath, clusterCK.Certificate)

	strayCK, err := ourx509.GenerateAnchor("stray.linkerd.cluster.local", time.Hour, 0)
	if err != nil {
		t.Fatalf("failed to generate stray certificate: %v", err)
	}
	writeCert(t, strayPath, strayCK.Certificate)

	keyPEM, err := keyToPEM(issuerCK)
	if err != nil {
		t.Fatalf("failed to encode issuer key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	_, _, _, allCerts, err := LoadIssuerChainFromPaths([]string{issuerPath, clusterPath, strayPath}, keyPath)
	if err != nil {
		t.Fatalf("LoadIssuerChainFromPaths failed: %v", err)
	}

	err = ValidateRotationCerts(allCerts, []*x509.Certificate{rootCK.Certificate})
	if err == nil {
		t.Fatal("expected ValidateRotationCerts to reject the stray certificate")
	}
	if !strings.Contains(err.Error(), "stray.linkerd.cluster.local") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadIssuerChainFromPathsKeyNotLast(t *testing.T) {
	// A key file given as one of the certificate files.
	_, issuerCK, _, _ := buildFederatedChainCK(t)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "issuer.key")
	keyPEM, err := keyToPEM(issuerCK)
	if err != nil {
		t.Fatalf("failed to encode issuer key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	_, _, _, _, err = LoadIssuerChainFromPaths([]string{keyPath}, filepath.Join(dir, "issuer.crt"))
	if err == nil {
		t.Fatal("expected an error when a .key file is given as a certificate file")
	}
	if !strings.Contains(err.Error(), "only one key file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadIssuerChainFromPathsRotationSameSubject(t *testing.T) {
	// Anchor rotation: the replacement intermediate carries the same subject
	// DN as the one it replaces, and both generations' certificates are
	// present (until the control plane can be restarted, all of them must
	// be). The key picks the next-generation issuer; the chain must build
	// through the anchor that actually signs it, not the same-named stale
	// one, and every certificate must still reach the trust bundle.
	_, _, clusterCK, rootCK := buildFederatedChainCK(t)

	// A second intermediate with the identical subject DN, signed by the
	// same root, that does NOT sign the next-generation issuer.
	rotatedCK, err := ourx509.GenerateIssuer(rootCK, clusterCK.Certificate.Subject.CommonName, 24*time.Hour, 1)
	if err != nil {
		t.Fatalf("failed to generate rotated cluster anchor: %v", err)
	}

	// The next-generation issuer, signed by the rotated anchor.
	rotatedIssuerCK, err := ourx509.GenerateIssuer(rotatedCK, "identity.linkerd.cluster.local", 24*time.Hour, 0)
	if err != nil {
		t.Fatalf("failed to generate rotated issuer: %v", err)
	}

	dir := t.TempDir()
	oldPath := filepath.Join(dir, "cluster-anchor-old.crt")
	newPath := filepath.Join(dir, "cluster-anchor.crt")
	issuerPath := filepath.Join(dir, "issuer.crt")
	keyPath := filepath.Join(dir, "issuer.key")

	writeCert(t, oldPath, clusterCK.Certificate)
	writeCert(t, newPath, rotatedCK.Certificate)
	writeCert(t, issuerPath, rotatedIssuerCK.Certificate)

	keyPEM, err := keyToPEM(rotatedIssuerCK)
	if err != nil {
		t.Fatalf("failed to encode issuer key: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	// Stale anchor listed first, so position can't save us: signature
	// verification must pick the anchor that actually signs the issuer.
	chain, _, _, allCerts, err := LoadIssuerChainFromPaths([]string{oldPath, newPath, issuerPath}, keyPath)
	if err != nil {
		t.Fatalf("LoadIssuerChainFromPaths failed: %v", err)
	}
	if len(chain) != 2 || !chain[0].Equal(rotatedIssuerCK.Certificate) || !chain[1].Equal(rotatedCK.Certificate) {
		t.Fatalf("chain must be the rotated issuer under the anchor that signs it, got %d certificate(s)", len(chain))
	}
	if chain[1].Equal(clusterCK.Certificate) {
		t.Error("chain must not contain the stale same-subject anchor")
	}

	// All four certs (both generations) must reach the trust bundle.
	if err := ValidateRotationCerts(allCerts, []*x509.Certificate{rootCK.Certificate}); err != nil {
		t.Errorf("ValidateRotationCerts failed: %v", err)
	}
}

func TestValidateRotationCertsOrphan(t *testing.T) {
	// A certificate signed by a root that is not in the trust bundle: it
	// has a perfectly good issuer, just not one we trust or were given.
	_, _, _, rootCK := buildFederatedChainCK(t)

	otherRootCK, err := ourx509.GenerateAnchor("other.root.linkerd.cluster.local", 24*time.Hour, 2)
	if err != nil {
		t.Fatalf("failed to generate other root: %v", err)
	}
	orphanCK, err := ourx509.GenerateIssuer(otherRootCK, "orphan.linkerd.cluster.local", 24*time.Hour, 1)
	if err != nil {
		t.Fatalf("failed to generate orphan: %v", err)
	}

	err = ValidateRotationCerts([]*x509.Certificate{orphanCK.Certificate}, []*x509.Certificate{rootCK.Certificate})
	if err == nil {
		t.Fatal("expected an error for a certificate whose issuer is outside the given certs and the trust bundle")
	}
	if !strings.Contains(err.Error(), "orphan.linkerd.cluster.local") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAssembleIssuerChainWithRoot(t *testing.T) {
	// The chain walks all the way to a self-signed root when it's included.
	_, issuer, clusterAnchor, root := buildFederatedChain(t)

	chain := AssembleIssuerChain(issuer, []*x509.Certificate{root, issuer, clusterAnchor})
	if len(chain) != 3 {
		t.Fatalf("expected chain of length 3, got %d", len(chain))
	}
	if !chain[0].Equal(issuer) || !chain[1].Equal(clusterAnchor) || !chain[2].Equal(root) {
		t.Errorf("chain should be issuer -> cluster anchor -> root, got %s -> %s -> %s",
			chain[0].Subject.CommonName, chain[1].Subject.CommonName, chain[2].Subject.CommonName)
	}
}

// buildAttackChain builds the material a mesh participant could assemble
// from nothing but an ordinary workload certificate: a new keypair and
// certificate rogue, signed by the workload certificate's key. If chain
// assembly accepted the workload certificate as an intermediate, the rogue
// certificate could be installed as the identity issuer.
func buildAttackChain(t *testing.T) (rogue, workload, issuer, clusterAnchor *x509.Certificate) {
	t.Helper()

	workload, issuerCK, clusterCK, _ := buildFederatedChainCK(t)
	issuer, clusterAnchor = issuerCK.Certificate, clusterCK.Certificate

	// A non-CA certificate with its private key, like a workload
	// certificate every mesh pod holds.
	workloadKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate workload key: %v", err)
	}
	workload, err = signCert(issuerCK, "workload.default.serviceaccount.identity.linkerd.cluster.local", &workloadKey.PublicKey, false)
	if err != nil {
		t.Fatalf("failed to generate workload certificate: %v", err)
	}

	// The rogue "issuer" certificate, signed by the workload certificate.
	rogueKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate rogue key: %v", err)
	}
	rogue, err = signCert(&ourx509.CertAndKey{Certificate: workload, PrivateKey: workloadKey}, "rogue.linkerd.cluster.local", &rogueKey.PublicKey, true)
	if err != nil {
		t.Fatalf("failed to generate rogue certificate: %v", err)
	}

	return rogue, workload, issuer, clusterAnchor
}

// signCert creates a certificate for pub signed by ca, which is a CA when
// isCA is set and a plain end-entity certificate otherwise.
func signCert(ca *ourx509.CertAndKey, cn string, pub crypto.PublicKey, isCA bool) (*x509.Certificate, error) {
	signer, ok := ca.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("CA private key is not a crypto.Signer (%T)", ca.PrivateKey)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if isCA {
		template.KeyUsage = x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.IsCA = true
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func TestAssembleIssuerChainRejectsNonCAIssuer(t *testing.T) {
	// The workload certificate signs the rogue certificate, but it is not a
	// CA, so the chain must not be routed through it: the rogue certificate
	// ends up alone, unanchored.
	rogue, workload, issuer, clusterAnchor := buildAttackChain(t)

	chain := AssembleIssuerChain(rogue, []*x509.Certificate{rogue, workload, issuer, clusterAnchor})
	if len(chain) != 1 || !chain[0].Equal(rogue) {
		t.Fatalf("chain must not include the non-CA workload certificate, got %d certificate(s)", len(chain))
	}
}

func TestVerifyChainAnchoredNonCAIntermediate(t *testing.T) {
	// Even if such a chain is handed to VerifyChainAnchored directly, the
	// control-plane-style verification must reject it: the workload
	// certificate is not a CA.
	rogue, workload, issuer, clusterAnchor := buildAttackChain(t)

	_, err := VerifyChainAnchored([]*x509.Certificate{rogue, workload, issuer}, []*x509.Certificate{clusterAnchor})
	if err == nil {
		t.Fatal("expected an error for a chain routed through a non-CA certificate")
	}
}

func TestVerifyChainAnchoredNonCALeaf(t *testing.T) {
	// Installing a workload certificate (a non-CA) as the identity issuer
	// must be rejected, as the control plane rejects it.
	_, workload, issuer, clusterAnchor := buildAttackChain(t)

	_, err := VerifyChainAnchored([]*x509.Certificate{workload, issuer}, []*x509.Certificate{clusterAnchor})
	if err == nil {
		t.Fatal("expected an error for a non-CA leaf certificate")
	}
}

func TestValidateRotationCertsNonCAVouching(t *testing.T) {
	// A non-CA certificate may not vouch for other certificates as rotation
	// material: the rogue certificate, signed only by the workload
	// certificate, must not reach the trust bundle.
	rogue, workload, issuer, clusterAnchor := buildAttackChain(t)

	err := ValidateRotationCerts([]*x509.Certificate{rogue, workload, issuer}, []*x509.Certificate{clusterAnchor})
	if err == nil {
		t.Fatal("expected an error when a certificate is vouched for only by a non-CA certificate")
	}
	if !strings.Contains(err.Error(), "rogue.linkerd.cluster.local") {
		t.Errorf("unexpected error: %v", err)
	}
}
