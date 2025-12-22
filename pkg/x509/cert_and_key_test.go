package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Test helpers

func generateTestCertAndKey(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageCertSign,
		IsCA:      true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, priv
}

func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	return key
}

func ecKeyToPEM(key *ecdsa.PrivateKey) string {
	bytes, _ := x509.MarshalECPrivateKey(key)
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block))
}

func rsaKeyToPEM(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

func pkcs8KeyToPEM(key interface{}) string {
	bytes, _ := x509.MarshalPKCS8PrivateKey(key)
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(block))
}

// Tests

func TestNewCertAndKey(t *testing.T) {
	cert1, key1 := generateTestCertAndKey(t)
	cert2, _ := generateTestCertAndKey(t)

	ck := NewCertAndKey(cert2, key1)

	if ck.Certificate != cert2 {
		t.Errorf("certificate not set correctly")
	}
	if ck.PrivateKey != key1 {
		t.Errorf("private key not set correctly")
	}
	if !ck.HasKey() {
		t.Errorf("HasKey() returned false when key is present")
	}

	// Verify we also set cert1 properly
	_ = cert1
}

func TestNewCertAndKeyWithoutKey(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)

	ck := NewCertAndKey(cert, nil)

	if ck.Certificate != cert {
		t.Errorf("certificate not set correctly")
	}
	if ck.PrivateKey != nil {
		t.Errorf("private key should be nil")
	}
	if ck.HasKey() {
		t.Errorf("HasKey() returned true when key is nil")
	}
}

func TestLoadCertFromPEM(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	pemData := certToPEM(cert)

	ck := &CertAndKey{}
	err := ck.LoadCertFromPEM(pemData)

	if err != nil {
		t.Fatalf("LoadCertFromPEM failed: %v", err)
	}

	if ck.Certificate == nil {
		t.Fatal("certificate not loaded")
	}

	if ck.Certificate.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("expected CN %s, got %s", cert.Subject.CommonName, ck.Certificate.Subject.CommonName)
	}
}

func TestLoadCertFromPEMInvalid(t *testing.T) {
	tests := []struct {
		name    string
		pemData string
	}{
		{
			name:    "empty",
			pemData: "",
		},
		{
			name:    "invalid_pem",
			pemData: "not a pem file",
		},
		{
			name: "wrong_block_type",
			pemData: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890
-----END RSA PRIVATE KEY-----`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ck := &CertAndKey{}
			err := ck.LoadCertFromPEM(tt.pemData)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestLoadKeyFromPEMECDSA(t *testing.T) {
	_, key := generateTestCertAndKey(t)
	pemData := ecKeyToPEM(key)

	ck := &CertAndKey{}
	err := ck.LoadKeyFromPEM(pemData)

	if err != nil {
		t.Fatalf("LoadKeyFromPEM failed: %v", err)
	}

	if ck.PrivateKey == nil {
		t.Fatal("private key not loaded")
	}

	_, ok := ck.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", ck.PrivateKey)
	}
}

func TestLoadKeyFromPEMRSA(t *testing.T) {
	key := generateRSAKey(t)
	pemData := rsaKeyToPEM(key)

	ck := &CertAndKey{}
	err := ck.LoadKeyFromPEM(pemData)

	if err != nil {
		t.Fatalf("LoadKeyFromPEM failed: %v", err)
	}

	if ck.PrivateKey == nil {
		t.Fatal("private key not loaded")
	}

	_, ok := ck.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("expected *rsa.PrivateKey, got %T", ck.PrivateKey)
	}
}

func TestLoadKeyFromPEMPKCS8(t *testing.T) {
	_, key := generateTestCertAndKey(t)
	pemData := pkcs8KeyToPEM(key)

	ck := &CertAndKey{}
	err := ck.LoadKeyFromPEM(pemData)

	if err != nil {
		t.Fatalf("LoadKeyFromPEM failed: %v", err)
	}

	if ck.PrivateKey == nil {
		t.Fatal("private key not loaded")
	}

	_, ok := ck.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Errorf("expected *ecdsa.PrivateKey, got %T", ck.PrivateKey)
	}
}

func TestLoadKeyFromPEMInvalid(t *testing.T) {
	tests := []struct {
		name    string
		pemData string
	}{
		{
			name:    "empty",
			pemData: "",
		},
		{
			name:    "invalid_pem",
			pemData: "not a pem file",
		},
		{
			name: "wrong_block_type",
			pemData: `-----BEGIN CERTIFICATE-----
MIIEpAIBAAKCAQEA1234567890
-----END CERTIFICATE-----`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ck := &CertAndKey{}
			err := ck.LoadKeyFromPEM(tt.pemData)
			if err == nil {
				t.Errorf("expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestNewCertAndKeyFromPEM(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	certPEM := certToPEM(cert)
	keyPEM := ecKeyToPEM(key)

	t.Run("with_key", func(t *testing.T) {
		ck, err := NewCertAndKeyFromPEM(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("NewCertAndKeyFromPEM failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey == nil {
			t.Fatal("private key not loaded")
		}
		if !ck.HasKey() {
			t.Error("HasKey() returned false")
		}
	})

	t.Run("without_key", func(t *testing.T) {
		ck, err := NewCertAndKeyFromPEM(certPEM, "")
		if err != nil {
			t.Fatalf("NewCertAndKeyFromPEM failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey != nil {
			t.Error("private key should be nil")
		}
		if ck.HasKey() {
			t.Error("HasKey() returned true")
		}
	})

	t.Run("invalid_cert", func(t *testing.T) {
		_, err := NewCertAndKeyFromPEM("invalid", "")
		if err == nil {
			t.Error("expected error for invalid certificate")
		}
	})

	t.Run("invalid_key", func(t *testing.T) {
		_, err := NewCertAndKeyFromPEM(certPEM, "invalid")
		if err == nil {
			t.Error("expected error for invalid key")
		}
	})
}

func TestNewCertAndKeyFromFiles(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	certPEM := certToPEM(cert)
	keyPEM := ecKeyToPEM(key)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	os.WriteFile(certPath, []byte(certPEM), 0644)
	os.WriteFile(keyPath, []byte(keyPEM), 0600)

	t.Run("with_key", func(t *testing.T) {
		ck, err := NewCertAndKeyFromFiles(certPath, keyPath)
		if err != nil {
			t.Fatalf("NewCertAndKeyFromFiles failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey == nil {
			t.Fatal("private key not loaded")
		}
	})

	t.Run("without_key", func(t *testing.T) {
		ck, err := NewCertAndKeyFromFiles(certPath, "")
		if err != nil {
			t.Fatalf("NewCertAndKeyFromFiles failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey != nil {
			t.Error("private key should be nil")
		}
	})

	t.Run("missing_cert_file", func(t *testing.T) {
		_, err := NewCertAndKeyFromFiles(filepath.Join(tmpDir, "missing.pem"), "")
		if err == nil {
			t.Error("expected error for missing cert file")
		}
	})

	t.Run("missing_key_file", func(t *testing.T) {
		_, err := NewCertAndKeyFromFiles(certPath, filepath.Join(tmpDir, "missing-key.pem"))
		if err == nil {
			t.Error("expected error for missing key file")
		}
	})
}

func TestLoadFromSecret(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	certPEM := certToPEM(cert)
	keyPEM := ecKeyToPEM(key)

	t.Run("tls_secret", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.crt": []byte(certPEM),
				"tls.key": []byte(keyPEM),
			},
		}

		ck := &CertAndKey{}
		err := ck.LoadFromSecret(secret, "", "")
		if err != nil {
			t.Fatalf("LoadFromSecret failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey == nil {
			t.Fatal("private key not loaded")
		}
	})

	t.Run("custom_keys", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"cert.pem": []byte(certPEM),
				"priv.key": []byte(keyPEM),
			},
		}

		ck := &CertAndKey{}
		err := ck.LoadFromSecret(secret, "cert.pem", "priv.key")
		if err != nil {
			t.Fatalf("LoadFromSecret failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey == nil {
			t.Fatal("private key not loaded")
		}
	})

	t.Run("cert_only", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.crt": []byte(certPEM),
			},
		}

		ck := &CertAndKey{}
		err := ck.LoadFromSecret(secret, "", "")
		if err != nil {
			t.Fatalf("LoadFromSecret failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey != nil {
			t.Error("private key should be nil when not present")
		}
	})

	t.Run("crt_pem_format", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"crt.pem": []byte(certPEM),
				"key.pem": []byte(keyPEM),
			},
		}

		ck := &CertAndKey{}
		err := ck.LoadFromSecret(secret, "", "")
		if err != nil {
			t.Fatalf("LoadFromSecret failed: %v", err)
		}

		if ck.Certificate == nil {
			t.Fatal("certificate not loaded")
		}
		if ck.PrivateKey == nil {
			t.Fatal("private key not loaded")
		}
	})

	t.Run("missing_cert_key", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{},
		}

		ck := &CertAndKey{}
		err := ck.LoadFromSecret(secret, "missing", "")
		if err == nil {
			t.Error("expected error for missing cert key")
		}
	})

	t.Run("missing_specified_key", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"tls.crt": []byte(certPEM),
			},
		}

		ck := &CertAndKey{}
		err := ck.LoadFromSecret(secret, "", "missing-key")
		if err == nil {
			t.Error("expected error when specified key is missing")
		}
	})
}

func TestNewCertAndKeyFromSecret(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	certPEM := certToPEM(cert)
	keyPEM := ecKeyToPEM(key)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"tls.crt": []byte(certPEM),
			"tls.key": []byte(keyPEM),
		},
	}

	ck, err := NewCertAndKeyFromSecret(secret, "", "")
	if err != nil {
		t.Fatalf("NewCertAndKeyFromSecret failed: %v", err)
	}

	if ck.Certificate == nil {
		t.Fatal("certificate not loaded")
	}
	if ck.PrivateKey == nil {
		t.Fatal("private key not loaded")
	}
}

func TestCertPEM(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	expectedPEM := certToPEM(cert)

	ck := NewCertAndKey(cert, nil)
	pemData, err := ck.CertPEM()

	if err != nil {
		t.Fatalf("CertPEM failed: %v", err)
	}

	if pemData != expectedPEM {
		t.Error("PEM output does not match expected")
	}

	// Test with no certificate
	ck2 := &CertAndKey{}
	_, err = ck2.CertPEM()
	if err == nil {
		t.Error("expected error when no certificate is loaded")
	}
}

func TestKeyPEM(t *testing.T) {
	t.Run("ecdsa_key", func(t *testing.T) {
		_, key := generateTestCertAndKey(t)
		expectedPEM := ecKeyToPEM(key)

		ck := NewCertAndKey(nil, key)
		pemData, err := ck.KeyPEM()

		if err != nil {
			t.Fatalf("KeyPEM failed: %v", err)
		}

		if pemData != expectedPEM {
			t.Error("PEM output does not match expected")
		}
	})

	t.Run("rsa_key", func(t *testing.T) {
		key := generateRSAKey(t)
		expectedPEM := rsaKeyToPEM(key)

		ck := NewCertAndKey(nil, key)
		pemData, err := ck.KeyPEM()

		if err != nil {
			t.Fatalf("KeyPEM failed: %v", err)
		}

		if pemData != expectedPEM {
			t.Error("PEM output does not match expected")
		}
	})

	t.Run("no_key", func(t *testing.T) {
		ck := &CertAndKey{}
		_, err := ck.KeyPEM()
		if err == nil {
			t.Error("expected error when no key is loaded")
		}
	})
}

func TestWriteToFiles(t *testing.T) {
	cert, key := generateTestCertAndKey(t)
	ck := NewCertAndKey(cert, key)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	err := ck.WriteToFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("WriteToFiles failed: %v", err)
	}

	// Verify files exist and have correct permissions
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("cert file not created: %v", err)
	}
	if certInfo.Mode().Perm() != 0644 {
		t.Errorf("cert file has wrong permissions: %o", certInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key file has wrong permissions: %o", keyInfo.Mode().Perm())
	}

	// Verify content can be read back
	ck2, err := NewCertAndKeyFromFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("failed to read back files: %v", err)
	}

	if ck2.Certificate.Subject.CommonName != cert.Subject.CommonName {
		t.Error("certificate content mismatch")
	}
	if !ck2.HasKey() {
		t.Error("key not loaded from file")
	}
}

func TestWriteCertToFile(t *testing.T) {
	cert, _ := generateTestCertAndKey(t)
	ck := NewCertAndKey(cert, nil)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")

	err := ck.WriteCertToFile(certPath)
	if err != nil {
		t.Fatalf("WriteCertToFile failed: %v", err)
	}

	// Verify file exists
	_, err = os.Stat(certPath)
	if err != nil {
		t.Fatalf("cert file not created: %v", err)
	}

	// Verify content
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}

	expectedPEM := certToPEM(cert)
	if string(data) != expectedPEM {
		t.Error("cert file content mismatch")
	}
}

func TestWriteKeyToFile(t *testing.T) {
	_, key := generateTestCertAndKey(t)
	ck := NewCertAndKey(nil, key)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")

	err := ck.WriteKeyToFile(keyPath)
	if err != nil {
		t.Fatalf("WriteKeyToFile failed: %v", err)
	}

	// Verify file exists and has correct permissions
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key file has wrong permissions: %o", keyInfo.Mode().Perm())
	}

	// Verify content
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	expectedPEM := ecKeyToPEM(key)
	if string(data) != expectedPEM {
		t.Error("key file content mismatch")
	}

	// Test error when no key
	ck2 := &CertAndKey{}
	err = ck2.WriteKeyToFile(keyPath)
	if err == nil {
		t.Error("expected error when writing key without key loaded")
	}
}

func TestHasKey(t *testing.T) {
	t.Run("with_key", func(t *testing.T) {
		_, key := generateTestCertAndKey(t)
		ck := NewCertAndKey(nil, key)
		if !ck.HasKey() {
			t.Error("HasKey() should return true when key is present")
		}
	})

	t.Run("without_key", func(t *testing.T) {
		ck := &CertAndKey{}
		if ck.HasKey() {
			t.Error("HasKey() should return false when key is nil")
		}
	})
}
