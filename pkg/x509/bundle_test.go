package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a test certificate for testing purposes
func generateTestCert(cn string) (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(certDER)
}

// certToPEM converts a certificate to PEM format
func certToPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

func TestNewBundle(t *testing.T) {
	b := NewBundle()
	if b == nil {
		t.Fatal("NewBundle() returned nil")
	}
	if b.Len() != 0 {
		t.Errorf("NewBundle() should create empty bundle, got length %d", b.Len())
	}
}

func TestLoadFromPEM(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	pem1 := certToPEM(cert1)
	pem2 := certToPEM(cert2)
	combinedPEM := pem1 + pem2

	t.Run("single certificate", func(t *testing.T) {
		b := NewBundle()
		if err := b.LoadFromPEM(pem1); err != nil {
			t.Fatalf("LoadFromPEM() failed: %v", err)
		}

		if b.Len() != 1 {
			t.Errorf("Expected 1 certificate, got %d", b.Len())
		}
	})

	t.Run("multiple certificates", func(t *testing.T) {
		b := NewBundle()
		if err := b.LoadFromPEM(combinedPEM); err != nil {
			t.Fatalf("LoadFromPEM() failed: %v", err)
		}

		if b.Len() != 2 {
			t.Errorf("Expected 2 certificates, got %d", b.Len())
		}
	})

	t.Run("empty PEM", func(t *testing.T) {
		b := NewBundle()
		if err := b.LoadFromPEM(""); err != nil {
			t.Errorf("LoadFromPEM() with empty string should not error: %v", err)
		}

		if b.Len() != 0 {
			t.Errorf("Expected 0 certificates, got %d", b.Len())
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		b := NewBundle()
		err := b.LoadFromPEM("not a valid pem")
		if err == nil {
			t.Error("LoadFromPEM() should error on invalid PEM")
		}
	})

	t.Run("resets bundle on load", func(t *testing.T) {
		b := NewBundle()
		if err := b.LoadFromPEM(combinedPEM); err != nil {
			t.Fatalf("LoadFromPEM() failed: %v", err)
		}

		if b.Len() != 2 {
			t.Errorf("Expected 2 certificates, got %d", b.Len())
		}

		// Load again with just one cert - should replace, not append
		if err := b.LoadFromPEM(pem1); err != nil {
			t.Fatalf("LoadFromPEM() failed: %v", err)
		}

		if b.Len() != 1 {
			t.Errorf("Expected 1 certificate after reload, got %d", b.Len())
		}
	})
}

func TestAdd(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	t.Run("add certificate", func(t *testing.T) {
		b := NewBundle()
		if err := b.Add(cert1); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		if b.Len() != 1 {
			t.Errorf("Expected 1 certificate, got %d", b.Len())
		}

		if !b.Contains(cert1) {
			t.Error("Bundle should contain added certificate")
		}
	})

	t.Run("add multiple certificates", func(t *testing.T) {
		b := NewBundle()
		if err := b.Add(cert1); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}
		if err := b.Add(cert2); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		if b.Len() != 2 {
			t.Errorf("Expected 2 certificates, got %d", b.Len())
		}
	})

	t.Run("add duplicate certificate", func(t *testing.T) {
		b := NewBundle()
		if err := b.Add(cert1); err != nil {
			t.Fatalf("Add() failed: %v", err)
		}

		err := b.Add(cert1)
		if err == nil {
			t.Error("Add() should error when adding duplicate certificate")
		}

		if b.Len() != 1 {
			t.Errorf("Expected 1 certificate after duplicate add, got %d", b.Len())
		}
	})
}

func TestRemove(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	t.Run("remove by SKI", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)
		b.Add(cert2)

		ski := getSubjectKeyID(cert1)
		if err := b.Remove(ski); err != nil {
			t.Fatalf("Remove() failed: %v", err)
		}

		if b.Len() != 1 {
			t.Errorf("Expected 1 certificate after removal, got %d", b.Len())
		}

		if b.Contains(cert1) {
			t.Error("Bundle should not contain removed certificate")
		}

		if !b.Contains(cert2) {
			t.Error("Bundle should still contain other certificate")
		}
	})

	t.Run("remove non-existent", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)

		err := b.Remove("nonexistent")
		if err == nil {
			t.Error("Remove() should error when removing non-existent certificate")
		}
	})

	t.Run("remove cert", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)
		b.Add(cert2)

		if err := b.RemoveCert(cert1); err != nil {
			t.Fatalf("RemoveCert() failed: %v", err)
		}

		if b.Len() != 1 {
			t.Errorf("Expected 1 certificate after removal, got %d", b.Len())
		}

		if b.Contains(cert1) {
			t.Error("Bundle should not contain removed certificate")
		}
	})
}

func TestContains(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	b := NewBundle()
	b.Add(cert1)

	if !b.Contains(cert1) {
		t.Error("Contains() should return true for added certificate")
	}

	if b.Contains(cert2) {
		t.Error("Contains() should return false for non-added certificate")
	}
}

func TestContainsSKI(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	b := NewBundle()
	b.Add(cert1)

	ski1 := getSubjectKeyID(cert1)
	ski2 := getSubjectKeyID(cert2)

	if !b.ContainsSKI(ski1) {
		t.Error("ContainsSKI() should return true for added certificate")
	}

	if b.ContainsSKI(ski2) {
		t.Error("ContainsSKI() should return false for non-added certificate")
	}

	// Test with colon-separated format
	skiWithColons := strings.ToUpper(ski1)
	var formatted strings.Builder
	for i, c := range skiWithColons {
		if i > 0 && i%2 == 0 {
			formatted.WriteRune(':')
		}
		formatted.WriteRune(c)
	}

	if !b.ContainsSKI(formatted.String()) {
		t.Error("ContainsSKI() should handle colon-separated SKI format")
	}
}

func TestCertificates(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	b := NewBundle()
	b.Add(cert1)
	b.Add(cert2)

	certs := b.Certificates()

	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}

	// Verify it returns a copy (modifying returned slice shouldn't affect bundle)
	certs[0] = nil
	if b.Len() != 2 {
		t.Error("Modifying returned certificates should not affect bundle")
	}
}

func TestPEM(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	t.Run("empty bundle", func(t *testing.T) {
		b := NewBundle()
		pem := b.PEM()
		if pem != "" {
			t.Error("PEM() should return empty string for empty bundle")
		}
	})

	t.Run("single certificate", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)

		pemData := b.PEM()
		if pemData == "" {
			t.Error("PEM() should return non-empty string")
		}

		if !strings.Contains(pemData, "-----BEGIN CERTIFICATE-----") {
			t.Error("PEM() should contain PEM header")
		}

		if !strings.Contains(pemData, "-----END CERTIFICATE-----") {
			t.Error("PEM() should contain PEM footer")
		}
	})

	t.Run("multiple certificates", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)
		b.Add(cert2)

		pemData := b.PEM()

		// Count occurrences of BEGIN CERTIFICATE
		count := strings.Count(pemData, "-----BEGIN CERTIFICATE-----")
		if count != 2 {
			t.Errorf("Expected 2 certificates in PEM output, got %d", count)
		}
	})

	t.Run("ordering stability", func(t *testing.T) {
		pem1 := certToPEM(cert1)
		pem2 := certToPEM(cert2)
		originalPEM := pem1 + pem2

		b := NewBundle()
		if err := b.LoadFromPEM(originalPEM); err != nil {
			t.Fatalf("LoadFromPEM() failed: %v", err)
		}

		outputPEM := b.PEM()

		// Parse both to compare certificates in order
		originalCerts := parsePEMCerts(t, originalPEM)
		outputCerts := parsePEMCerts(t, outputPEM)

		if len(originalCerts) != len(outputCerts) {
			t.Fatalf("Certificate count mismatch: original %d, output %d", len(originalCerts), len(outputCerts))
		}

		for i := range originalCerts {
			if !originalCerts[i].Equal(outputCerts[i]) {
				t.Errorf("Certificate %d differs after load/dump", i)
			}
		}
	})
}

func TestLen(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	b := NewBundle()
	if b.Len() != 0 {
		t.Errorf("Expected length 0, got %d", b.Len())
	}

	b.Add(cert1)
	if b.Len() != 1 {
		t.Errorf("Expected length 1, got %d", b.Len())
	}
}

func TestAll(t *testing.T) {
	cert1, err := generateTestCert("test1.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert2, err := generateTestCert("test2.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	cert3, err := generateTestCert("test3.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	t.Run("iterate over certificates", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)
		b.Add(cert2)
		b.Add(cert3)

		count := 0
		seen := make(map[string]bool)

		for cert := range b.All() {
			count++
			ski := getSubjectKeyID(cert)
			if seen[ski] {
				t.Errorf("Certificate with SKI %s seen multiple times", ski)
			}
			seen[ski] = true
		}

		if count != 3 {
			t.Errorf("Expected to iterate over 3 certificates, got %d", count)
		}
	})

	t.Run("early break", func(t *testing.T) {
		b := NewBundle()
		b.Add(cert1)
		b.Add(cert2)
		b.Add(cert3)

		count := 0
		for range b.All() {
			count++
			if count == 2 {
				break
			}
		}

		if count != 2 {
			t.Errorf("Expected to iterate over 2 certificates before break, got %d", count)
		}
	})

	t.Run("empty bundle", func(t *testing.T) {
		b := NewBundle()

		count := 0
		for range b.All() {
			count++
		}

		if count != 0 {
			t.Errorf("Expected to iterate over 0 certificates, got %d", count)
		}
	})
}

// Helper function to parse PEM certificates for testing
func parsePEMCerts(t *testing.T, pemData string) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate
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

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	return certs
}
