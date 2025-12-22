package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/linkerd/linkerd-trust/v2/pkg/utils"
	pkgtls "github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
)

func newCmdTrustAnchor() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "anchor",
		Short: "Manage trust anchors",
		Long:  `Generate and manage trust anchor (root CA) certificates.`,
	}

	cmd.AddCommand(newCmdTrustAnchorGenerate())

	return cmd
}

func newCmdTrustAnchorGenerate() *cobra.Command {
	var validityDuration string
	var identity string
	var overwrite bool
	var pathlen int

	cmd := &cobra.Command{
		Use:   "generate <cert-file> <key-file>",
		Short: "Generate a new trust anchor (root CA) certificate",
		Long: `Generate a new self-signed root CA certificate and private key.

This creates a trust anchor that can be used to sign identity issuer certificates.
The certificate is generated with CA:TRUE and appropriate key usage for a root CA.`,
		Example: `  # Generate a root CA certificate
  linkerd trust anchor generate ca.crt ca.key

  # Generate with custom identity
  linkerd trust anchor generate ca.crt ca.key --identity my-root.cluster.local

  # Generate with custom validity period
  linkerd trust anchor generate ca.crt ca.key --validity 87600h`,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			certFile := args[0]
			keyFile := args[1]

			// Check if files exist
			if !overwrite {
				if _, err := os.Stat(certFile); err == nil {
					return fmt.Errorf("certificate file %s already exists (use --overwrite to replace)", certFile)
				}
				if _, err := os.Stat(keyFile); err == nil {
					return fmt.Errorf("key file %s already exists (use --overwrite to replace)", keyFile)
				}
			}

			// Parse validity duration
			validity, err := time.ParseDuration(validityDuration)
			if err != nil {
				return fmt.Errorf("invalid validity duration: %w", err)
			}

			// Generate root CA
			fmt.Printf("Generating trust anchor certificate for %s...\n", identity)

			cert, key, err := generateAnchor(identity, validity, pathlen)

			if err != nil {
				return fmt.Errorf("failed to generate anchor: %w", err)
			}

			// Write certificate
			certPEM := pkgtls.EncodeCertificatesPEM(cert)

			if err := os.WriteFile(certFile, []byte(certPEM), 0644); err != nil {
				return fmt.Errorf("failed to write certificate file: %w", err)
			}

			// Write private key
			keyPEM, err := pkgtls.EncodePrivateKeyPEM(key)

			if err != nil {
				return fmt.Errorf("failed to encode private key: %w", err)
			}

			err = os.WriteFile(keyFile, []byte(keyPEM), 0600)

			if err != nil {
				return fmt.Errorf("failed to write key file: %w", err)
			}

			fmt.Printf("✓ Root CA certificate written to %s\n", certFile)
			fmt.Printf("✓ Private key written to %s\n", keyFile)
			fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
			fmt.Printf("  Subject Key ID: %s\n", utils.GetSubjectKeyID(cert))
			fmt.Printf("  Valid: %s to %s\n",
				cert.NotBefore.Format("2006-01-02 15:04:05"),
				cert.NotAfter.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().StringVar(&identity, "identity", "root.linkerd.cluster.local", "Common Name (identity) for the root CA certificate")
	cmd.Flags().StringVar(&validityDuration, "duration", "720h", "Duration period for the certificate (default: 30 days)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	cmd.Flags().IntVar(&pathlen, "pathlen", 1, "Maximum path length for intermediate CAs (0 means no intermediates allowed)")

	return cmd
}

func generateAnchor(identity string, validity time.Duration, pathlen int) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Generate private key
	key, err := pkgtls.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
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
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, key, nil
}
