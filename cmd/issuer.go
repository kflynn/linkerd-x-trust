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

func newCmdTrustIssuer() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issuer",
		Short: "Manage identity issuers",
		Long:  `Generate and manage trust issuer (intermediate CA) certificates.`,
	}

	cmd.AddCommand(newCmdTrustIssuerGenerate())
	return cmd
}

func newCmdTrustIssuerGenerate() *cobra.Command {
	var validityDuration string
	var identity string
	var overwrite bool
	var pathlen int

	cmd := &cobra.Command{
		Use:   "generate <anchor-cert> <anchor-key> <cert-file> <key-file>",
		Short: "Generate a new identity issuer (intermediate CA) certificate",
		Long: `Generate a new Linkerd identity issuer certificate and private key.

This creates a Linkerd identity issuer certificate.`,
		Example: `  # Generate an identity issuer CA certificate
  linkerd trust issuer generate anchor.crt anchor.key issuer.crt issuer.key

  # Generate with custom identity
  linkerd trust issuer generate anchor.crt anchor.key issuer.crt issuer.key --identity my-identity.cluster.local

  # Generate with custom validity period
  linkerd trust issuer generate anchor.crt anchor.key issuer.crt issuer.key --validity 720h`,
		Args:         cobra.ExactArgs(4),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			anchorCertFile := args[0]
			anchorKeyFile := args[1]
			certFile := args[2]
			keyFile := args[3]

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

			// Load anchor cert and key
			anchorCred, _, _, err := utils.LoadCertAndKeyFromPaths(anchorCertFile, anchorKeyFile)

			if err != nil {
				return fmt.Errorf("failed to load trust anchor: %w", err)
			}

			// Generate trust issuer
			fmt.Printf("Generating trust issuer certificate for %s...\n", identity)

			cert, key, err := generateIssuer(anchorCred, identity, validity, pathlen)

			if err != nil {
				return fmt.Errorf("failed to generate issuer: %w", err)
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

			fmt.Printf("✓ Identity issuer certificate written to %s\n", certFile)
			fmt.Printf("✓ Private key written to %s\n", keyFile)
			fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
			fmt.Printf("  Subject Key ID: %s\n", utils.GetSubjectKeyID(cert))
			fmt.Printf("  Valid: %s to %s\n",
				cert.NotBefore.Format("2006-01-02 15:04:05"),
				cert.NotAfter.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().StringVar(&identity, "identity", "identity.linkerd.cluster.local", "Common Name (identity) for the identity issuer certificate")
	cmd.Flags().StringVar(&validityDuration, "duration", "336h", "Duration period for the certificate (default: 14 days)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	cmd.Flags().IntVar(&pathlen, "pathlen", 0, "Maximum path length for intermediate CAs (0 means no intermediates allowed)")

	return cmd
}

func generateIssuer(anchorCred *pkgtls.Cred, identity string, validity time.Duration, pathlen int) (*x509.Certificate, *ecdsa.PrivateKey, error) {
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

	// Sign the identity issuer certificate with the anchor CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, anchorCred.Certificate, key.Public(), anchorCred.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	return cert, key, nil
}
