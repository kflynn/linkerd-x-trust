package main

import (
	"fmt"
	"os"
	"time"

	ourx509 "github.com/linkerd/linkerd-trust/v2/pkg/x509"
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
			anchor, err := ourx509.NewCertAndKeyFromFiles(anchorCertFile, anchorKeyFile)

			if err != nil {
				return fmt.Errorf("failed to load trust anchor: %w", err)
			}

			// Generate trust issuer
			fmt.Printf("Generating trust issuer certificate for %s...\n", identity)

			issuer, err := ourx509.GenerateIssuer(anchor, identity, validity, pathlen)

			if err != nil {
				return fmt.Errorf("failed to generate issuer: %w", err)
			}

			// Write certificate
			err = issuer.WriteToFiles(certFile, keyFile)

			if err != nil {
				return fmt.Errorf("failed to write certificate and key to files: %w", err)
			}

			fmt.Printf("✓ Identity issuer certificate written to %s\n", certFile)
			fmt.Printf("✓ Private key written to %s\n", keyFile)
			fmt.Printf("  Subject: %s\n", issuer.SubjectName())
			fmt.Printf("  Subject Key ID: %s\n", issuer.SubjectKeyID())

			notBefore, notAfter := issuer.ValidityPeriod()

			fmt.Printf("  Valid: %s to %s\n", notBefore, notAfter)

			return nil
		},
	}

	cmd.Flags().StringVar(&identity, "identity", "identity.linkerd.cluster.local", "Common Name (identity) for the identity issuer certificate")
	cmd.Flags().StringVar(&validityDuration, "duration", "336h", "Duration period for the certificate (default: 14 days)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	cmd.Flags().IntVar(&pathlen, "pathlen", 0, "Maximum path length for intermediate CAs (0 means no intermediates allowed)")

	return cmd
}
