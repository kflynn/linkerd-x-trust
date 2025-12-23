package main

import (
	"fmt"
	"os"
	"time"

	ourx509 "github.com/linkerd/linkerd-trust/v2/pkg/x509"
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

			anchor, err := ourx509.GenerateAnchor(identity, validity, pathlen)

			if err != nil {
				return fmt.Errorf("failed to generate anchor: %w", err)
			}

			// Write certificate
			err = anchor.WriteToFiles(certFile, keyFile)

			if err != nil {
				return fmt.Errorf("failed to write certificate and key to files: %w", err)
			}

			fmt.Printf("✓ Root CA certificate written to %s\n", certFile)
			fmt.Printf("✓ Private key written to %s\n", keyFile)
			fmt.Printf("  Subject: %s\n", anchor.SubjectName())
			fmt.Printf("  Subject Key ID: %s\n", anchor.SubjectKeyID())

			notBefore, notAfter := anchor.ValidityPeriod()

			fmt.Printf("  Valid: %s to %s\n", notBefore, notAfter)

			return nil
		},
	}

	cmd.Flags().StringVar(&identity, "identity", "root.linkerd.cluster.local", "Common Name (identity) for the root CA certificate")
	cmd.Flags().StringVar(&validityDuration, "duration", "720h", "Duration period for the certificate (default: 30 days)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing files")
	cmd.Flags().IntVar(&pathlen, "pathlen", 1, "Maximum path length for intermediate CAs (0 means no intermediates allowed)")

	return cmd
}
