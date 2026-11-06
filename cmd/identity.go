package main

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/grantae/certinfo"
	"github.com/linkerd/linkerd-trust/v2/pkg/utils"
	"github.com/linkerd/linkerd2/pkg/k8s"
	pkgtls "github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type trustIdentityOptions struct {
	secretName string
	outputPEM  bool
	verbose    bool
	outputIDs  bool
}

func newTrustIdentityOptions() *trustIdentityOptions {
	return &trustIdentityOptions{
		secretName: utils.IdentityIssuerSecretName,
		outputPEM:  false,
		verbose:    false,
	}
}

func newCmdTrustIdentity() *cobra.Command {
	options := newTrustIdentityOptions()

	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage identity issuer credentials",
		Long: `Manage identity issuer credentials in the service mesh.

When run without subcommands, displays the identity issuer certificate.`,
		Example: `  # Display the identity issuer certificate
  linkerd trust identity

  # Update the identity issuer
  linkerd trust identity update issuer.crt issuer.key

  # Update with a federated issuer chain
  linkerd trust identity update issuer.crt cluster-anchor.crt issuer.key`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showIdentityIssuer(cmd.Context(), options)
		},
	}

	cmd.Flags().StringVar(&options.secretName, "secret", utils.IdentityIssuerSecretName, "Name of the identity issuer Secret")
	cmd.Flags().BoolVar(&options.outputPEM, "pem", false, "Output the certificate as PEM")
	cmd.Flags().BoolVar(&options.verbose, "verbose", false, "Display verbose certificate details")
	cmd.Flags().BoolVar(&options.outputIDs, "ids", false, "Output only Subject Key ID")

	cmd.AddCommand(newCmdTrustIdentityShow())
	cmd.AddCommand(newCmdTrustIdentityUpdate())

	return cmd
}

func newCmdTrustIdentityShow() *cobra.Command {
	options := newTrustIdentityOptions()

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Display the identity issuer certificate",
		Long:  `Display the identity issuer certificate from the linkerd-identity-issuer Secret.`,
		Example: `  # Display the identity issuer certificate
  linkerd trust identity show

  # Display from a custom Secret
  linkerd trust identity show --secret my-issuer -L my-namespace`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showIdentityIssuer(cmd.Context(), options)
		},
	}

	cmd.Flags().StringVar(&options.secretName, "secret", utils.IdentityIssuerSecretName, "Name of the identity issuer Secret")
	cmd.Flags().BoolVar(&options.outputPEM, "pem", false, "Output the certificate as PEM")
	cmd.Flags().BoolVar(&options.verbose, "verbose", false, "Display verbose certificate details")
	cmd.Flags().BoolVar(&options.outputIDs, "ids", false, "Output only Subject Key ID")

	return cmd
}

func newCmdTrustIdentityUpdate() *cobra.Command {
	var createFlag bool
	var secretName string

	cmd := &cobra.Command{
		Use:   "update <cert-file> [<intermediate-cert-file> ...] <key-file>",
		Short: "Update the identity issuer certificate and key",
		Long: `Update the identity issuer certificate and key in the linkerd-identity-issuer Secret.

The last argument is the key file; every earlier argument is a certificate
file. Each certificate file may hold a single certificate or a multi-
certificate bundle, in any order. The key file selects the certificate to
install: it must match exactly one of the certificates (for a federated
issuer, the identity issuer itself). That certificate's issuers must form a
chain, each signed by the one above it, anchored by the trust bundle.

Additional certificates beyond the leaf's chain are allowed, as long as each
one is signed by another given certificate or by a certificate in the trust
bundle: during issuer rotation, both the current and the next generation's
certificates need to be present until the control plane can be restarted.
Only the selected certificate's chain is written to the Secret.

The command validates that:
1. The key matches exactly one of the certificates (the one to install)
2. That certificate's issuer chain is anchored by the trust bundle
3. Every other certificate is signed by another given certificate or by
   a certificate in the trust bundle (so rotation material may be present)`,
		Example: `  # Update the identity issuer
  linkerd trust identity update issuer.crt issuer.key

  # Update with a federated issuer chain (issuer + cluster anchor)
  linkerd trust identity update issuer.crt cluster-anchor.crt issuer.key

  # Rotation: both generations present; the key picks the issuer to install
  linkerd trust identity update id1.crt anchor1.crt id2.crt anchor2.crt id1.key

  # Update in a custom namespace
  linkerd trust identity update issuer.crt cluster-anchor.crt issuer.key -L my-namespace

  # Create the Secret if it doesn't exist
  linkerd trust identity update --create issuer.crt cluster-anchor.crt issuer.key`,
		Args:         cobra.MinimumNArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			certFiles := args[:len(args)-1]
			keyFile := args[len(args)-1]

			// Load the certificate files and the key file. The leaf
			// certificate is the one matching the key; the rest of the
			// certificates are ordered into an issuer chain above it.
			// This happens before any cluster interaction, so local
			// errors are reported without needing cluster access.
			chainCerts, certData, keyData, allCerts, err := utils.LoadIssuerChainFromPaths(certFiles, keyFile)
			if err != nil {
				return fmt.Errorf("failed to load certificate and key: %w", err)
			}

			k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			if err != nil {
				return err
			}

			ctx := cmd.Context()

			// The issuer to install is the chain's leaf.
			issuerCert := chainCerts[0]

			// Get trust bundle
			trustBundleCerts, err := utils.GetTrustBundleCerts(ctx, k8sAPI, controlPlaneNamespace, utils.TrustRootsConfigMapName)
			if err != nil {
				return err
			}

			// Verify the certificate chain is anchored by a trust anchor
			signingCert, err := utils.VerifyChainAnchored(chainCerts, trustBundleCerts)
			if err != nil {
				return fmt.Errorf("%w (for a federated issuer, provide the issuer certificate and the intermediate certificates above it, e.g. 'identity update issuer.crt cluster-anchor.crt issuer.key')", err)
			}

			// Rotation: certificates beyond the leaf's chain (the next
			// generation's issuer and anchor) may be given, as long as each
			// one is signed by another given certificate or by a trust
			// bundle certificate.
			if err := utils.ValidateRotationCerts(allCerts, trustBundleCerts); err != nil {
				return err
			}

			if len(chainCerts) > 1 {
				fmt.Printf("✓ Certificate chain (%d intermediate(s)) is anchored by trust anchor: %s\n", len(chainCerts)-1, signingCert.Subject.CommonName)
			} else {
				fmt.Printf("✓ Certificate is signed by trust anchor: %s\n", signingCert.Subject.CommonName)
			}

			// Get or create the Secret
			secret, err := k8sAPI.CoreV1().Secrets(controlPlaneNamespace).Get(ctx, secretName, metav1.GetOptions{})
			var isNewSecret bool

			if err != nil {
				if !createFlag {
					return fmt.Errorf("Secret %s/%s not found (use --create to create it): %w", controlPlaneNamespace, secretName, err)
				}
				// Create new Secret with kubernetes.io/tls scheme by default
				secret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: controlPlaneNamespace,
					},
					Type: corev1.SecretTypeTLS,
					Data: map[string][]byte{},
				}
				isNewSecret = true
				fmt.Printf("Creating Secret %s/%s\n", controlPlaneNamespace, secretName)
			}

			// Determine the scheme and update accordingly
			if secret.Data == nil {
				secret.Data = make(map[string][]byte)
			}

			// Check if using linkerd.io/tls or kubernetes.io/tls scheme
			_, hasLinkerdKey := secret.Data[k8s.IdentityIssuerKeyName]
			_, hasLinkerdCrt := secret.Data[k8s.IdentityIssuerCrtName]

			if hasLinkerdKey || hasLinkerdCrt {
				// linkerd.io/tls scheme
				secret.Data[k8s.IdentityIssuerCrtName] = []byte(certData)
				secret.Data[k8s.IdentityIssuerKeyName] = []byte(keyData)
			} else {
				// kubernetes.io/tls scheme
				secret.Data["ca.crt"] = []byte(pkgtls.EncodeCertificatesPEM(signingCert))
				secret.Data[corev1.TLSCertKey] = []byte(certData)
				secret.Data[corev1.TLSPrivateKeyKey] = []byte(keyData)
			}

			// Create or update the Secret
			if isNewSecret {
				_, err = k8sAPI.CoreV1().Secrets(controlPlaneNamespace).Create(ctx, secret, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create Secret: %w", err)
				}
			} else {
				_, err = k8sAPI.CoreV1().Secrets(controlPlaneNamespace).Update(ctx, secret, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("failed to update Secret: %w", err)
				}
			}

			fmt.Printf("✓ Successfully updated identity issuer in Secret %s/%s\n", controlPlaneNamespace, secretName)
			fmt.Printf("  Issuer: %s\n", issuerCert.Subject.CommonName)
			fmt.Printf("  SKI: %s\n", utils.GetSubjectKeyID(issuerCert))
			fmt.Printf("  Valid: %s to %s\n", issuerCert.NotBefore.Format("2006-01-02 15:04:05"), issuerCert.NotAfter.Format("2006-01-02 15:04:05"))

			return nil
		},
	}

	cmd.Flags().BoolVar(&createFlag, "create", false, "Create the Secret if it doesn't exist")
	cmd.Flags().StringVar(&secretName, "secret", utils.IdentityIssuerSecretName, "Name of the identity issuer Secret")

	return cmd
}

// showIdentityIssuer displays the identity issuer certificate
func showIdentityIssuer(ctx context.Context, options *trustIdentityOptions) error {
	k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
	if err != nil {
		return err
	}

	// If --pem flag is set, output raw PEM
	if options.outputPEM {
		secret, err := k8sAPI.CoreV1().Secrets(controlPlaneNamespace).Get(ctx, options.secretName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get Secret %s/%s: %w", controlPlaneNamespace, options.secretName, err)
		}

		// Try linkerd.io/tls scheme first
		certData, ok := secret.Data[k8s.IdentityIssuerCrtName]
		if !ok {
			// Try kubernetes.io/tls scheme
			certData, ok = secret.Data[corev1.TLSCertKey]
			if !ok {
				return fmt.Errorf("neither %s nor %s key found in Secret", k8s.IdentityIssuerCrtName, corev1.TLSCertKey)
			}
		}

		fmt.Print(string(certData))
		return nil
	}

	// Get identity issuer certificate(s). For a federated issuer the Secret
	// holds a bundle: the issuer certificate followed by intermediates.
	certs, err := utils.GetCertsFromSecret(ctx, k8sAPI, controlPlaneNamespace, options.secretName)
	if err != nil {
		return err
	}
	cert := certs[0]

	// If --ids flag is set, output only Subject Key ID
	if options.outputIDs {
		fmt.Println(utils.GetSubjectKeyID(cert))
		return nil
	}

	if options.verbose {
		return showIdentityIssuerVerbose(certs, options.secretName)
	}

	return showIdentityIssuerDefault(certs, options.secretName)
}

func showIdentityIssuerDefault(certs []*x509.Certificate, secretName string) error {
	cert := certs[0]

	// Display certificate
	fmt.Printf("Identity Issuer Certificate (%s/%s)\n", controlPlaneNamespace, secretName)
	fmt.Println("==========================================")
	fmt.Println()

	fmt.Printf("Subject: %s\n", cert.Subject.CommonName)
	fmt.Printf("Subject Key ID: %s\n", utils.GetSubjectKeyID(cert))
	if cert.AuthorityKeyId != nil {
		fmt.Printf("Authority Key ID: %s\n", utils.GetAuthorityKeyID(cert))
	}
	fmt.Printf("Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Issuer: %s\n", cert.Issuer.CommonName)
	if cert.IsCA {
		fmt.Println("Is CA: true")
	}
	if len(certs) > 1 {
		fmt.Printf("Bundle: %d certificates (issuer + %d intermediate(s))\n", len(certs), len(certs)-1)
		for _, intermediate := range certs[1:] {
			fmt.Printf("  Intermediate: %s (SKI: %s)\n", intermediate.Subject.CommonName, utils.GetSubjectKeyID(intermediate))
		}
	}

	return nil
}

func showIdentityIssuerVerbose(certs []*x509.Certificate, secretName string) error {
	fmt.Printf("Identity Issuer Certificate (%s/%s)\n", controlPlaneNamespace, secretName)
	fmt.Println("==========================================")
	fmt.Println()

	for i, cert := range certs {
		if len(certs) > 1 {
			fmt.Printf("[%d] %s\n\n", i+1, cert.Subject.CommonName)
		} else {
			fmt.Printf("%s\n\n", cert.Subject.CommonName)
		}
		result, err := certinfo.CertificateText(cert)
		if err != nil {
			return fmt.Errorf("failed to format certificate: %w", err)
		}
		fmt.Print(result)
		if i < len(certs)-1 {
			fmt.Println()
		}
	}

	return nil
}
