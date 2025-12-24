package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/grantae/certinfo"
	"github.com/linkerd/linkerd-trust/v2/pkg/utils"
	ourx509 "github.com/linkerd/linkerd-trust/v2/pkg/x509"
	pkgcmd "github.com/linkerd/linkerd2/pkg/cmd"
	"github.com/linkerd/linkerd2/pkg/k8s"
	pkgtls "github.com/linkerd/linkerd2/pkg/tls"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type trustBundleOptions struct {
	configMapName string
	outputPEM     bool
	verbose       bool
	create        bool
	outputIDs     bool
}

func newTrustBundleOptions() *trustBundleOptions {
	return &trustBundleOptions{
		configMapName: utils.TrustRootsConfigMapName,
		outputPEM:     false,
		verbose:       false,
	}
}

func newCmdTrustBundle() *cobra.Command {
	options := newTrustBundleOptions()

	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Manage the Linkerd trust bundle",
		Long: `Manage or display the certificates in the Linkerd trust bundle.

When run without subcommands, displays all certificates in the trust bundle.`,
		Example: `  # Display certificates in the trust bundle
  linkerd trust bundle

  # Add a certificate to the trust bundle
  linkerd trust bundle add ca.crt

  # Remove a certificate from the trust bundle
  linkerd trust bundle remove ca.crt`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showTrustBundle(cmd.Context(), options)
		},
	}

	cmd.Flags().StringVar(&options.configMapName, "configmap", utils.TrustRootsConfigMapName, "Name of the trust roots ConfigMap")
	cmd.Flags().BoolVar(&options.outputPEM, "pem", false, "Output the trust bundle as PEM")
	cmd.Flags().BoolVar(&options.verbose, "verbose", false, "Display verbose certificate details")
	cmd.Flags().BoolVar(&options.outputIDs, "ids", false, "Output only Subject Key IDs")

	cmd.AddCommand(newCmdTrustBundleShow())
	cmd.AddCommand(newCmdTrustBundleAdd())
	cmd.AddCommand(newCmdTrustBundleRemove())
	cmd.AddCommand(newCmdTrustBundleWait())

	return cmd
}

func newCmdTrustBundleShow() *cobra.Command {
	options := newTrustBundleOptions()

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Display certificates in the Linkerd trust bundle",
		Long:  `Display all certificates in the Linkerd trust bundle.`,
		Example: `  # Display certificates in the trust bundle
  linkerd trust bundle show

  # Display from a custom ConfigMap
  linkerd trust bundle show --configmap my-trust-roots -L my-namespace`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return showTrustBundle(cmd.Context(), options)
		},
	}

	cmd.Flags().StringVar(&options.configMapName, "configmap", utils.TrustRootsConfigMapName, "Name of the trust roots ConfigMap")
	cmd.Flags().BoolVar(&options.outputPEM, "pem", false, "Output the trust bundle as PEM")
	cmd.Flags().BoolVar(&options.verbose, "verbose", false, "Display verbose certificate details")
	cmd.Flags().BoolVar(&options.outputIDs, "ids", false, "Output only Subject Key IDs")

	return cmd
}

func newCmdTrustBundleAdd() *cobra.Command {
	options := newTrustBundleOptions()
	var secretName string
	var secretNamespace string

	cmd := &cobra.Command{
		Use:   "add <cert-file>",
		Short: "Add a certificate to the Linkerd trust bundle",
		Long: `Add a certificate to the Linkerd trust bundle.

The certificate must be provided as a PEM file containing a certificate.
If the certificate is already present in the trust bundle, it will not be
added again. Without --create, the trust bundle ConfigMap must already
exist.`,
		Example: `  # Add a certificate to the trust bundle
  linkerd trust bundle add ca.crt

  # Add a certificate to a custom ConfigMap
  linkerd trust bundle add ca.crt --configmap my-trust-roots -L my-namespace

  # Create the ConfigMap if it doesn't exist
  linkerd trust bundle add ca.crt --create

  # Add the a certificate from a Secret
  linkerd trust bundle add --secret linkerd-trust-anchor -n cert-manager`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			specifiedCount := 0
			if len(args) > 0 {
				specifiedCount++
			}
			if secretName != "" {
				specifiedCount++
			}
			if specifiedCount == 0 {
				return fmt.Errorf("must specify either a certificate file or --secret flag")
			}
			if specifiedCount > 1 {
				return fmt.Errorf("cannot specify more than one of: certificate file or --secret flag")
			}

			k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			if err != nil {
				return err
			}

			newCertBundle := ourx509.NewBundle()

			// Load the new certificates as a bundle.
			if secretName != "" {
				// Read from Secret
				if secretNamespace == "" {
					secretNamespace = controlPlaneNamespace
				}

				secret, err := k8sAPI.CoreV1().Secrets(secretNamespace).Get(cmd.Context(), secretName, metav1.GetOptions{})

				if err != nil {
					return fmt.Errorf("could not read Secret %s/%s: %w", secretNamespace, secretName, err)
				}

				certAndKey, err := ourx509.NewCertAndKeyFromSecret(secret, "", "")

				if err != nil {
					return fmt.Errorf("could not load certificate from Secret %s/%s: %w", secretNamespace, secretName, err)
				}

				// Add the cert from the Secret to our new-certificates bundle.
				newCertBundle.Add(certAndKey.Certificate)
			} else {
				certFile := args[0]

				err = newCertBundle.LoadFromFile(certFile)

				if err != nil {
					return fmt.Errorf("could not load certificates from %s: %w", certFile, err)
				}
			}

			// Set up to load our existing trust bundle.
			existingBundle := ourx509.NewBundle()

			// Does our ConfigMap already exist?
			mustCreate := false
			ctx := cmd.Context()
			configMap, err := k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Get(ctx, options.configMapName, metav1.GetOptions{})

			if err != nil {
				// No. If we're not allowed to create it, that's an error.
				if !options.create {
					return fmt.Errorf("ConfigMap %s/%s not found (use --create to create it): %w", controlPlaneNamespace, options.configMapName, err)
				}

				mustCreate = true
				configMap = &corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      options.configMapName,
						Namespace: controlPlaneNamespace,
					},
					Data: map[string]string{},
				}

				fmt.Printf("Creating ConfigMap %s/%s\n", controlPlaneNamespace, options.configMapName)
			} else {
				// ConfigMap exists, get existing trust bundle
				err = existingBundle.LoadFromConfigMap(configMap, "")

				if err != nil {
					return fmt.Errorf("could not load existing trust bundle: %w", err)
				}
			}

			// Add new certs only.
			for cert := range newCertBundle.All() {
				if !existingBundle.Contains(cert) {
					existingBundle.Add(cert)
					fmt.Printf("Added certificate %s (SKI: %s) to trust bundle\n", cert.Subject.CommonName, utils.GetSubjectKeyID(cert))
				} else {
					fmt.Printf("Certificate %s (SKI: %s) already exists in trust bundle, skipping\n", cert.Subject.CommonName, utils.GetSubjectKeyID(cert))
				}
			}

			// Update or create the ConfigMap
			configMap.Data[utils.TrustRootsDataKey] = existingBundle.PEM()

			if mustCreate {
				// Create new ConfigMap
				_, err = k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Create(ctx, configMap, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create ConfigMap: %w", err)
				}
			} else {
				// Update existing ConfigMap
				_, err = k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Update(ctx, configMap, metav1.UpdateOptions{})
				if err != nil {
					return fmt.Errorf("failed to update ConfigMap: %w", err)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&options.configMapName, "configmap", utils.TrustRootsConfigMapName, "Name of the trust roots ConfigMap")
	cmd.Flags().BoolVar(&options.create, "create", false, "Create the ConfigMap if it doesn't exist")
	cmd.Flags().StringVar(&secretName, "secret", "", "Name of the Secret containing the certificate to wait for")
	cmd.Flags().StringVarP(&secretNamespace, "secret-namespace", "n", "", "Namespace of the Secret (defaults to control plane namespace)")

	return cmd
}

func newCmdTrustBundleRemove() *cobra.Command {
	options := newTrustBundleOptions()
	var skiFlag string

	cmd := &cobra.Command{
		Use:   "remove <cert-file>",
		Short: "Remove a certificate from the Linkerd trust bundle",
		Long: `Remove a certificate from the Linkerd trust bundle.

The certificate can be specified either as a PEM file containing the
certificate, or using the --id SKI to give its full hex Subject Key ID.`,
		Example: `  # Remove a certificate by file
  linkerd trust bundle remove ca.crt

  # Remove a certificate by Subject Key ID
  linkerd trust bundle remove --id 2053a02b6151b3878a9d64bd5348b66ee64725be

  # Remove from a custom ConfigMap
  linkerd trust bundle remove ca.crt --configmap my-trust-roots -L my-namespace`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate that either file or --id is provided, but not both
			if len(args) == 0 && skiFlag == "" {
				return fmt.Errorf("must specify either a certificate file or use --id flag")
			}
			if len(args) > 0 && skiFlag != "" {
				return fmt.Errorf("cannot specify both a certificate file and --id flag")
			}

			k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			if err != nil {
				return err
			}

			ctx := cmd.Context()

			// Get the existing ConfigMap
			configMap, err := k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Get(ctx, options.configMapName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get ConfigMap %s/%s: %w", controlPlaneNamespace, options.configMapName, err)
			}

			// Get existing trust bundle
			existingBundle, err := ourx509.NewBundleFromConfigMap(configMap, "")

			if err != nil {
				return fmt.Errorf("could not load existing trust bundle: %w", err)
			}

			// Determine target SKI
			var targetSKI string
			if skiFlag != "" {
				// Use the provided SKI
				targetSKI = strings.ToLower(strings.ReplaceAll(skiFlag, ":", ""))
			} else {
				// Read from file
				certFile := args[0]
				certData, err := os.ReadFile(certFile)
				if err != nil {
					return fmt.Errorf("failed to read certificate file: %w", err)
				}

				certs, err := pkgtls.DecodePEMCertificates(string(certData))
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}

				if len(certs) == 0 {
					return fmt.Errorf("no valid certificates found in %s", certFile)
				}

				targetSKI = utils.GetSubjectKeyID(certs[0])
			}

			// Remove certificates matching the SKI
			err = existingBundle.Remove(targetSKI)

			if err != nil {
				// This can only happen if the certificate isn't in the bundle.
				return err
			}

			// Update the ConfigMap
			configMap.Data[utils.TrustRootsDataKey] = existingBundle.PEM()

			_, err = k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Update(ctx, configMap, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update ConfigMap: %w", err)
			}

			fmt.Println("Successfully removed certificate from trust bundle")
			return nil
		},
	}

	cmd.Flags().StringVar(&options.configMapName, "configmap", utils.TrustRootsConfigMapName, "Name of the trust roots ConfigMap")
	cmd.Flags().StringVar(&skiFlag, "id", "", "Subject Key ID of the certificate to remove (hex format)")

	return cmd
}

func newCmdTrustBundleWait() *cobra.Command {
	options := newTrustBundleOptions()
	var skiFlag string
	var timeoutDuration string
	var secretName string
	var secretNamespace string

	cmd := &cobra.Command{
		Use:   "wait <cert-file>",
		Short: "Wait for a certificate to appear in the trust bundle",
		Long: `Wait for a certificate to appear in the trust bundle in the linkerd-identity-trust-roots ConfigMap.

The certificate can be specified as a PEM file, by Subject Key ID using the --id flag,
or from a Secret using the --secret flag. This command polls the ConfigMap until the
certificate appears or the timeout expires.`,
		Example: `  # Wait for a certificate to appear in the trust bundle
  linkerd trust bundle wait anchor.crt

  # Wait for a certificate by Subject Key ID with custom timeout
  linkerd trust bundle wait --id 8b5d19a740e9f20b4d2f645e5496ce491f5821dd --timeout 5m

  # Wait for a certificate from a Secret
  linkerd trust bundle wait --secret linkerd-trust-anchor -n cert-manager

  # Wait for a certificate to appear in a custom ConfigMap
  linkerd trust bundle wait anchor.crt --configmap my-trust-roots -L my-namespace`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate that exactly one of file, --id, or --secret is provided
			specifiedCount := 0
			if len(args) > 0 {
				specifiedCount++
			}
			if skiFlag != "" {
				specifiedCount++
			}
			if secretName != "" {
				specifiedCount++
			}
			if specifiedCount == 0 {
				return fmt.Errorf("must specify either a certificate file, --id flag, or --secret flag")
			}
			if specifiedCount > 1 {
				return fmt.Errorf("cannot specify more than one of: certificate file, --id flag, or --secret flag")
			}

			// Parse timeout
			timeout, err := time.ParseDuration(timeoutDuration)
			if err != nil {
				return fmt.Errorf("invalid timeout duration: %w", err)
			}

			ctx := cmd.Context()

			// Determine target SKI

			k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			if err != nil {
				return err
			}

			var targetSKI string
			if skiFlag != "" {
				// Use the provided SKI
				targetSKI = strings.ToLower(strings.ReplaceAll(skiFlag, ":", ""))
			} else if secretName != "" {
				// Read from Secret
				if secretNamespace == "" {
					secretNamespace = controlPlaneNamespace
				}

				secret, err := k8sAPI.CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{})

				if err != nil {
					return fmt.Errorf("could not read Secret %s/%s: %w", secretNamespace, secretName, err)
				}

				certAndKey, err := ourx509.NewCertAndKeyFromSecret(secret, "", "")

				if err != nil {
					return fmt.Errorf("could not load certificate from Secret %s/%s: %w", secretNamespace, secretName, err)
				}

				targetSKI = utils.GetSubjectKeyID(certAndKey.Certificate)
				fmt.Printf("Loaded certificate %s from Secret %s/%s\n", certAndKey.Certificate.Subject.CommonName, secretNamespace, secretName)
			} else {
				// Read from file
				certAndKey, err := ourx509.NewCertAndKeyFromFiles(args[0], "")

				if err != nil {
					return fmt.Errorf("could not load certificate from file %s: %w", args[0], err)
				}

				targetSKI = utils.GetSubjectKeyID(certAndKey.Certificate)
			}

			fmt.Printf("Waiting for certificate with SKI %s to appear in trust bundle...\n", targetSKI)

			// Poll the ConfigMap
			startTime := time.Now()
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			timeoutTimer := time.NewTimer(timeout)
			defer timeoutTimer.Stop()

			for {
				select {
				case <-timeoutTimer.C:
					return fmt.Errorf("timeout waiting for certificate with SKI %s", targetSKI)
				case <-ticker.C:
					// Get the current ConfigMap
					configMap, err := k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Get(ctx, options.configMapName, metav1.GetOptions{})
					if err != nil {
						// ConfigMap doesn't exist yet, keep waiting
						continue
					}

					// Load trust bundle
					existingBundle, err := ourx509.NewBundleFromConfigMap(configMap, "")

					if err != nil {
						// Bundle is malformed, keep waiting
						continue
					}

					// Check if target certificate is present
					if existingBundle.ContainsSKI(targetSKI) {
						elapsed := time.Since(startTime)
						fmt.Printf("✓ Certificate with SKI %s found in trust bundle after %s\n", targetSKI, elapsed)
						return nil
					}
				}
			}
		},
	}

	cmd.Flags().StringVar(&options.configMapName, "configmap", utils.TrustRootsConfigMapName, "Name of the trust roots ConfigMap")
	cmd.Flags().StringVar(&skiFlag, "id", "", "Subject Key ID of the certificate to wait for (hex format)")
	cmd.Flags().StringVar(&secretName, "secret", "", "Name of the Secret containing the certificate to wait for")
	cmd.Flags().StringVarP(&secretNamespace, "secret-namespace", "n", "", "Namespace of the Secret (defaults to control plane namespace)")
	cmd.Flags().StringVar(&timeoutDuration, "timeout", "1m", "Maximum time to wait (e.g., 30s, 1m, 5m)")

	return cmd
}

type chainOptions struct {
	*trustBundleOptions
	namespace string
	selector  string
}

func newChainOptions() *chainOptions {
	return &chainOptions{
		trustBundleOptions: newTrustBundleOptions(),
		namespace:          "",
		selector:           "",
	}
}

func newCmdTrustChain() *cobra.Command {
	options := newChainOptions()

	cmd := &cobra.Command{
		Use:   "chain [flags] (POD)",
		Short: "Display and verify the trust chain",
		Long: `Display and verify the complete trust chain in the service mesh.

This command reads all certificates in the trust bundle, the identity issuer certificate,
and a workload certificate, then displays their relationships as a tree diagram and verifies
the chain of trust. By default, it uses the linkerd-identity controller. You can specify a
pod name or use a label selector.`,
		Example: `  # Display and verify the trust chain using identity controller
  linkerd trust chain

  # Use identity controller in a custom control plane namespace
  linkerd trust chain -L linkerd-custom

  # Check trust chain for a specific pod
  linkerd trust chain my-pod

  # Check trust chain for a pod in a specific namespace
  linkerd trust chain -n faces face-55d6d64d96-frf4w

  # Check trust chain for pods matching a label
  linkerd trust chain -n faces -l app=myapp

  # Check a pod but use trust bundle from custom control plane namespace
  linkerd trust chain -L linkerd-custom my-pod`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set default namespace if not specified
			if options.namespace == "" {
				options.namespace = pkgcmd.GetDefaultNamespace(kubeconfigPath, kubeContext)
			}

			k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
			if err != nil {
				return err
			}

			ctx := cmd.Context()

			// Read trust bundle from ConfigMap (always from control plane namespace)
			trustBundleCerts, err := utils.GetTrustBundleCerts(ctx, k8sAPI, controlPlaneNamespace, options.configMapName)
			if err != nil {
				return err
			}

			// Read identity issuer from Secret (always from control plane namespace)
			issuerSecretCert, err := utils.GetCertFromSecret(ctx, k8sAPI, controlPlaneNamespace, utils.IdentityIssuerSecretName)
			if err != nil {
				return err
			}

			// Read workload cert - either from specified pod or from identity controller
			var workloadCert, identityIssuerFromProxy *x509.Certificate

			if len(args) > 0 || options.selector != "" {
				// Use specified pod(s)
				pods, err := utils.GetPods(ctx, k8sAPI, options.namespace, options.selector, args)
				if err != nil {
					return err
				}
				if len(pods) == 0 {
					return fmt.Errorf("no pods found matching criteria")
				}
				pod := pods[0]
				container, err := utils.GetContainerWithPort(pod, k8s.ProxyAdminPortName)
				if err != nil {
					return err
				}
				certs, err := utils.GetContainerCertificate(k8sAPI, pod, container, k8s.ProxyAdminPortName, false)
				if err != nil {
					return err
				}
				if len(certs) < 2 {
					return fmt.Errorf("expected at least 2 certificates from pod, got %d", len(certs))
				}
				workloadCert = certs[0]
				identityIssuerFromProxy = certs[1]
			} else {
				// Use linkerd-identity controller
				workloadCert, identityIssuerFromProxy, err = utils.GetWorkloadCertFromIdentity(ctx, k8sAPI, controlPlaneNamespace)

				if err != nil {
					return err
				}
			}

			// Verify that identity issuers match
			fmt.Println("Trust Chain Verification")
			fmt.Println("========================")
			fmt.Println()

			errors := []string{}

			// Verify identity issuer from secret matches the one from proxy
			issuerSecretSKI := utils.GetSubjectKeyID(issuerSecretCert)
			identityIssuerFromProxySKI := utils.GetSubjectKeyID(identityIssuerFromProxy)

			if issuerSecretSKI != identityIssuerFromProxySKI {
				errors = append(errors, fmt.Sprintf("❌ Identity issuer mismatch: Secret SKI (%s) != Proxy issuer SKI (%s)", issuerSecretSKI, identityIssuerFromProxySKI))
			} else {
				fmt.Printf("✓ Identity issuer from Secret matches issuer from proxy (SKI: %s)\n", issuerSecretSKI)
			}

			// Verify trust bundle signs the identity issuer
			trustBundleSignsIssuer := false
			var signingRoot *x509.Certificate
			for _, trustCert := range trustBundleCerts {
				if utils.VerifyCertSignedBy(issuerSecretCert, trustCert) {
					trustBundleSignsIssuer = true
					signingRoot = trustCert
					break
				}
			}

			if !trustBundleSignsIssuer {
				errors = append(errors, "❌ No certificate in trust bundle signs the identity issuer")
			} else {
				fmt.Printf("✓ Trust anchor %s signs identity issuer %s\n", signingRoot.Subject.CommonName, issuerSecretCert.Subject.CommonName)
			}

			// Verify identity issuer signs workload cert
			if !utils.VerifyCertSignedBy(workloadCert, issuerSecretCert) {
				errors = append(errors, "❌ Identity issuer does not sign workload certificate")
			} else {
				fmt.Printf("✓ Identity issuer %s signs workload certificate\n", issuerSecretCert.Subject.CommonName)
			}

			fmt.Println()
			fmt.Println("Certificate Hierarchy")
			fmt.Println("====================")
			fmt.Println()

			if options.verbose {
				// Verbose mode: show full certificate details
				fmt.Println("Trust Anchors (in ConfigMap):")
				for i, cert := range trustBundleCerts {
					ski := utils.GetSubjectKeyID(cert)
					fmt.Printf("\n[%d] %s\n", i+1, cert.Subject.CommonName)
					if signingRoot != nil && ski == utils.GetSubjectKeyID(signingRoot) {
						fmt.Println("    (Signs identity issuer ✓)")
					}
					fmt.Println()
					result, err := certinfo.CertificateText(cert)
					if err != nil {
						return fmt.Errorf("failed to format trust anchor certificate: %w", err)
					}
					fmt.Print(result)
				}

				fmt.Printf("\nIdentity Issuer (in Secret %s):\n\n", utils.IdentityIssuerSecretName)
				result, err := certinfo.CertificateText(issuerSecretCert)
				if err != nil {
					return fmt.Errorf("failed to format issuer certificate: %w", err)
				}
				fmt.Print(result)

				fmt.Println("\nWorkload Certificate:")
				if len(workloadCert.URIs) > 0 {
					fmt.Printf("Identity: %s\n\n", workloadCert.URIs[0].String())
				} else {
					fmt.Println()
				}
				result, err = certinfo.CertificateText(workloadCert)
				if err != nil {
					return fmt.Errorf("failed to format workload certificate: %w", err)
				}
				fmt.Print(result)
			} else {
				// Default mode: show tree diagram
				fmt.Println("Trust Anchors (in ConfigMap):")
				for i, cert := range trustBundleCerts {
					ski := utils.GetSubjectKeyID(cert)
					fmt.Printf("  [%d] %s\n", i+1, cert.Subject.CommonName)
					fmt.Printf("      SKI: %s\n", ski)
					fmt.Printf("      Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02"))
					if signingRoot != nil && ski == utils.GetSubjectKeyID(signingRoot) {
						fmt.Println("      └─> Signs identity issuer ✓")
					}
				}

				fmt.Println()
				fmt.Printf("Identity Issuer (in Secret %s):\n", utils.IdentityIssuerSecretName)
				fmt.Printf("  %s\n", issuerSecretCert.Subject.CommonName)
				fmt.Printf("  SKI: %s\n", issuerSecretSKI)
				fmt.Printf("  AKI: %s\n", utils.GetAuthorityKeyID(issuerSecretCert))
				fmt.Printf("  Valid: %s to %s\n", issuerSecretCert.NotBefore.Format("2006-01-02"), issuerSecretCert.NotAfter.Format("2006-01-02"))
				fmt.Println("  └─> Signs workload certificates ✓")

				fmt.Println()
				fmt.Println("Workload Certificate:")
				fmt.Printf("  %s\n", workloadCert.Subject.CommonName)
				fmt.Printf("  SKI: %s\n", utils.GetSubjectKeyID(workloadCert))
				fmt.Printf("  AKI: %s\n", utils.GetAuthorityKeyID(workloadCert))
				fmt.Printf("  Valid: %s to %s\n", workloadCert.NotBefore.Format("2006-01-02"), workloadCert.NotAfter.Format("2006-01-02"))
				if len(workloadCert.URIs) > 0 {
					fmt.Printf("  Identity: %s\n", workloadCert.URIs[0].String())
				}
			}

			fmt.Println()
			if len(errors) > 0 {
				fmt.Println("Errors:")
				for _, e := range errors {
					fmt.Println(e)
				}
				return fmt.Errorf("trust chain verification failed")
			}

			fmt.Println("✓ Trust chain verification successful")
			return nil
		},
	}

	cmd.Flags().StringVar(&options.configMapName, "configmap", utils.TrustRootsConfigMapName, "Name of the trust roots ConfigMap")
	cmd.Flags().BoolVar(&options.verbose, "verbose", false, "Display full certificate details")
	cmd.Flags().StringVarP(&options.namespace, "namespace", "n", "", "Namespace of the pod")
	cmd.Flags().StringVarP(&options.selector, "selector", "l", "", "Selector (label query) to filter pods")

	pkgcmd.ConfigureNamespaceFlagCompletion(cmd, []string{"namespace"},
		kubeconfigPath, impersonate, impersonateGroup, kubeContext)

	return cmd
}

// showTrustBundle displays all certificates in the trust bundle
func showTrustBundle(ctx context.Context, options *trustBundleOptions) error {
	k8sAPI, err := k8s.NewAPI(kubeconfigPath, kubeContext, impersonate, impersonateGroup, 0)
	if err != nil {
		return err
	}

	configMap, err := k8sAPI.CoreV1().ConfigMaps(controlPlaneNamespace).Get(ctx, options.configMapName, metav1.GetOptions{})

	if err != nil {
		return fmt.Errorf("failed to get ConfigMap %s/%s: %w", controlPlaneNamespace, options.configMapName, err)
	}

	// Load the trust bundle.
	bundle, err := ourx509.NewBundleFromConfigMap(configMap, "")

	if err != nil {
		return fmt.Errorf("failed to load trust bundle: %w", err)
	}

	// If --pem flag is set, output raw PEM
	if options.outputPEM {
		fmt.Print(bundle.PEM())
		return nil
	}

	// If --ski flag is set, output only Subject Key IDs
	if options.outputIDs {
		for _, cert := range bundle.Certificates() {
			fmt.Println(utils.GetSubjectKeyID(cert))
		}
		return nil
	}

	if options.verbose {
		return showTrustBundleVerbose(bundle.Certificates(), options.configMapName)
	}

	return showTrustBundleDefault(bundle.Certificates(), options.configMapName)
}

func showTrustBundleDefault(certs []*x509.Certificate, configMapName string) error {
	// Display certificates
	fmt.Printf("Trust Bundle Certificates (%s/%s)\n", controlPlaneNamespace, configMapName)
	fmt.Println("==========================================")
	fmt.Println()

	for i, cert := range certs {
		fmt.Printf("[%d] %s\n", i+1, cert.Subject.CommonName)
		fmt.Printf("    Subject Key ID: %s\n", utils.GetSubjectKeyID(cert))
		if cert.AuthorityKeyId != nil {
			fmt.Printf("    Authority Key ID: %s\n", utils.GetAuthorityKeyID(cert))
		}
		fmt.Printf("    Valid: %s to %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Issuer: %s\n", cert.Issuer.CommonName)
		if cert.IsCA {
			fmt.Println("    Is CA: true")
		}
		fmt.Println()
	}

	fmt.Printf("Total: %d certificate(s)\n", len(certs))
	return nil
}

func showTrustBundleVerbose(certs []*x509.Certificate, configMapName string) error {
	fmt.Printf("Trust Bundle Certificates (%s/%s)\n", controlPlaneNamespace, configMapName)
	fmt.Println("==========================================")
	fmt.Println()

	for i, cert := range certs {
		fmt.Printf("[%d] %s\n\n", i+1, cert.Subject.CommonName)
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
