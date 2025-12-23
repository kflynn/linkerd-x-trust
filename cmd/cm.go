package main

import (
	_ "embed"
	"fmt"

	"github.com/spf13/cobra"
)

//go:embed manifests/cert-manager.yaml
var certManagerYAML string

func newCmdCertManager() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cert-manager",
		Aliases: []string{"cm"},
		Short:   "cert-manager utilities",
		Args:    cobra.NoArgs,
	}

	cmd.AddCommand(newCmdCertManagerBootstrap())

	return cmd
}

func newCmdCertManagerBootstrap() *cobra.Command {
	return &cobra.Command{
		Use:   "bootstrap",
		Short: "Output example YAML for using Linkerd with cert-manager",
		Long: `Output example YAML for using Linkerd with cert-manager.

This command outputs a minimal example of the necessary cert-manager
resources (Issuers, ClusterIssuers, and Certificates) needed to manage
Linkerd's trust anchor and identity issuer certificates using
cert-manager.

CAREFULLY REVIEW THE OUTPUT OF THIS COMMAND BEFORE APPLYING IT TO YOUR
CLUSTER. You should expect to modify it for your environment for all
the following reasons:

1. The bootstrap YAML uses a self-signed Issuer for the trust anchor.
2. It uses a six-month validity period for the trust anchor and a two-week
   validity period for the identity issuer.
3. It does not configure trust-manager: you are expected to keep the trust
   bundle up to date yourself (perhaps using "linkerd x-trust bundle").

Again, CAREFULLY REVIEW THE OUTPUT OF THIS COMMAND BEFORE APPLYING IT TO
YOUR CLUSTER. You should expect to modify it for your environment`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(certManagerYAML)
		},
	}
}
