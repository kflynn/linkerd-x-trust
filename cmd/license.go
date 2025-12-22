package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

const copyrightInfo = "linkerd-x-trust  Copyright (C) 2025 Flynn <license@kodachi.com>"

const licenseInfo = `
This is free software which may be copied under certain conditions;
run "linkerd x-trust license copying" for more information. It has
ABSOLUTELY NO WARRANTY, not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE; run "linkerd x-trust license warranty" for more
information.
`

const warrantyInfo = `
To the extent permitted by law, this program comes with ABSOLUTELY NO
WARRANTY, not even the implied warranties of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE, and its authors accept NO LIABILITY for its
use under any circumstances. See the GNU General Public License version
3 for more information. If you didn't receive a copy of the GPL with this
program, see https://github.com/linkerd/linkerd-x-trust/blob/main/LICENSE.
`

const copyingInfo = `
This is free software which may be copied, modified, or redistributed
under certain conditions, as described in the GNU General Public License
version 3. If you did not receive a copy of that license with this
program, see https://github.com/linkerd/linkerd-x-trust/blob/main/LICENSE.
`

func newCmdLicense() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "license",
		Short: "Print the license information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(copyrightInfo + "\n" + licenseInfo)
		},
	}

	cmd.AddCommand(newCmdLicenseWarranty())
	cmd.AddCommand(newCmdLicenseCopying())

	return cmd
}

func newCmdLicenseWarranty() *cobra.Command {
	return &cobra.Command{
		Use:   "warranty",
		Short: "Print details about the (lack of any) warranty",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(copyrightInfo + "\n" + warrantyInfo)
		},
	}
}

func newCmdLicenseCopying() *cobra.Command {
	return &cobra.Command{
		Use:   "copying",
		Short: "Print details about copying this software",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(copyrightInfo + "\n" + copyingInfo)
		},
	}
}
