package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage Cedar policies",
	}

	var file string
	apply := &cobra.Command{
		Use:   "apply",
		Short: "Apply a Cedar policy file to the control plane",
		RunE: func(_ *cobra.Command, _ []string) error {
			if file == "" {
				return fmt.Errorf("--file is required")
			}
			// TODO(W3): POST to control plane policy endpoint
			return fmt.Errorf("not implemented yet (W3): would apply %s", file)
		},
	}
	apply.Flags().StringVarP(&file, "file", "f", "", "path to a Cedar policy file")

	cmd.AddCommand(apply)
	return cmd
}
