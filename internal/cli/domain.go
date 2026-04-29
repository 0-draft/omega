package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDomainCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "domain",
		Short: "Manage Raftel domains (hierarchical namespaces, e.g. media.news)",
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "create <name>",
			Short: "Create a new domain",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				// TODO(W1): hit control plane via gRPC
				return fmt.Errorf("not implemented yet (W1): would create %q", args[0])
			},
		},
		&cobra.Command{
			Use:   "get <name>",
			Short: "Get a domain by name",
			Args:  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				return fmt.Errorf("not implemented yet (W1): would get %q", args[0])
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List domains",
			RunE: func(_ *cobra.Command, _ []string) error {
				return fmt.Errorf("not implemented yet (W1)")
			},
		},
	)

	return cmd
}
