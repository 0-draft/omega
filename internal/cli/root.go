package cli

import (
	"github.com/spf13/cobra"

	"github.com/kanywst/raftel/internal/version"
)

func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "raftel",
		Short: "Raftel — Workload Identity + Authorization, in one binary",
		Long: `Raftel is a single-binary control plane for SPIFFE-compatible workload identity,
AuthZEN-compliant authorization, OIDC federation, and AI agent identity.`,
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
		newServerCommand(),
		newAgentCommand(),
		newDomainCommand(),
		newPolicyCommand(),
		newSVIDCommand(),
	)

	return root
}
