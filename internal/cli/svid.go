package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newSVIDCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "svid",
		Short: "Interact with SPIFFE SVIDs via the local agent",
	}

	var socket string
	fetch := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch an X.509-SVID via the SPIFFE Workload API",
		RunE: func(_ *cobra.Command, _ []string) error {
			// TODO(W2): connect to Workload API socket, print SVID + bundle
			return fmt.Errorf("not implemented yet (W2): socket=%s", socket)
		},
	}
	fetch.Flags().StringVar(&socket, "socket", "/tmp/raftel-agent.sock", "Workload API unix socket")

	cmd.AddCommand(fetch)
	return cmd
}
