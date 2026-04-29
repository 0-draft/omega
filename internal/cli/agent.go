package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newAgentCommand() *cobra.Command {
	var (
		socket    string
		serverAddr string
	)

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the Raftel node agent (SPIFFE Workload API)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO(W2): listen SPIFFE Workload API on the unix socket,
			//           UID-attest the caller, ask the control plane for an SVID.
			return fmt.Errorf("not implemented yet (W2): socket=%s server=%s",
				socket, serverAddr)
		},
	}

	cmd.Flags().StringVar(&socket, "socket", "/tmp/raftel-agent.sock", "Workload API unix socket path")
	cmd.Flags().StringVar(&serverAddr, "server", "127.0.0.1:8443", "control plane gRPC address")

	return cmd
}
