package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newServerCommand() *cobra.Command {
	var (
		dataDir  string
		grpcAddr string
		httpAddr string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Raftel control plane (Identity + Policy + Federation Hub)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO(W1): wire storage (SQLite at <dataDir>/raftel.db)
			// TODO(W2): wire identity (CA + SVID issuer)
			// TODO(W3): wire policy (Cedar PDP + AuthZEN HTTP)
			// TODO(W2): expose gRPC on grpcAddr
			// TODO(W3): expose AuthZEN HTTP on httpAddr
			return fmt.Errorf("not implemented yet (W1-W3): data-dir=%s grpc=%s http=%s",
				dataDir, grpcAddr, httpAddr)
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", ".raftel", "directory for SQLite db, CA key, etc.")
	cmd.Flags().StringVar(&grpcAddr, "grpc-addr", "127.0.0.1:8443", "gRPC listen address")
	cmd.Flags().StringVar(&httpAddr, "http-addr", "127.0.0.1:8080", "AuthZEN HTTP listen address")

	return cmd
}
