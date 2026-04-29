package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"

	"github.com/kanywst/raftel/internal/agent/attestor"
	"github.com/kanywst/raftel/internal/agent/workloadapi"
)

func newAgentCommand() *cobra.Command {
	var (
		socket    string
		serverURL string
		mappings  []string
	)

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the Raftel node agent (SPIFFE Workload API)",
		Long: `Run the Raftel node agent: a SPIFFE Workload API gRPC server on a unix
socket that issues X.509-SVIDs to local workloads attested by their UID.

For each workload connection, the agent extracts the peer UID via
SO_PEERCRED (Linux) / LOCAL_PEERCRED (Darwin/BSD), maps it to a SPIFFE
ID via --map, and asks the control plane to sign a fresh CSR.`,
		RunE: func(c *cobra.Command, _ []string) error {
			mapping, err := parseMappings(mappings)
			if err != nil {
				return err
			}
			if len(mapping) == 0 {
				return fmt.Errorf("at least one --map is required (e.g. --map uid=%d,id=spiffe://raftel.local/example/web)", os.Getuid())
			}
			return runAgent(c.Context(), socket, serverURL, mapping)
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "/tmp/raftel-agent.sock", "Workload API unix socket path")
	cmd.Flags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	cmd.Flags().StringArrayVar(&mappings, "map", nil, "uid->spiffe-id mapping (repeatable), e.g. --map 'uid=1000,id=spiffe://raftel.local/example/web'")
	return cmd
}

func parseMappings(specs []string) (workloadapi.Mapping, error) {
	out := workloadapi.Mapping{}
	for _, s := range specs {
		var uidStr, id string
		for _, kv := range strings.Split(s, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return nil, fmt.Errorf("invalid map entry %q (expected key=value pairs)", s)
			}
			switch strings.TrimSpace(k) {
			case "uid":
				uidStr = strings.TrimSpace(v)
			case "id":
				id = strings.TrimSpace(v)
			default:
				return nil, fmt.Errorf("unknown key %q in --map %q (expected uid=, id=)", k, s)
			}
		}
		if uidStr == "" || id == "" {
			return nil, fmt.Errorf("--map %q is missing uid or id", s)
		}
		u, err := strconv.ParseUint(uidStr, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("--map uid=%q: %w", uidStr, err)
		}
		out[uint32(u)] = id
	}
	return out, nil
}

func runAgent(parent context.Context, socketPath, serverURL string, mapping workloadapi.Mapping) error {
	lis, err := attestor.Listen(socketPath)
	if err != nil {
		return err
	}
	defer lis.Close()

	grpcSrv := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(grpcSrv, workloadapi.NewServer(serverURL, mapping))

	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "raftel agent: socket=%s server=%s mappings=%d\n", socketPath, serverURL, len(mapping))
		errCh <- grpcSrv.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		grpcSrv.GracefulStop()
		return nil
	case err := <-errCh:
		return err
	}
}
