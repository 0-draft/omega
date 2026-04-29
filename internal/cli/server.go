package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

func newServerCommand() *cobra.Command {
	var (
		dataDir     string
		httpAddr    string
		trustDomain string
		policyDir   string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Omega control plane (Identity + Policy + Federation Hub)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(dataDir, 0o755); err != nil {
				return fmt.Errorf("create data dir: %w", err)
			}
			store, err := storage.Open(filepath.Join(dataDir, "omega.db"))
			if err != nil {
				return err
			}
			defer store.Close()

			ca, err := identity.LoadOrCreate(filepath.Join(dataDir, "ca"), trustDomain)
			if err != nil {
				return fmt.Errorf("ca: %w", err)
			}

			pdp := policy.New()
			if policyDir != "" {
				if err := pdp.LoadDir(policyDir); err != nil {
					return fmt.Errorf("policy: %w", err)
				}
			}

			srv := &http.Server{
				Addr:              httpAddr,
				Handler:           api.NewServer(store, ca, pdp).Handler(),
				ReadHeaderTimeout: 5 * time.Second,
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() {
				fmt.Fprintf(os.Stderr, "omega server: trust-domain=%s data-dir=%s listen=http://%s\n", ca.TrustDomain(), dataDir, httpAddr)
				if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
					return
				}
				errCh <- nil
			}()

			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
				return nil
			case err := <-errCh:
				return err
			}
		},
	}

	cmd.Flags().StringVar(&dataDir, "data-dir", ".omega", "directory for SQLite db, CA key, etc.")
	cmd.Flags().StringVar(&httpAddr, "http-addr", "127.0.0.1:8080", "HTTP listen address (admin API + AuthZEN endpoint)")
	cmd.Flags().StringVar(&trustDomain, "trust-domain", "omega.local", "SPIFFE trust domain")
	cmd.Flags().StringVar(&policyDir, "policy-dir", "", "directory of *.cedar policy files (and optional entities.json) to load at startup")

	return cmd
}
