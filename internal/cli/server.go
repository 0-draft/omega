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

	"github.com/kanywst/raftel/internal/server/api"
	"github.com/kanywst/raftel/internal/server/storage"
)

func newServerCommand() *cobra.Command {
	var (
		dataDir  string
		httpAddr string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the Raftel control plane (Identity + Policy + Federation Hub)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := os.MkdirAll(dataDir, 0o755); err != nil {
				return fmt.Errorf("create data dir: %w", err)
			}
			store, err := storage.Open(filepath.Join(dataDir, "raftel.db"))
			if err != nil {
				return err
			}
			defer store.Close()

			srv := &http.Server{
				Addr:              httpAddr,
				Handler:           api.NewServer(store).Handler(),
				ReadHeaderTimeout: 5 * time.Second,
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			errCh := make(chan error, 1)
			go func() {
				fmt.Fprintf(os.Stderr, "raftel server: listening on http://%s (data-dir=%s)\n", httpAddr, dataDir)
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

	cmd.Flags().StringVar(&dataDir, "data-dir", ".raftel", "directory for SQLite db, CA key, etc.")
	cmd.Flags().StringVar(&httpAddr, "http-addr", "127.0.0.1:8080", "HTTP listen address (admin API + AuthZEN endpoint)")

	return cmd
}
