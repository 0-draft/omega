package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kanywst/omega/internal/server/api"
)

func newSVIDCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "svid",
		Short: "Interact with SPIFFE SVIDs",
	}

	var socket string
	fetch := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch an X.509-SVID via the local agent (SPIFFE Workload API)",
		RunE: func(_ *cobra.Command, _ []string) error {
			// TODO(W2 #11): connect to Workload API socket, print SVID + bundle.
			return fmt.Errorf("not implemented yet (W2 #11): socket=%s", socket)
		},
	}
	fetch.Flags().StringVar(&socket, "socket", "/tmp/omega-agent.sock", "Workload API unix socket")

	var (
		serverURL string
		spiffeID  string
		outDir    string
	)
	issue := &cobra.Command{
		Use:   "issue",
		Short: "Generate a fresh ECDSA key + CSR locally and ask the control plane for an X.509-SVID",
		RunE: func(c *cobra.Command, _ []string) error {
			if spiffeID == "" {
				return fmt.Errorf("--spiffe-id is required")
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("gen key: %w", err)
			}
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
			if err != nil {
				return fmt.Errorf("create csr: %w", err)
			}
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

			reqBody, err := json.Marshal(api.IssueSVIDRequest{SPIFFEID: spiffeID, CSR: string(csrPEM)})
			if err != nil {
				return err
			}
			resp, err := http.Post(strings.TrimRight(serverURL, "/")+"/v1/svid", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				return fmt.Errorf("connect to %s: %w", serverURL, err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			var out api.IssueSVIDResponse
			if err := json.Unmarshal(body, &out); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}

			keyDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

			if outDir == "" {
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# SVID")
				_, _ = c.OutOrStdout().Write([]byte(out.SVID))
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# bundle")
				_, _ = c.OutOrStdout().Write([]byte(out.Bundle))
				_, _ = fmt.Fprintln(c.OutOrStdout(), "# private key")
				_, _ = c.OutOrStdout().Write(keyPEM)
				_, _ = fmt.Fprintf(c.OutOrStdout(), "# expires_at: %s\n", out.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
				return nil
			}

			if err := os.MkdirAll(outDir, 0o700); err != nil {
				return err
			}
			files := map[string][]byte{
				"svid.pem":   []byte(out.SVID),
				"bundle.pem": []byte(out.Bundle),
				"key.pem":    keyPEM,
			}
			for name, data := range files {
				path := filepath.Join(outDir, name)
				mode := os.FileMode(0o644)
				if name == "key.pem" {
					mode = 0o600
				}
				if err := os.WriteFile(path, data, mode); err != nil {
					return fmt.Errorf("write %s: %w", path, err)
				}
			}
			_, _ = fmt.Fprintf(c.OutOrStdout(), "wrote %s/{svid,bundle,key}.pem (expires_at=%s)\n", outDir, out.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"))
			return nil
		},
	}
	issue.Flags().StringVar(&serverURL, "server", "http://127.0.0.1:8080", "control plane HTTP base URL")
	issue.Flags().StringVar(&spiffeID, "spiffe-id", "", "SPIFFE ID to issue (e.g. spiffe://omega.local/example/web)")
	issue.Flags().StringVar(&outDir, "out-dir", "", "directory to write svid.pem / bundle.pem / key.pem (default: stdout)")

	cmd.AddCommand(fetch, issue)
	return cmd
}
