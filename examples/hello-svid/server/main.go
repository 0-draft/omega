// hello-svid/server is a tiny mTLS HTTPS server that proves the
// Omega workload identity loop end-to-end. It fetches its own X.509-SVID
// from the local Omega agent over the SPIFFE Workload API, accepts
// connections only from peers in the same trust domain, and echoes back
// the caller's SPIFFE ID.
//
// Run via examples/hello-svid/README.md or `make demo`.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	socket := flag.String("socket", "/tmp/omega-server.sock", "Omega agent Workload API socket")
	addr := flag.String("addr", "127.0.0.1:9443", "HTTPS listen address")
	td := flag.String("trust-domain", "omega.local", "trust domain whose peers are accepted")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	src, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+*socket)),
	)
	if err != nil {
		log.Fatalf("connect to agent %s: %v", *socket, err)
	}
	defer src.Close()

	svid, err := src.GetX509SVID()
	if err != nil {
		log.Fatalf("fetch svid: %v", err)
	}
	log.Printf("server SPIFFE ID: %s (expires %s)", svid.ID, svid.Certificates[0].NotAfter.Format(time.RFC3339))

	trustDomain, err := spiffeid.TrustDomainFromString(*td)
	if err != nil {
		log.Fatalf("trust domain: %v", err)
	}

	srv := &http.Server{
		Addr:              *addr,
		TLSConfig:         tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeMemberOf(trustDomain)),
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "no client cert", http.StatusUnauthorized)
				return
			}
			peerID, err := spiffeid.FromURI(r.TLS.PeerCertificates[0].URIs[0])
			if err != nil {
				http.Error(w, "peer SPIFFE ID parse: "+err.Error(), http.StatusBadRequest)
				return
			}
			fmt.Fprintf(w, "hello from %s -> caller %s\n", svid.ID, peerID)
		}),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on https://%s (mTLS, accept any %s peer)", *addr, trustDomain)
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
