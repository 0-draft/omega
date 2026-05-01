package federation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/0-draft/omega/internal/server/federation"
)

const samplePEM = "-----BEGIN CERTIFICATE-----\nMIIBdjCCAR2gAwIBAgI=\n-----END CERTIFICATE-----\n"

func TestRegistryOwnOnly(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := federation.NewRegistry(td, []byte(samplePEM), nil, time.Hour)
	got := r.Bundles()
	if len(got) != 1 || string(got["omega.alpha"]) != samplePEM {
		t.Fatalf("unexpected bundles: %v", got)
	}
}

func TestRegistryFetchesPeer(t *testing.T) {
	peerPEM := "-----BEGIN CERTIFICATE-----\npeerbundle\n-----END CERTIFICATE-----\n"
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/bundle" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(peerPEM))
	}))
	defer peerSrv.Close()

	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := federation.NewRegistry(td, []byte(samplePEM), []federation.PeerConfig{
		{TrustDomain: "omega.beta", URL: peerSrv.URL},
	}, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for {
		got := r.Bundles()
		if string(got["omega.beta"]) == peerPEM {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer bundle never appeared: %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRegistryIgnoresUnreachablePeer(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := federation.NewRegistry(td, []byte(samplePEM), []federation.PeerConfig{
		{TrustDomain: "omega.dead", URL: "http://127.0.0.1:1"}, // closed port
	}, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	r.Run(ctx) // returns when ctx times out, after one failed refresh

	got := r.Bundles()
	if _, ok := got["omega.dead"]; ok {
		t.Fatalf("dead peer should be omitted: %v", got)
	}
	if _, ok := got["omega.alpha"]; !ok {
		t.Fatalf("own bundle missing: %v", got)
	}
}
