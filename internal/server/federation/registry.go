// Package federation maintains the set of SPIFFE trust bundles this
// Omega server is willing to vouch for: its own bundle plus the bundles
// of any peer trust domains configured via --federate-with. Agents pull
// the merged map from /v1/federation/bundles and feed it to the
// Workload API's FetchX509Bundles stream so workloads can validate
// cross-trust-domain mTLS handshakes.
//
// Current model: the operator names every peer explicitly on the
// command line. Bundle exchange is a one-way GET against the peer's
// /v1/bundle PEM endpoint, refreshed on a timer. The SPIFFE Federation
// spec (SPIFFE Trust Domain and Bundle Format §5) describes a richer
// JWKS-based bundle exchange with rotation hints; that work is planned
// alongside the OIDC federation hub.
package federation

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// PeerConfig identifies one federated trust domain by its name and the
// HTTP base URL of the peer Omega control plane that vends the bundle.
type PeerConfig struct {
	TrustDomain string
	URL         string
}

// Registry serves the merged trust-bundle map for this control plane.
// The own bundle never expires (it lives as long as the CA). Peer
// bundles are fetched in the background; a peer that has never been
// reached is omitted from the map rather than served as an empty entry.
type Registry struct {
	ownTD     spiffeid.TrustDomain
	ownBundle []byte

	peers      []PeerConfig
	httpClient *http.Client
	refresh    time.Duration

	mu          sync.RWMutex
	peerBundles map[string][]byte // trust domain -> PEM
}

// NewRegistry returns a Registry that always serves ownTD -> ownBundle
// and lazily merges in peer bundles once Run has populated them. The
// caller is responsible for invoking Run; Bundles() is safe to call
// before Run completes (it just returns own-only).
func NewRegistry(ownTD spiffeid.TrustDomain, ownBundle []byte, peers []PeerConfig, refresh time.Duration) *Registry {
	if refresh <= 0 {
		refresh = 30 * time.Second
	}
	return &Registry{
		ownTD:       ownTD,
		ownBundle:   ownBundle,
		peers:       peers,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		refresh:     refresh,
		peerBundles: map[string][]byte{},
	}
}

// Bundles returns a fresh copy of the trust-domain -> PEM map. Callers
// are free to mutate the returned map and slices.
func (r *Registry) Bundles() map[string][]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]byte, len(r.peerBundles)+1)
	out[r.ownTD.Name()] = append([]byte(nil), r.ownBundle...)
	for td, pem := range r.peerBundles {
		out[td] = append([]byte(nil), pem...)
	}
	return out
}

// Peers returns the configured peer set (without bundle contents).
// Useful for diagnostics endpoints.
func (r *Registry) Peers() []PeerConfig {
	out := make([]PeerConfig, len(r.peers))
	copy(out, r.peers)
	return out
}

// Run blocks until ctx is canceled, refreshing every peer bundle on
// each tick. It performs an immediate fetch on entry so the first
// /v1/federation/bundles caller does not race the timer.
func (r *Registry) Run(ctx context.Context) {
	r.refreshAll(ctx)
	t := time.NewTicker(r.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refreshAll(ctx)
		}
	}
}

func (r *Registry) refreshAll(ctx context.Context) {
	for _, p := range r.peers {
		body, err := r.fetchPeer(ctx, p.URL)
		if err != nil {
			slog.Warn("federation: peer bundle fetch failed", "peer", p.TrustDomain, "url", p.URL, "err", err)
			continue
		}
		r.mu.Lock()
		r.peerBundles[p.TrustDomain] = body
		r.mu.Unlock()
	}
}

func (r *Registry) fetchPeer(ctx context.Context, baseURL string) ([]byte, error) {
	url := strings.TrimRight(baseURL, "/") + "/v1/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		return nil, fmt.Errorf("response is not a PEM bundle (%d bytes)", len(body))
	}
	return body, nil
}
