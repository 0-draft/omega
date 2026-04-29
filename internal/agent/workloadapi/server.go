// Package workloadapi implements the SPIFFE Workload API server side
// that runs inside `omega agent`.
//
// PoC v0.0.1: only FetchX509SVID and FetchX509Bundles are implemented.
// FetchX509SVID attests the peer via UID, looks up the SPIFFE ID from
// the agent's mapping, and serves an X.509-SVID. The first call hits
// the control plane to issue a fresh certificate; subsequent calls are
// served from a per-UID cache. The stream stays open and sends a new
// SVID at the cert's mid-life refresh point.
package workloadapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	workloadpb "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/kanywst/omega/internal/agent/attestor"
	"github.com/kanywst/omega/internal/server/api"
)

// Mapping maps a peer UID to the SPIFFE ID the agent will request on
// its behalf. v0.1 will replace this with attestor plugins (K8s SAT,
// process info, etc.).
type Mapping map[uint32]string

// svidEntry is one cached, kernel-attested SVID for a UID.
type svidEntry struct {
	spiffeID  string
	svidDER   []byte
	bundleDER []byte
	keyDER    []byte
	notBefore time.Time
	notAfter  time.Time
}

// refreshAt returns the moment past which we should re-issue. We
// refresh at the midpoint of validity so a workload always holds a
// cert with at least ~half its lifetime remaining.
func (e *svidEntry) refreshAt() time.Time {
	return e.notBefore.Add(e.notAfter.Sub(e.notBefore) / 2)
}

func (e *svidEntry) stale(now time.Time) bool {
	return !now.Before(e.refreshAt())
}

type Server struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	serverURL  string
	mapping    Mapping
	httpClient *http.Client
	now        func() time.Time

	mu    sync.Mutex
	cache map[uint32]*svidEntry
}

func NewServer(serverURL string, mapping Mapping) *Server {
	return &Server{
		serverURL:  strings.TrimRight(serverURL, "/"),
		mapping:    mapping,
		httpClient: http.DefaultClient,
		now:        time.Now,
		cache:      map[uint32]*svidEntry{},
	}
}

func (s *Server) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	ctx := stream.Context()
	creds, err := credsFromContext(ctx)
	if err != nil {
		return err
	}
	spiffeID, ok := s.mapping[creds.UID]
	if !ok {
		return status.Errorf(codes.PermissionDenied, "no SVID mapping for uid=%d", creds.UID)
	}

	for {
		entry, err := s.getOrRefresh(ctx, creds.UID, spiffeID)
		if err != nil {
			return err
		}
		if err := stream.Send(&workloadpb.X509SVIDResponse{
			Svids: []*workloadpb.X509SVID{{
				SpiffeId:    entry.spiffeID,
				X509Svid:    entry.svidDER,
				X509SvidKey: entry.keyDER,
				Bundle:      entry.bundleDER,
			}},
		}); err != nil {
			return err
		}
		wait := time.Until(entry.refreshAt())
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}

func (s *Server) FetchX509Bundles(_ *workloadpb.X509BundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	ctx := stream.Context()
	bundleDER, trustDomain, err := s.fetchBundle(ctx)
	if err != nil {
		return err
	}
	return stream.Send(&workloadpb.X509BundlesResponse{
		Bundles: map[string][]byte{trustDomain: bundleDER},
	})
}

// getOrRefresh returns a non-stale SVID for the (uid, spiffeID) pair,
// reissuing through the control plane if the cached one is missing or
// past its refresh time. The cache lock is released across the network
// call so a slow control plane doesn't block other UIDs; the cost is
// that two concurrent requests for the same fresh-needed entry may
// both hit the control plane. Acceptable for the PoC.
func (s *Server) getOrRefresh(ctx context.Context, uid uint32, spiffeID string) (*svidEntry, error) {
	s.mu.Lock()
	if entry, ok := s.cache[uid]; ok && entry.spiffeID == spiffeID && !entry.stale(s.now()) {
		s.mu.Unlock()
		return entry, nil
	}
	s.mu.Unlock()

	resp, key, err := s.requestSVID(ctx, spiffeID)
	if err != nil {
		return nil, err
	}
	svidDER, bundleDER, err := pemToDER(resp.SVID, resp.Bundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decode pem: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal key: %v", err)
	}
	cert, err := x509.ParseCertificate(svidDER)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "parse svid: %v", err)
	}
	entry := &svidEntry{
		spiffeID:  spiffeID,
		svidDER:   svidDER,
		bundleDER: bundleDER,
		keyDER:    keyDER,
		notBefore: cert.NotBefore,
		notAfter:  cert.NotAfter,
	}
	s.mu.Lock()
	s.cache[uid] = entry
	s.mu.Unlock()
	return entry, nil
}

func (s *Server) requestSVID(ctx context.Context, spiffeID string) (*api.IssueSVIDResponse, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "gen key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, err := json.Marshal(api.IssueSVIDRequest{SPIFFEID: spiffeID, CSR: string(csrPEM)})
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "marshal req: %v", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.serverURL+"/v1/svid", bytes.NewReader(body))
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "new req: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, status.Errorf(codes.Internal, "control plane %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out api.IssueSVIDResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, nil, status.Errorf(codes.Internal, "decode response: %v", err)
	}
	return &out, key, nil
}

func (s *Server) fetchBundle(ctx context.Context) ([]byte, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.serverURL+"/v1/bundle", nil)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "new req: %v", err)
	}
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", status.Errorf(codes.Unavailable, "control plane: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", status.Errorf(codes.Internal, "bundle fetch %d", resp.StatusCode)
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, "", status.Error(codes.Internal, "invalid bundle pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", status.Errorf(codes.Internal, "parse bundle: %v", err)
	}
	td := trustDomainFromCertCN(cert.Subject.CommonName)
	return block.Bytes, td, nil
}

// trustDomainFromCertCN reads the trust domain back from the bundle CA
// CN. We currently set CN="Omega Local CA"; for the PoC we hard-code
// "omega.local". A dedicated control plane endpoint will replace this
// before v0.1.
func trustDomainFromCertCN(_ string) string {
	return "omega.local"
}

func credsFromContext(ctx context.Context) (attestor.Creds, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return attestor.Creds{}, status.Error(codes.Internal, "no peer info on context")
	}
	creds, ok := attestor.CredsFromAddr(p.Addr)
	if !ok {
		return attestor.Creds{}, status.Error(codes.PermissionDenied, "peer is not UID-attested (not connected via omega agent listener)")
	}
	return creds, nil
}

func pemToDER(svidPEM, bundlePEM string) (svidDER, bundleDER []byte, err error) {
	sb, _ := pem.Decode([]byte(svidPEM))
	if sb == nil {
		return nil, nil, errors.New("svid pem")
	}
	bb, _ := pem.Decode([]byte(bundlePEM))
	if bb == nil {
		return nil, nil, errors.New("bundle pem")
	}
	return sb.Bytes, bb.Bytes, nil
}

var _ workloadpb.SpiffeWorkloadAPIServer = (*Server)(nil)
