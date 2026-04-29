// Package workloadapi implements the SPIFFE Workload API server side
// that runs inside `omega agent`.
//
// PoC v0.0.1: only FetchX509SVID and FetchX509Bundles are implemented.
// Each FetchX509SVID call attests the peer via UID, looks up the SPIFFE
// ID from the agent's mapping, generates an ephemeral key + CSR, and
// asks the control plane HTTP API to sign it. No cache, no rotation.
// Cache + auto-refresh land in #11b.
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
	"fmt"
	"io"
	"net/http"
	"strings"

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

type Server struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	serverURL  string
	mapping    Mapping
	httpClient *http.Client
}

func NewServer(serverURL string, mapping Mapping) *Server {
	return &Server{
		serverURL:  strings.TrimRight(serverURL, "/"),
		mapping:    mapping,
		httpClient: http.DefaultClient,
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

	resp, key, err := s.requestSVID(ctx, spiffeID)
	if err != nil {
		return err
	}

	svidDER, bundleDER, err := pemToDER(resp.SVID, resp.Bundle)
	if err != nil {
		return status.Errorf(codes.Internal, "decode pem: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return status.Errorf(codes.Internal, "marshal key: %v", err)
	}

	if err := stream.Send(&workloadpb.X509SVIDResponse{
		Svids: []*workloadpb.X509SVID{{
			SpiffeId:    spiffeID,
			X509Svid:    svidDER,
			X509SvidKey: keyDER,
			Bundle:      bundleDER,
		}},
	}); err != nil {
		return err
	}
	// PoC: send once and end the stream. The client will reconnect to
	// poll. Cache + rotation arrive in #11b.
	return nil
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
// "omega.local". In #11b the agent will get the trust domain from a
// dedicated control plane endpoint.
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

// Compile-time assertion: Server satisfies the proto interface.
var _ workloadpb.SpiffeWorkloadAPIServer = (*Server)(nil)

// Quiet the "imported and not used" check in test variants that don't
// touch fmt directly.
var _ = fmt.Sprintf
