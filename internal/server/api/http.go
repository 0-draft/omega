// Package api exposes the Omega control plane over HTTP/JSON.
//
// PoC v0.0.1 keeps things simple: net/http + encoding/json. The
// AuthZEN evaluation endpoint and gRPC Workload API land in W3 / W2.
package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

type Server struct {
	store  *storage.Store
	ca     *identity.Authority
	policy *policy.Engine
}

func NewServer(store *storage.Store, ca *identity.Authority, pdp *policy.Engine) *Server {
	return &Server{store: store, ca: ca, policy: pdp}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("POST /v1/domains", s.createDomain)
	mux.HandleFunc("GET /v1/domains", s.listDomains)
	mux.HandleFunc("GET /v1/domains/{name}", s.getDomain)
	mux.HandleFunc("POST /v1/svid", s.issueSVID)
	mux.HandleFunc("GET /v1/bundle", s.getBundle)
	mux.HandleFunc("POST /access/v1/evaluation", s.evaluateAccess)
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) createDomain(w http.ResponseWriter, r *http.Request) {
	var d storage.Domain
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
		return
	}
	created, err := s.store.CreateDomain(r.Context(), d)
	switch {
	case errors.Is(err, storage.ErrAlreadyExists):
		writeErr(w, http.StatusConflict, err)
	case err != nil:
		writeErr(w, http.StatusBadRequest, err)
	default:
		writeJSON(w, http.StatusCreated, created)
	}
}

func (s *Server) getDomain(w http.ResponseWriter, r *http.Request) {
	d, err := s.store.GetDomain(r.Context(), r.PathValue("name"))
	switch {
	case errors.Is(err, storage.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err)
	default:
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *Server) listDomains(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListDomains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if items == nil {
		items = []storage.Domain{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type IssueSVIDRequest struct {
	SPIFFEID string `json:"spiffe_id"`
	CSR      string `json:"csr"`
}

type IssueSVIDResponse struct {
	SVID      string    `json:"svid"`
	Bundle    string    `json:"bundle"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) issueSVID(w http.ResponseWriter, r *http.Request) {
	var req IssueSVIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
		return
	}
	id, err := spiffeid.FromString(req.SPIFFEID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("spiffe_id: %w", err))
		return
	}
	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil {
		writeErr(w, http.StatusBadRequest, errors.New("csr: invalid PEM"))
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("csr: parse: %w", err))
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("csr: signature: %w", err))
		return
	}
	svid, err := s.ca.IssueSVID(id, csr.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, IssueSVIDResponse{
		SVID:      string(svid.CertPEM),
		Bundle:    string(svid.BundlePEM),
		ExpiresAt: svid.NotAfter,
	})
}

func (s *Server) evaluateAccess(w http.ResponseWriter, r *http.Request) {
	var req policy.EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid body: %w", err))
		return
	}
	resp, err := s.policy.Evaluate(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getBundle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.ca.BundlePEM())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}
