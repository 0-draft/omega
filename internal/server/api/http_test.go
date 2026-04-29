package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/storage"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPDomainRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Post(srv.URL+"/v1/domains", "application/json", strings.NewReader(`{"name":"example","description":"hi"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status: got %d want 201", resp.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/v1/domains/example")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("get status: got %d want 200", resp2.StatusCode)
	}
	var d storage.Domain
	if err := json.NewDecoder(resp2.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.Name != "example" || d.Description != "hi" {
		t.Errorf("got %+v", d)
	}

	resp3, err := http.Post(srv.URL+"/v1/domains", "application/json", strings.NewReader(`{"name":"example"}`))
	if err != nil {
		t.Fatalf("dup post: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("dup status: got %d want 409", resp3.StatusCode)
	}

	resp4, err := http.Get(srv.URL + "/v1/domains/nope")
	if err != nil {
		t.Fatalf("404 get: %v", err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusNotFound {
		t.Fatalf("404 status: got %d want 404", resp4.StatusCode)
	}
}

func TestHTTPSVIDRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(api.IssueSVIDRequest{
		SPIFFEID: "spiffe://omega.local/example/web",
		CSR:      string(csrPEM),
	})
	resp, err := http.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post svid: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("svid status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.IssueSVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	block, _ := pem.Decode([]byte(out.SVID))
	if block == nil {
		t.Fatal("svid pem decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse svid: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://omega.local/example/web" {
		t.Errorf("svid URI: %v", cert.URIs)
	}

	caBlock, _ := pem.Decode([]byte(out.Bundle))
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("svid does not chain to bundle: %v", err)
	}

	bundleResp, err := http.Get(srv.URL + "/v1/bundle")
	if err != nil {
		t.Fatalf("bundle get: %v", err)
	}
	defer bundleResp.Body.Close()
	if bundleResp.StatusCode != http.StatusOK {
		t.Fatalf("bundle status: %d", bundleResp.StatusCode)
	}
}

func TestHTTPSVIDRejectsForeignTrustDomain(t *testing.T) {
	srv := newTestServer(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, _ := json.Marshal(api.IssueSVIDRequest{SPIFFEID: "spiffe://other.example/foo", CSR: string(csrPEM)})
	resp, err := http.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}
