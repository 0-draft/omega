package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/raftel/internal/server/api"
	"github.com/kanywst/raftel/internal/server/storage"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "raftel.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := httptest.NewServer(api.NewServer(store).Handler())
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
