package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

func TestLoadOrCreatePersistsCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")

	a, err := identity.LoadOrCreate(dir, "omega.local")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	bundleA := a.BundlePEM()

	b, err := identity.LoadOrCreate(dir, "omega.local")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(bundleA) != string(b.BundlePEM()) {
		t.Fatal("bundle changed across reload — CA was not persisted")
	}
}

func TestIssueSVIDValidates(t *testing.T) {
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "ca"), "omega.local")
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}

	id, err := spiffeid.FromString("spiffe://omega.local/example/web")
	if err != nil {
		t.Fatalf("spiffeid: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen workload key: %v", err)
	}

	svid, err := a.IssueSVID(id, &key.PublicKey)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	block, _ := pem.Decode(svid.CertPEM)
	if block == nil {
		t.Fatal("svid cert pem decode failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse svid: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != id.String() {
		t.Errorf("svid URI SAN: got %v want [%s]", cert.URIs, id.String())
	}
	if cert.IsCA {
		t.Error("svid should not be a CA")
	}
	if time.Until(cert.NotAfter) > 31*time.Minute {
		t.Errorf("svid validity too long: %s", cert.NotAfter)
	}
	if cert.Subject.CommonName != id.String() {
		t.Errorf("subject CN: got %q want %q", cert.Subject.CommonName, id.String())
	}

	caBlock, _ := pem.Decode(svid.BundlePEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("svid does not chain to ca: %v", err)
	}
}

func TestIssueSVIDRejectsForeignTrustDomain(t *testing.T) {
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "ca"), "omega.local")
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	other, _ := spiffeid.FromString("spiffe://other.example/foo")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := a.IssueSVID(other, &key.PublicKey); err == nil {
		t.Fatal("expected error for foreign trust domain")
	}
}
