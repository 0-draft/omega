// Package identity owns the Raftel CA and SVID issuance.
//
// PoC v0.0.1 uses a single self-signed CA per data-dir, ECDSA P-256.
// HSM (PKCS#11) and KMS plugins land in v0.3 — the Authority struct is
// intentionally tied to crypto.Signer so we can swap in a remote signer.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	svidValidity = 30 * time.Minute
)

type Authority struct {
	trustDomain spiffeid.TrustDomain
	cert        *x509.Certificate
	key         crypto.Signer
	bundlePEM   []byte
}

func LoadOrCreate(dir, trustDomain string) (*Authority, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("trust domain: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca dir: %w", err)
	}
	keyPath := filepath.Join(dir, "ca.key")
	crtPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(keyPath); err == nil {
		return loadAuthority(td, keyPath, crtPath)
	}
	return createAuthority(td, keyPath, crtPath)
}

func createAuthority(td spiffeid.TrustDomain, keyPath, crtPath string) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Raftel Local CA"},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		return nil, err
	}
	return &Authority{trustDomain: td, cert: cert, key: key, bundlePEM: crtPEM}, nil
}

func loadAuthority(td spiffeid.TrustDomain, keyPath, crtPath string) (*Authority, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid CA key PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca key is not a crypto.Signer")
	}
	crtBlock, _ := pem.Decode(crtPEM)
	if crtBlock == nil {
		return nil, errors.New("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	return &Authority{trustDomain: td, cert: cert, key: signer, bundlePEM: crtPEM}, nil
}

func (a *Authority) TrustDomain() spiffeid.TrustDomain { return a.trustDomain }
func (a *Authority) BundlePEM() []byte                 { return a.bundlePEM }

type SVID struct {
	SPIFFEID  spiffeid.ID
	CertPEM   []byte
	BundlePEM []byte
	NotAfter  time.Time
}

// IssueSVID signs an X.509-SVID for id over the public key in pub.
// The SPIFFE ID must be a member of this authority's trust domain.
func (a *Authority) IssueSVID(id spiffeid.ID, pub crypto.PublicKey) (*SVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.String()},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(svidValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{idAsURL(id)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, pub, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign svid: %w", err)
	}
	return &SVID{
		SPIFFEID:  id,
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		BundlePEM: a.bundlePEM,
		NotAfter:  tpl.NotAfter,
	}, nil
}

func idAsURL(id spiffeid.ID) *url.URL {
	u, _ := url.Parse(id.String())
	return u
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	return rand.Int(rand.Reader, limit)
}
