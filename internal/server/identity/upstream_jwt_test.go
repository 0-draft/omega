package identity_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

// upstreamAuthority stands in for an external SPIRE / Istio trust domain: a
// real issuing authority whose X.509 bundle, JWKS, and minted JWT-SVIDs we
// hand to omega's non-issuing upstream source.
func upstreamAuthority(t *testing.T, td string) identity.Authority {
	t.Helper()
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "upstream-ca"), td)
	if err != nil {
		t.Fatalf("upstream authority: %v", err)
	}
	return a
}

func TestUpstreamSourceValidatesUpstreamJWTSVID(t *testing.T) {
	const td = "upstream.example"
	up := upstreamAuthority(t, td)
	jwks, err := up.JWTBundle()
	if err != nil {
		t.Fatalf("upstream JWTBundle: %v", err)
	}

	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}

	// JWTBundle now serves the upstream signing keys, not the empty JWKS.
	served, err := src.JWTBundle()
	if err != nil {
		t.Fatalf("src.JWTBundle: %v", err)
	}
	if keyCount(t, served) == 0 {
		t.Fatal("upstream source served an empty JWKS; expected the upstream signing key")
	}

	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, err := up.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("upstream issue: %v", err)
	}

	got, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com")
	if err != nil {
		t.Fatalf("ValidateJWTSVID: %v", err)
	}
	if got.String() != id.String() {
		t.Fatalf("sub = %q, want %q", got, id)
	}

	// ParseJWTSVIDClaims returns the subject and the raw claims without an
	// audience requirement.
	pid, claims, err := src.ParseJWTSVIDClaims(svid.Token)
	if err != nil {
		t.Fatalf("ParseJWTSVIDClaims: %v", err)
	}
	if pid.String() != id.String() {
		t.Fatalf("parsed sub = %q, want %q", pid, id)
	}
	if claims["sub"] != id.String() {
		t.Fatalf("claims sub = %v, want %q", claims["sub"], id)
	}
}

func TestUpstreamSourceRejectsWrongAudience(t *testing.T) {
	const td = "upstream.example"
	up := upstreamAuthority(t, td)
	jwks, _ := up.JWTBundle()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, _ := up.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)

	if _, err := src.ValidateJWTSVID(svid.Token, "https://other.example.com"); err == nil {
		t.Fatal("expected validation to fail on a mismatched audience")
	}
}

func TestUpstreamSourceRejectsUnknownSigner(t *testing.T) {
	const td = "upstream.example"
	trusted := upstreamAuthority(t, td)
	jwks, _ := trusted.JWTBundle()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", trusted.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}

	// A different authority for the same trust domain: same sub, different
	// signing key, so its kid is absent from the served JWKS.
	rogue := upstreamAuthority(t, td)
	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, _ := rogue.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)

	if _, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com"); err == nil {
		t.Fatal("expected validation to fail for a token signed by an unknown key")
	}
}

func TestUpstreamSourceRejectsSubjectOutsideTrustDomain(t *testing.T) {
	// The source's trust domain differs from the issuing authority's, so a
	// validly-signed token's subject is not a member of the source's domain.
	const issuerTD = "issuer.example"
	up := upstreamAuthority(t, issuerTD)
	jwks, _ := up.JWTBundle()
	src, err := identity.NewUpstreamSourceWithJWT("other.example", "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://" + issuerTD + "/workload/web")
	svid, _ := up.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)

	if _, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com"); err == nil {
		t.Fatal("expected validation to fail for a subject outside the source trust domain")
	}
}

func TestNewUpstreamSourceWithJWTRejectsBadJWKS(t *testing.T) {
	bundle := upstreamBundle(t)

	cases := map[string][]byte{
		"not json":        []byte("{not json"),
		"no usable keys":  []byte(`{"keys":[]}`),
		"unsupported kty": []byte(`{"keys":[{"kty":"RSA","kid":"a","n":"x","e":"AQAB"}]}`),
		"missing kid":     []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`),
		"bad coordinate":  []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"!!","y":"!!"}]}`),
		"off curve":       []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`),
	}
	for name, jwks := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := identity.NewUpstreamSourceWithJWT("upstream.example", "", bundle, jwks); err == nil {
				t.Fatalf("expected error for %s JWKS", name)
			}
		})
	}
}

func TestUpstreamSourceWithoutJWTServesEmptyJWKS(t *testing.T) {
	src, err := identity.NewUpstreamSource("upstream.example", "", upstreamBundle(t))
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}
	jwks, err := src.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	if keyCount(t, jwks) != 0 {
		t.Fatalf("X.509-only source served %d keys, want empty JWKS", keyCount(t, jwks))
	}
	if _, err := src.ValidateJWTSVID("token", "aud"); !errors.Is(err, identity.ErrUpstreamJWTNotConfigured) {
		t.Fatalf("ValidateJWTSVID err = %v, want ErrUpstreamJWTNotConfigured", err)
	}
}

func keyCount(t *testing.T, jwks []byte) int {
	t.Helper()
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatalf("parse served JWKS: %v", err)
	}
	return len(set.Keys)
}
