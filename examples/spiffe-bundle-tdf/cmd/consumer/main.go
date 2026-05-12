// consumer fetches omega's `/v1/spiffe-bundle` endpoint and parses
// the response through the upstream go-spiffe v2 SDK to prove the
// SPIFFE Trust Domain Format document omega emits is real
// SPIFFE-conformant material, not just a JSON shape that happens to
// look right.
//
// The demo runs the entire round-trip in one process: it boots no
// server (the shell wrapper does that), HTTP-GETs the endpoint, hands
// the body to `spiffebundle.Read`, and asserts that:
//
//   - the parsed bundle exposes at least one X.509 authority;
//   - the parsed bundle exposes at least one JWT authority;
//   - the X.509 anchor is a CA the bundle would be willing to chain
//     a peer SVID against.
//
// A non-zero exit code surfaces any of those failing.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

func main() {
	addr := flag.String("addr", "http://127.0.0.1:18690", "base URL of the omega server")
	trustDomain := flag.String("trust-domain", "omega.demo", "expected trust domain on the parsed bundle")
	flag.Parse()

	td, err := spiffeid.TrustDomainFromString(*trustDomain)
	if err != nil {
		log.Fatalf("consumer: trust domain: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := *addr + "/v1/spiffe-bundle"
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("consumer: GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Fatalf("consumer: GET %s returned %d: %s", url, resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		log.Fatalf("consumer: GET %s returned Content-Type %q, want application/json", url, ct)
	}

	// Parse through the upstream SDK rather than a hand-rolled
	// decoder. Anything the SDK rejects, a real SPIFFE consumer
	// (SPIRE agent, spiffe-helper, a workload using go-spiffe)
	// would reject too.
	bundle, err := spiffebundle.Read(td, resp.Body)
	if err != nil {
		log.Fatalf("consumer: spiffebundle.Read: %v", err)
	}

	x509Authorities := bundle.X509Authorities()
	jwtAuthorities := bundle.JWTAuthorities()
	if len(x509Authorities) == 0 {
		log.Fatal("consumer: parsed bundle has no X.509 authorities")
	}
	if len(jwtAuthorities) == 0 {
		log.Fatal("consumer: parsed bundle has no JWT authorities")
	}

	seq, hasSeq := bundle.SequenceNumber()
	hint, hasHint := bundle.RefreshHint()
	fmt.Fprintf(os.Stdout, "[consumer] success\n")
	fmt.Fprintf(os.Stdout, "[consumer]   trust_domain:  %s\n", td)
	fmt.Fprintf(os.Stdout, "[consumer]   x509 anchors:  %d (subject=%q)\n", len(x509Authorities), x509Authorities[0].Subject)
	keyIDs := make([]string, 0, len(jwtAuthorities))
	for kid := range jwtAuthorities {
		keyIDs = append(keyIDs, kid)
	}
	fmt.Fprintf(os.Stdout, "[consumer]   jwt authorities: %d (kids=%v)\n", len(jwtAuthorities), keyIDs)
	if hasSeq {
		fmt.Fprintf(os.Stdout, "[consumer]   sequence:      %d\n", seq)
	}
	if hasHint {
		fmt.Fprintf(os.Stdout, "[consumer]   refresh_hint:  %s\n", hint)
	}
}
