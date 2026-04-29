// hello-svid/client is the counterpart to hello-svid/server. It fetches
// its own X.509-SVID from the local Omega agent, calls the server with
// mTLS, and verifies that the server's SPIFFE ID matches an expected
// value.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	socket := flag.String("socket", "/tmp/omega-client.sock", "Omega agent Workload API socket")
	url := flag.String("url", "https://127.0.0.1:9443/", "server URL")
	expect := flag.String("expect-server-id", "spiffe://omega.local/hello/server", "expected server SPIFFE ID")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src, err := workloadapi.NewX509Source(ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+*socket)),
	)
	if err != nil {
		log.Fatalf("connect to agent %s: %v", *socket, err)
	}
	defer src.Close()

	svid, err := src.GetX509SVID()
	if err != nil {
		log.Fatalf("fetch svid: %v", err)
	}
	log.Printf("client SPIFFE ID: %s", svid.ID)

	expected, err := spiffeid.FromString(*expect)
	if err != nil {
		log.Fatalf("expect-server-id: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(expected)),
		},
	}

	resp, err := httpClient.Get(*url)
	if err != nil {
		log.Fatalf("get %s: %v", *url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	fmt.Print(string(body))
	if len(body) > 0 && body[len(body)-1] != '\n' {
		os.Stdout.Write([]byte("\n"))
	}
}
