// federation/check fetches the X.509 trust bundle map from a local
// Omega agent's Workload API socket and prints every trust domain plus
// the SHA-256 fingerprint of its root cert. The federation example uses
// it to prove that an agent in trust domain alpha is actually serving
// trust domain beta's bundle (and vice versa).
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	socket := flag.String("socket", "/tmp/omega-agent.sock", "Workload API unix socket")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+*socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	set, err := client.FetchX509Bundles(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fetch: %v\n", err)
		os.Exit(1)
	}
	bundles := set.Bundles()
	names := make([]string, 0, len(bundles))
	for _, b := range bundles {
		names = append(names, b.TrustDomain().Name())
	}
	sort.Strings(names)
	for _, n := range names {
		for _, b := range bundles {
			if b.TrustDomain().Name() != n {
				continue
			}
			roots := b.X509Authorities()
			if len(roots) == 0 {
				fmt.Printf("%-16s no roots\n", n)
				continue
			}
			sum := sha256.Sum256(roots[0].Raw)
			fmt.Printf("%-16s sha256=%s\n", n, hex.EncodeToString(sum[:]))
		}
	}
}
