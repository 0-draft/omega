// receiver is a tiny webhook sink for the audit-siem example. It
// listens for POSTed audit batches from omega server, optionally
// verifies the HMAC-SHA256 signature header, and appends every event
// to a JSONL file (and stdout) so the demo script can grep for
// expected decisions.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const signatureHeader = "X-Omega-Signature"

type batch struct {
	Events []json.RawMessage `json:"events"`
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18099", "listen address")
	secret := flag.String("secret", "", "shared HMAC secret; empty = signatures not required")
	out := flag.String("out", "", "append received events to this JSONL file (empty = stdout only)")
	flag.Parse()

	var sink io.Writer = os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("open out: %v", err)
		}
		defer f.Close()
		sink = io.MultiWriter(os.Stdout, f)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
			return
		}
		if *secret != "" {
			got := r.Header.Get(signatureHeader)
			if !validSignature(got, body, *secret) {
				log.Printf("reject: bad signature header=%q", got)
				http.Error(w, "bad signature", http.StatusUnauthorized)
				return
			}
		}
		var b batch
		if err := json.Unmarshal(body, &b); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		for _, e := range b.Events {
			fmt.Fprintln(sink, string(e))
		}
		log.Printf("delivered batch events=%d count_header=%s", len(b.Events), r.Header.Get("X-Omega-Event-Count"))
		w.WriteHeader(http.StatusNoContent)
	})

	log.Printf("listening on %s (signed=%t)", *addr, *secret != "")
	srv := &http.Server{Addr: *addr, Handler: mux}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func validSignature(header string, body []byte, secret string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	wantHex, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return subtle.ConstantTimeCompare(wantHex, mac.Sum(nil)) == 1
}
