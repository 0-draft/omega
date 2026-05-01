// authzen-adapter is the bridge that lets an Envoy ext_authz HTTP filter
// talk to Omega's OpenID AuthZEN 1.0 PDP endpoint.
//
// Wire format on the inbound side: Envoy posts the original request's
// method, path, and a configurable set of headers to /authz/<original
// path>. We extract the principal from a header (default x-user) so the
// example stays decoupled from any specific identity source - in
// production this is set by Envoy from the client X.509-SVID SAN URI,
// from a verified JWT, or from session middleware.
//
// On the outbound side we issue an AuthZEN evaluation:
//
//	POST /access/v1/evaluation
//	{
//	  "subject":  {"type":"User","id":"alice"},
//	  "action":   {"name":"GET"},
//	  "resource": {"type":"HttpPath","id":"/get"}
//	}
//
// 200 → allow → return 200 to Envoy → upstream is reached.
// 403 → deny  → return 403 to Envoy → client gets 403.
//
// All logging is one structured slog line per decision so the demo's
// docker compose logs read cleanly.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultPathPrefix = "/authz"

type entity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type authzenRequest struct {
	Subject  entity         `json:"subject"`
	Action   map[string]any `json:"action"`
	Resource entity         `json:"resource"`
}

type authzenResponse struct {
	Decision bool     `json:"decision"`
	Reasons  []string `json:"reasons,omitempty"`
}

func main() {
	var (
		listen        = flag.String("listen", ":9000", "HTTP listen address")
		omegaURL      = flag.String("omega-url", "http://omega-server:8080", "Omega control plane base URL")
		pathPrefix    = flag.String("path-prefix", defaultPathPrefix, "Envoy ext_authz path_prefix to strip from incoming requests")
		userHeader    = flag.String("user-header", "x-user", "Header carrying the principal id; in production this is x-spiffe-id or similar")
		subjectType   = flag.String("subject-type", "User", "Cedar entity type for the subject")
		resourceType  = flag.String("resource-type", "HttpPath", "Cedar entity type for the resource")
		anonymousID   = flag.String("anonymous-id", "anonymous", "Subject id when the user header is absent")
		clientTimeout = flag.Duration("omega-timeout", 2*time.Second, "Timeout for AuthZEN PDP calls")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	httpClient := &http.Client{Timeout: *clientTimeout}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		method := r.Method
		path := strings.TrimPrefix(r.URL.Path, *pathPrefix)
		if path == "" {
			path = "/"
		}

		subjectID := r.Header.Get(*userHeader)
		if subjectID == "" {
			subjectID = *anonymousID
		}

		req := authzenRequest{
			Subject:  entity{Type: *subjectType, ID: subjectID},
			Action:   map[string]any{"name": method},
			Resource: entity{Type: *resourceType, ID: path},
		}
		body, err := json.Marshal(req)
		if err != nil {
			logger.Error("marshal authzen request", "err", err)
			http.Error(w, "adapter error", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), *clientTimeout)
		defer cancel()
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, *omegaURL+"/access/v1/evaluation", bytes.NewReader(body))
		if err != nil {
			logger.Error("build pdp request", "err", err)
			http.Error(w, "adapter error", http.StatusInternalServerError)
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			logger.Error("pdp call failed", "err", err, "subject", subjectID, "method", method, "path", path)
			http.Error(w, "pdp unreachable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			logger.Error("pdp non-200", "status", resp.StatusCode, "body", string(raw))
			http.Error(w, "pdp error", http.StatusBadGateway)
			return
		}

		var dec authzenResponse
		if err := json.Unmarshal(raw, &dec); err != nil {
			logger.Error("decode pdp response", "err", err, "body", string(raw))
			http.Error(w, "pdp protocol error", http.StatusBadGateway)
			return
		}

		decision := "deny"
		statusCode := http.StatusForbidden
		if dec.Decision {
			decision = "allow"
			statusCode = http.StatusOK
		}
		logger.Info("decision",
			"decision", decision,
			"subject", subjectID,
			"method", method,
			"path", path,
			"reasons", dec.Reasons,
			"pdp_latency_ms", time.Since(start).Milliseconds(),
		)
		w.WriteHeader(statusCode)
	})

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "authzen-adapter listening on %s, omega=%s, path_prefix=%s, user_header=%s\n",
		*listen, *omegaURL, *pathPrefix, *userHeader)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("http server", "err", err)
		os.Exit(1)
	}
}
