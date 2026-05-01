// client orchestrates the human -> agent -> sub-agent delegation
// chain end-to-end against an Omega control plane:
//
//  1. mints a JWT-SVID for the human (acting as an OIDC IdP would),
//  2. mints a JWT-SVID for the coordinator agent,
//  3. mints a JWT-SVID for the sub-agent that will call the tool,
//  4. runs hop 1: token-exchange(subject=human,  actor=coord) -> t1,
//  5. runs hop 2: token-exchange(subject=t1,     actor=sub)   -> t2,
//  6. calls the tool-server with t2 as a Bearer token,
//  7. prints the JSON the tool-server echoed back.
//
// The exit code is 0 on success and 1 on any policy / transport
// failure, so the wrapping shell script can assert against it.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

func main() {
	var (
		omegaURL = flag.String("omega-url", "http://127.0.0.1:18097", "Omega control plane base URL")
		toolURL  = flag.String("tool-url", "http://127.0.0.1:19000/tool/issues", "tool-server endpoint")
		human    = flag.String("human", "spiffe://omega.local/humans/alice", "root human SPIFFE ID")
		coord    = flag.String("coordinator", "spiffe://omega.local/agents/claude-code", "coordinator agent SPIFFE ID")
		sub      = flag.String("sub-agent", "spiffe://omega.local/agents/claude-code/github-tool", "sub-agent SPIFFE ID")
		toolAud  = flag.String("tool-audience", "mcp://github-issue", "audience requested for the tool-call token")
	)
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("[client] ")

	humanTok := mustIssueJWT(*omegaURL, *human, []string{"omega-internal"}, 600)
	log.Printf("minted human JWT-SVID  sub=%s", *human)

	coordTok := mustIssueJWT(*omegaURL, *coord, []string{"omega-internal"}, 600)
	log.Printf("minted coord JWT-SVID  sub=%s", *coord)

	subTok := mustIssueJWT(*omegaURL, *sub, []string{"omega-internal"}, 600)
	log.Printf("minted sub   JWT-SVID  sub=%s", *sub)

	hop1, err := exchange(*omegaURL, exchangeReq{
		SubjectToken:      humanTok,
		ActorToken:        coordTok,
		RequestedSPIFFEID: *coord,
		Audience:          []string{"omega-internal"},
		TTLSeconds:        300,
	})
	if err != nil {
		fail("hop1 (human->coord) failed: %v", err)
	}
	log.Printf("hop 1: chain=%v sub=%s", hop1.DelegationChain, hop1.SPIFFEID)

	hop2, err := exchange(*omegaURL, exchangeReq{
		SubjectToken:      hop1.AccessToken,
		ActorToken:        subTok,
		RequestedSPIFFEID: *sub,
		Audience:          []string{*toolAud},
		TTLSeconds:        300,
	})
	if err != nil {
		fail("hop2 (coord->sub) failed: %v", err)
	}
	log.Printf("hop 2: chain=%v sub=%s", hop2.DelegationChain, hop2.SPIFFEID)

	body, err := callTool(*toolURL, hop2.AccessToken)
	if err != nil {
		fail("tool call failed: %v", err)
	}

	// The shell wrapper greps stdout for these markers, so they are
	// part of the API of this binary. Don't reword without updating
	// run-demo.sh.
	fmt.Println("[result] tool-server echoed:")
	fmt.Println(string(body))
}

func fail(format string, args ...any) {
	log.Printf("FAIL: "+format, args...)
	os.Exit(1)
}

func mustIssueJWT(omegaURL, spiffeID string, audience []string, ttl int) string {
	body, _ := json.Marshal(map[string]any{
		"spiffe_id":   spiffeID,
		"audience":    audience,
		"ttl_seconds": ttl,
	})
	resp, err := http.Post(omegaURL+"/v1/svid/jwt", "application/json", bytes.NewReader(body))
	if err != nil {
		fail("issue JWT-SVID for %s: %v", spiffeID, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fail("issue JWT-SVID for %s: status %d body=%s", spiffeID, resp.StatusCode, raw)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		fail("decode JWT-SVID response: %v body=%s", err, raw)
	}
	return out.Token
}

type exchangeReq struct {
	SubjectToken      string
	ActorToken        string
	RequestedSPIFFEID string
	Audience          []string
	TTLSeconds        int
}

type exchangeResp struct {
	AccessToken     string   `json:"access_token"`
	SPIFFEID        string   `json:"spiffe_id"`
	Audience        []string `json:"audience"`
	DelegationChain []string `json:"delegation_chain"`
	ExpiresIn       int      `json:"expires_in"`
}

func exchange(omegaURL string, r exchangeReq) (exchangeResp, error) {
	body, _ := json.Marshal(map[string]any{
		"grant_type":          grantTypeTokenExchange,
		"subject_token":       r.SubjectToken,
		"subject_token_type":  tokenTypeJWT,
		"actor_token":         r.ActorToken,
		"actor_token_type":    tokenTypeJWT,
		"requested_spiffe_id": r.RequestedSPIFFEID,
		"audience":            r.Audience,
		"ttl_seconds":         r.TTLSeconds,
	})
	httpReq, _ := http.NewRequest(http.MethodPost, omegaURL+"/v1/token/exchange", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return exchangeResp{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return exchangeResp{}, fmt.Errorf("status %d body=%s", resp.StatusCode, raw)
	}
	var out exchangeResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return exchangeResp{}, fmt.Errorf("decode: %w body=%s", err, raw)
	}
	return out, nil
}

func callTool(toolURL, bearer string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, toolURL, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return raw, fmt.Errorf("tool status %d", resp.StatusCode)
	}
	return raw, nil
}
