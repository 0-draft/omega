package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kanywst/omega/internal/server/policy"
)

const policyAllowWebGetAPI = `permit (
  principal == Spiffe::"spiffe://omega.local/example/web",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`

func writePolicies(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestEvaluateAllowAndDeny(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"allow.cedar": policyAllowWebGetAPI,
	})
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("load: %v", err)
	}

	allow, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/example/web"},
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/api/foo"},
	})
	if err != nil {
		t.Fatalf("evaluate allow: %v", err)
	}
	if !allow.Decision {
		t.Errorf("expected allow, got %+v", allow)
	}
	if len(allow.Reasons) == 0 {
		t.Errorf("expected at least one matching policy id in reasons")
	}

	deny, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/example/web"},
		Action:   policy.Action{Name: "DELETE"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/api/foo"},
	})
	if err != nil {
		t.Fatalf("evaluate deny: %v", err)
	}
	if deny.Decision {
		t.Errorf("expected deny on DELETE, got allow")
	}
}

func TestEmptyEngineDeniesEverything(t *testing.T) {
	e := policy.New()
	resp, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/example/web"},
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/api/foo"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Errorf("empty engine must deny by default")
	}
}

func TestValidateMissingFields(t *testing.T) {
	e := policy.New()
	if _, err := e.Evaluate(policy.EvalRequest{
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/x"},
	}); err == nil {
		t.Error("missing subject must error")
	}
	if _, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/x"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/x"},
	}); err == nil {
		t.Error("missing action must error")
	}
	if _, err := e.Evaluate(policy.EvalRequest{
		Subject: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/x"},
		Action:  policy.Action{Name: "GET"},
	}); err == nil {
		t.Error("missing resource must error")
	}
}

func TestLoadDirRejectsBadPolicy(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"bad.cedar": "this is not cedar syntax",
	})
	e := policy.New()
	if err := e.LoadDir(dir); err == nil {
		t.Error("expected error loading invalid cedar")
	}
}
