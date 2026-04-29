// Package policy is the Omega Policy Decision Point.
//
// It wraps cedar-go to evaluate AuthZEN-style {subject, action, resource,
// context} requests against a Cedar policy set. Policies are loaded from
// a directory of .cedar files at startup; an optional entities.json in
// the same directory seeds the entity store with parents/attrs.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	cedar "github.com/cedar-policy/cedar-go"
)

// Engine holds a Cedar PolicySet plus the static entity map. It is safe
// for concurrent Evaluate calls; Reload swaps the underlying state under
// a write lock.
type Engine struct {
	mu       sync.RWMutex
	policies *cedar.PolicySet
	entities cedar.EntityMap
}

// New returns an Engine with an empty policy set and no entities. A
// request against an empty engine will always evaluate to deny, matching
// Cedar's default-deny semantics.
func New() *Engine {
	return &Engine{
		policies: cedar.NewPolicySet(),
		entities: cedar.EntityMap{},
	}
}

// LoadDir reads every *.cedar file in dir as a Cedar policy and, if
// present, dir/entities.json as the entity map. The two are swapped in
// atomically; on error the engine is left untouched.
func (e *Engine) LoadDir(dir string) error {
	ps, ents, err := loadFromDir(dir)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.policies = ps
	e.entities = ents
	e.mu.Unlock()
	return nil
}

func loadFromDir(dir string) (*cedar.PolicySet, cedar.EntityMap, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.cedar"))
	if err != nil {
		return nil, nil, fmt.Errorf("glob policies: %w", err)
	}
	sort.Strings(matches)

	ps := cedar.NewPolicySet()
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}
		fileSet, err := cedar.NewPolicySetFromBytes(filepath.Base(path), raw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for id, p := range fileSet.All() {
			if !ps.Add(id, p) {
				return nil, nil, fmt.Errorf("duplicate policy id %q (defined again in %s)", id, path)
			}
		}
	}

	ents := cedar.EntityMap{}
	entPath := filepath.Join(dir, "entities.json")
	if raw, err := os.ReadFile(entPath); err == nil {
		if err := json.Unmarshal(raw, &ents); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", entPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read %s: %w", entPath, err)
	}

	return ps, ents, nil
}

// Entity is the on-the-wire form of an AuthZEN subject/resource: a typed
// id pair plus optional free-form attributes. Action carries only Name
// (mapped to Cedar's Action::"name") and is represented separately.
type Entity struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	Attrs map[string]any `json:"properties,omitempty"`
}

type Action struct {
	Name string `json:"name"`
}

// EvalRequest mirrors the AuthZEN PDP API evaluation request shape.
type EvalRequest struct {
	Subject  Entity         `json:"subject"`
	Action   Action         `json:"action"`
	Resource Entity         `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvalResponse is the AuthZEN decision response. We omit the optional
// `context` field for the PoC.
type EvalResponse struct {
	Decision bool     `json:"decision"`
	Reasons  []string `json:"reasons,omitempty"`
}

// Evaluate runs the request through the policy set and returns the
// AuthZEN decision. Missing subject/resource type or id is treated as a
// validation error rather than a silent deny.
func (e *Engine) Evaluate(req EvalRequest) (EvalResponse, error) {
	if err := validate(req); err != nil {
		return EvalResponse{}, err
	}

	cedarReq := cedar.Request{
		Principal: cedar.NewEntityUID(cedar.EntityType(req.Subject.Type), cedar.String(req.Subject.ID)),
		Action:    cedar.NewEntityUID("Action", cedar.String(req.Action.Name)),
		Resource:  cedar.NewEntityUID(cedar.EntityType(req.Resource.Type), cedar.String(req.Resource.ID)),
		Context:   recordFromMap(req.Context),
	}

	e.mu.RLock()
	ps := e.policies
	ents := e.entities
	e.mu.RUnlock()

	ok, diag := cedar.Authorize(ps, ents, cedarReq)
	resp := EvalResponse{Decision: bool(ok)}
	for _, r := range diag.Reasons {
		resp.Reasons = append(resp.Reasons, string(r.PolicyID))
	}
	return resp, nil
}

func validate(r EvalRequest) error {
	switch {
	case strings.TrimSpace(r.Subject.Type) == "" || strings.TrimSpace(r.Subject.ID) == "":
		return fmt.Errorf("subject.type and subject.id are required")
	case strings.TrimSpace(r.Action.Name) == "":
		return fmt.Errorf("action.name is required")
	case strings.TrimSpace(r.Resource.Type) == "" || strings.TrimSpace(r.Resource.ID) == "":
		return fmt.Errorf("resource.type and resource.id are required")
	}
	return nil
}

// recordFromMap converts a JSON-decoded context map into a Cedar Record.
// Only the JSON primitive shapes are bridged; nested arrays/objects fall
// through as Cedar strings of their JSON representation, which keeps the
// PoC honest without pretending to support full Cedar value translation.
func recordFromMap(m map[string]any) cedar.Record {
	if len(m) == 0 {
		return cedar.NewRecord(cedar.RecordMap{})
	}
	out := cedar.RecordMap{}
	for k, v := range m {
		out[cedar.String(k)] = valueOf(v)
	}
	return cedar.NewRecord(out)
}

func valueOf(v any) cedar.Value {
	switch x := v.(type) {
	case nil:
		return cedar.String("")
	case bool:
		if x {
			return cedar.True
		}
		return cedar.False
	case string:
		return cedar.String(x)
	case float64:
		return cedar.Long(int64(x))
	default:
		raw, _ := json.Marshal(x)
		return cedar.String(string(raw))
	}
}
