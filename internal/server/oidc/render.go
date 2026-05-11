package oidc

import (
	"errors"
	"fmt"
	"strings"
)

// RenderSPIFFEID interpolates the placeholders {sub}, {idp}, {email},
// {preferred_username}, {name} in template using values from c. A
// placeholder that resolves to an empty string is a hard error so a
// misconfigured template fails fast instead of producing a SPIFFE ID
// with an empty path segment.
//
// Result is intentionally NOT URL-escaped: the caller (api package)
// passes the rendered string into spiffeid.FromString, which is the
// canonical validator. Operators are responsible for choosing
// placeholders whose values are SPIFFE-path-safe (no `/` in `email`
// is the most common gotcha; `preferred_username` is usually a good
// pick).
func RenderSPIFFEID(template string, c *Claims) (string, error) {
	if c == nil {
		return "", errors.New("oidc: claims are nil")
	}
	subs := map[string]string{
		"{sub}":                c.Subject,
		"{idp}":                c.IdPName,
		"{email}":              c.Email,
		"{preferred_username}": c.PreferredUN,
		"{name}":               c.Name,
	}
	out := template
	for k, v := range subs {
		if !strings.Contains(out, k) {
			continue
		}
		if v == "" {
			return "", fmt.Errorf("oidc: template uses %s but the claim is empty", k)
		}
		out = strings.ReplaceAll(out, k, v)
	}
	return out, nil
}
