# examples/spiffe-bundle-tdf

End-to-end demo that omega's `GET /v1/spiffe-bundle` endpoint emits a
SPIFFE Trust Domain Format (TDF) document the upstream `go-spiffe v2`
SDK consumes without any glue code. Closes the interop story for the
`/v1/spiffe-bundle` endpoint shipped in the SPIFFE TDF PR: a
regression that breaks the on-the-wire shape trips the SDK parser
instead of silently working against a permissive hand-rolled decoder.

`make demo`:

1. boots `omega server` with `--spiffe-bundle-refresh-hint 180s` so
   the response carries a non-default `spiffe_refresh_hint`;
2. builds and runs a tiny `cmd/consumer` Go binary that
   - HTTP-GETs `/v1/spiffe-bundle`,
   - hands the body to `spiffebundle.Read(td, body)` from
     `github.com/spiffe/go-spiffe/v2/bundle/spiffebundle`,
   - asserts both `X509Authorities()` and `JWTAuthorities()` are
     non-empty,
   - prints the parsed `SequenceNumber` and `RefreshHint`;
3. dumps the first 200 chars of the raw response so the demo
   output is self-documenting.

Sample success output:

```text
[consumer] success
[consumer]   trust_domain:  omega.demo
[consumer]   x509 anchors:  1 (subject="CN=Omega Local CA")
[consumer]   jwt authorities: 1 (kids=[BA0vwLDU7Bs])
[consumer]   sequence:      1
[consumer]   refresh_hint:  3m0s
```

## Run

```text
make demo
```

The script tears itself down on exit; force a manual cleanup:

```text
make down
```

## Requirements

- Go (for the consumer build; the same go.mod that powers omega
  itself supplies `go-spiffe v2`).
- `omega` on `$PATH` (the repo `make build` puts it under `./bin`;
  the parent CI matrix exports that path for the demo).
- `curl`.

## What this demo is not

This is an interop check, not a conformance certificate. It proves
the SDK accepts the document end-to-end. The conformance row in
`docs/conformance-spiffe.md` §4.1 covers the field-by-field claim.
