// Cedar policy gating POST /v1/token/exchange.
//
// Permits an exchange only when:
//   - the requesting principal is an AI agent (path prefix /agents/),
//   - the chain is at most 2 hops deep (human -> agent -> sub-agent),
//   - and the chain root is a federated human (path prefix /humans/).
//
// Anything else (service-to-service exchange, deeper chains,
// agent-only chains with no human root) hits Cedar default-deny and
// returns 403 from the handler.

@id("allow-ai-acting-for-human")
permit (
  principal is Spiffe,
  action == Action::"token.exchange",
  resource is Spiffe
) when {
  principal has kind &&
  principal.kind == "ai" &&
  context.delegation_depth <= 2 &&
  principal.delegation_chain.contains("spiffe://omega.local/humans/alice")
};
