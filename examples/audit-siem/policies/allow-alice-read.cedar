// alice may read any Doc. Used by the audit-siem demo to drive
// AuthZEN evaluations whose decisions are captured in the audit
// chain and forwarded to the webhook receiver.
@id("allow-alice-read")
permit (
  principal == User::"alice",
  action    == Action::"read",
  resource
);
