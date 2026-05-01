// alice may GET any HttpPath. Demonstrates a per-subject permit
// scoped by HTTP method.
@id("allow-alice-get")
permit (
  principal == User::"alice",
  action    == Action::"GET",
  resource
);
