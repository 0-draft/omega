// Anyone (including the anonymous default subject the adapter assigns
// when the x-user header is absent) may GET /status/200. Demonstrates a
// resource-scoped permit independent of principal — typical pattern for
// health and liveness endpoints exposed through the proxy.
@id("allow-public-status")
permit (
  principal,
  action    == Action::"GET",
  resource  == HttpPath::"/status/200"
);
