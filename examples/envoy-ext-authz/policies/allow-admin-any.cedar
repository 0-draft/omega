// admin may perform any action on any resource. Demonstrates an
// unscoped permit — useful for break-glass / operator identities.
@id("allow-admin-any")
permit (
  principal == User::"admin",
  action,
  resource
);
