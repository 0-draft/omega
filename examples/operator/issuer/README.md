# Omega cert-manager external Issuer

This example shows cert-manager handing CertificateRequest signing off
to Omega via the `OmegaClusterIssuer` external Issuer. Apply a
cert-manager `Certificate`, get a SPIFFE-bound X.509 SVID delivered as
a Kubernetes Secret without writing CSR-handling glue.

The Issuer is implemented on top of
[cert-manager/issuer-lib](https://github.com/cert-manager/issuer-lib)
so the cert-manager API surface (CertificateRequest approval, retry
budget, status conditions, Kubernetes events) is identical to any
in-tree issuer.

## Wire diagram

```text
kubectl apply -f certificate.yaml
        |
        v
+---------------+   CertificateRequest    +-----------------+
| cert-manager  | ----------------------> | omega operator  |
| (controllers) | <-------- status ------ | (issuer-lib)    |
+---------------+   .status.certificate   +-----------------+
        |                                          |
        v                                          v
   Secret/web-tls                          POST /v1/svid
  tls.crt/tls.key/ca.crt              +----------------------+
                                      | omega server         |
                                      | (control plane)      |
                                      +----------------------+
```

The operator extracts the SPIFFE ID from the CSR's first `spiffe://`
URI SAN - set `Certificate.spec.uris: ["spiffe://..."]` and the rest
flows through unchanged. cert-manager's
[csi-driver-spiffe](https://github.com/cert-manager/csi-driver-spiffe)
forms CSRs the same way, so the same Issuer signs SPIFFE-bound CSI
volume requests with no additional code.

## End-to-end on kind

```bash
# 0. Tools required: kind, kubectl, helm, omega (this repo's binary).

# 1. Bring up a kind cluster and install cert-manager + Omega CRDs.
kind create cluster --name omega-issuer
helm repo add jetstack https://charts.jetstack.io --force-update
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true --wait

kubectl apply -f ../../../charts/omega/crds/omegadomain.yaml
kubectl apply -f ../../../charts/omega/crds/omegaissuer.yaml

# 1a. Grant cert-manager's auto-approver permission to approve
#     CertificateRequests aimed at our group. Without this, the
#     CertificateRequest sits forever with no Approved condition.
kubectl apply -f approver-rbac.yaml

# 2. Run the Omega control plane on the host (port 18088 keeps it out
#    of the way of any local omega-server). Leave running.
omega server --http-addr 127.0.0.1:18088 --data-dir /tmp/omega-issuer-demo

# 3. Run the operator pointing at the host control plane.
#    On Docker Desktop / OrbStack, host.docker.internal resolves the
#    host from inside the kind container. On Linux kind, replace the
#    URL with your host's bridge IP (`hostname -I | awk '{print $1}'`).
omega operator --omega-url=http://127.0.0.1:18088 \
  --metrics-addr=:18181 --health-addr=:18182

# 4. Apply: domain, ClusterIssuer, Certificate. Order matters.
kubectl apply -f domain.yaml
kubectl apply -f clusterissuer.yaml
kubectl apply -f certificate.yaml
```

## Verify

```bash
# Issuer reaches Ready=True after the first /v1/bundle Check.
kubectl get omegaclusterissuer
# NAME    URL                       READY   REASON    AGE
# omega   http://127.0.0.1:18088    True    Checked   5s

# Certificate reaches Ready=True a moment after the issuer is ready.
kubectl get certificate
# NAME   READY   SECRET    AGE
# web    True    web-tls   8s

# Read the SVID PEM out of the Secret and inspect the SPIFFE ID.
kubectl get secret web-tls -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
#     X509v3 Subject Alternative Name:
#         URI:spiffe://omega.local/example/web
```

## Going to production

The example uses a host-bound Omega control plane and an out-of-cluster
operator. Production deployments add three things:

- **In-cluster Omega server** behind a Service. Replace `clusterissuer.yaml`'s
  URL with `http://omega-server.omega-system.svc:8080`.
- **mTLS to the control plane.** A planned follow-up will mount a
  workload SVID into the operator pod and verify the server cert
  against the trust bundle. Until then, restrict `/v1/svid` to a
  private NetworkPolicy.
- **One Issuer per tenant namespace.** `OmegaIssuer` (Namespaced)
  scopes signing rights to a single namespace; `OmegaClusterIssuer`
  is for shared platforms where every namespace is allowed to ask for
  identities under the same trust domain.

## Known limitations

- The Issuer trusts whatever SPIFFE ID is in the CSR's URI SAN. There
  is no policy hook yet to gate which namespace can mint which SPIFFE
  ID - the control plane will sign anything that parses. A planned
  follow-up introduces a Cedar-evaluated namespace-to-SPIFFE-ID policy.
- Only `Certificate.spec.uris` is honored as a SPIFFE source.
  `commonName` is **not** parsed for SPIFFE IDs because cert-manager
  doesn't put CN-derived values in the CSR's URI SAN.
- Kubernetes `CertificateSigningRequest` works (issuer-lib enables it
  by default) but is not exercised by this example.
