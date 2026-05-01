/**
 * Typed client for the Omega control plane HTTP API.
 *
 * In dev, requests go to /api/omega/* which Next rewrites to OMEGA_API
 * (default http://127.0.0.1:8080). Keeps CORS out of the picture.
 */

import { z } from "zod";

const base = "/api/omega";

async function get<T>(path: string, schema: z.ZodSchema<T>): Promise<T> {
  const res = await fetch(`${base}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new OmegaError(res.status, `GET ${path} -> ${res.status}`);
  }
  return schema.parse(await res.json());
}

export class OmegaError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "OmegaError";
  }
}

export const Domain = z.object({
  name: z.string(),
  description: z.string().optional().default(""),
  created_at: z.string().optional(),
});
export type Domain = z.infer<typeof Domain>;

const DomainList = z.object({ items: z.array(Domain) });

export const AuditEvent = z.object({
  seq: z.number(),
  ts: z.string(),
  kind: z.string(),
  subject: z.string(),
  decision: z.string(),
  payload: z.unknown(),
  prev_hash: z.string().optional(),
  hash: z.string().optional(),
});
export type AuditEvent = z.infer<typeof AuditEvent>;

const AuditList = z.object({ items: z.array(AuditEvent) });

const AuditVerify = z.object({
  valid: z.boolean(),
  first_bad_seq: z.number().optional(),
});

export const omega = {
  health: () => fetch(`${base}/healthz`, { cache: "no-store" }).then((r) => r.ok),
  listDomains: () => get("/v1/domains", DomainList).then((d) => d.items),
  listAudit: (limit = 50) => get(`/v1/audit?limit=${limit}`, AuditList).then((d) => d.items),
  verifyAudit: () => get("/v1/audit/verify", AuditVerify),
  bundleUrl: () => `${base}/v1/bundle`,
  jwtBundleUrl: () => `${base}/v1/jwt/bundle`,
};
