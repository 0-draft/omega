import type { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const target = () => process.env.OMEGA_API ?? "http://127.0.0.1:8080";

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const url = `${target()}/${path.join("/")}${req.nextUrl.search}`;

  const init: RequestInit & { duplex?: "half" } = {
    method: req.method,
    headers: stripHopByHop(req.headers),
    cache: "no-store",
    redirect: "manual",
  };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await req.arrayBuffer();
  }

  try {
    const upstream = await fetch(url, init);
    return new Response(upstream.body, {
      status: upstream.status,
      headers: stripHopByHop(upstream.headers),
    });
  } catch (err) {
    return new Response(`upstream unreachable: ${target()} (${(err as Error).message})`, {
      status: 502,
      headers: { "content-type": "text/plain" },
    });
  }
}

function stripHopByHop(src: Headers): Headers {
  const out = new Headers();
  src.forEach((value, key) => {
    if (!HOP_BY_HOP.has(key.toLowerCase())) out.set(key, value);
  });
  return out;
}

export {
  proxy as GET,
  proxy as POST,
  proxy as PUT,
  proxy as DELETE,
  proxy as PATCH,
  proxy as HEAD,
  proxy as OPTIONS,
};
