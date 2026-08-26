// Cloudflare Worker — reverse proxy for the two GitHub OAuth endpoints the
// ocserv-sso portal reaches server-side. See ../wrangler.toml for deploy
// instructions and security notes.

const UPSTREAM = "https://github.com";

// Only these paths may be proxied; anything else 404s so the Worker is not
// an open GitHub mirror.
const ALLOWED = new Set([
  "/login/device/code",
  "/login/oauth/access_token",
]);

// Hop-by-hop headers that must not be forwarded to/from the upstream.
const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
]);

function clientIP(request) {
  // Cloudflare connects the Worker to the visitor over CF's edge; the real
  // visitor IP is in CF-Connecting-IP.
  return request.headers.get("CF-Connecting-IP") || "";
}

function ipAllowed(request, env) {
  const allow = env.GITHUB_PROXY_ALLOW_IP && env.GITHUB_PROXY_ALLOW_IP.trim();
  if (!allow) return true; // no allowlist configured -> allow any
  const set = new Set(allow.split(",").map((s) => s.trim()).filter(Boolean));
  return set.has(clientIP(request));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (!ALLOWED.has(url.pathname)) {
      return new Response("Not Found", { status: 404 });
    }

    if (request.method !== "GET" && request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    if (!ipAllowed(request, env)) {
      return new Response("Forbidden", { status: 403 });
    }

    // Reconstruct the upstream URL, preserving the query string.
    const upstream = new URL(url.pathname + url.search, UPSTREAM);

    // Forward request headers minus hop-by-hop; let fetch set Host itself.
    const headers = new Headers();
    for (const [k, v] of request.headers.entries()) {
      if (!HOP_BY_HOP.has(k.toLowerCase())) headers.set(k, v);
    }
    // GitHub OAuth wants these.
    headers.set("Accept", "application/json");
    headers.set("User-Agent", "ocserv-sso-proxy-worker");

    const init = {
      method: request.method,
      headers,
    };
    if (request.method === "POST") {
      init.body = await request.text();
    }

    let upstreamResp;
    try {
      upstreamResp = await fetch(upstream, init);
    } catch (err) {
      return new Response(`upstream error: ${err.message}`, { status: 502 });
    }

    // Relay status + body; strip hop-by-hop response headers.
    const respHeaders = new Headers();
    for (const [k, v] of upstreamResp.headers.entries()) {
      if (!HOP_BY_HOP.has(k.toLowerCase())) respHeaders.set(k, v);
    }
    // CORS: allow the portal (loopback or same origin) to read the response.
    respHeaders.set("Access-Control-Allow-Origin", "*");

    return new Response(upstreamResp.body, {
      status: upstreamResp.status,
      headers: respHeaders,
    });
  },
};
