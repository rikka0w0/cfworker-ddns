/** ===== Types ===== */
interface IpChoice {
  /** true=update record, false=keep existing */
  update: boolean;
  /** when update=true, true means the value came from CF-Connecting-IP */
  from_cf: boolean;
  /** IP string to write (required when update=true) */
  value?: string;
}

/** ===== Helpers ===== */
function pickAddress(rawParam: string | null, cfClientIp?: string): IpChoice {
  // Not provided: keep existing
  if (rawParam === null) return { update: false, from_cf: false };
  // Empty string: use CF-Connecting-IP (no platform-side autodetect!)
  if (rawParam === "") return { update: true, from_cf: true, value: cfClientIp };
  // Explicit value provided by user
  return { update: true, from_cf: false, value: rawParam };
}

function redactToken(t: string | null | undefined): string | null {
  if (!t) return t ?? null;
  const s = t.trim();
  if (s.length <= 6) return "***";
  return s.slice(0, 3) + "..." + s.slice(-3);
}

/** ===== Base64url & AES-GCM(v1) helpers ===== */
const te = new TextEncoder();
const td = new TextDecoder();

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function importAesKeyFromSecret(secret: string): Promise<CryptoKey> {
  // Derive a 256-bit key from the provided secret string
  const keyBytes = await crypto.subtle.digest("SHA-256", te.encode(secret));
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// ciphertext format: v1.<b64url(iv 12B)>.<b64url(ciphertext)>
async function encryptToken(masterSecret: string, raw: string): Promise<string> {
  const key = await importAesKeyFromSecret(masterSecret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(raw));
  return `v1.${b64urlEncode(iv)}.${b64urlEncode(new Uint8Array(ct))}`;
}
async function decryptToken(masterSecret: string, enc: string): Promise<string> {
  const [v, ivb64, ctb64] = enc.split(".");
  if (v !== "v1" || !ivb64 || !ctb64) throw new Error("bad token format");
  const key = await importAesKeyFromSecret(masterSecret);
  const iv = b64urlDecode(ivb64);
  const ct = b64urlDecode(ctb64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return td.decode(pt);
}

/** ===== DDNS Handler Registry ===== */
type DdnsHandlerResult = {
  ok: boolean;
  /** HTTP status code returned by provider (used to set Worker response status) */
  providerStatus?: number;
  /** Provider raw/body info for debugging */
  providerResponse?: unknown;
  /** Error summary when ok=false */
  error?: string;
};

type DdnsHandler = (
  domain: string,
  realDdnsToken: string,
  ipv4Choice: IpChoice,
  ipv6Choice: IpChoice
) => Promise<DdnsHandlerResult>;

/** ---- DuckDNS (no provider autodetect) ---- */
const duckdnsHandler: DdnsHandler = async (domain, realDdnsToken, ipv4Choice, ipv6Choice) => {
  const params = new URLSearchParams();
  params.set("domains", domain);
  params.set("token", realDdnsToken);
  params.set("verbose", "true");
  if (ipv4Choice.update) params.set("ip", ipv4Choice.value!);
  if (ipv6Choice.update) params.set("ipv6", ipv6Choice.value!);

  const url = "https://www.duckdns.org/update?" + params.toString();
  const resp = await fetch(url, { method: "GET" });
  const text = await resp.text();
  const ok = text.startsWith("OK");

  return {
    ok,
    providerStatus: resp.status,
    providerResponse: {
      provider: "duckdns",
      request: {
        domain,
        with_ip: ipv4Choice.update,
        with_ipv6: ipv6Choice.update,
        ip_value: ipv4Choice.update ? ipv4Choice.value : undefined,
        ipv6_value: ipv6Choice.update ? ipv6Choice.value : undefined,
        verbose: true,
      },
      response_text: text,
    },
    error: ok ? undefined : `duckdns: ${text.trim() || "request failed"}`,
  };
};

/** ---- deSEC (no provider autodetect) ----
 * API: GET https://update.dedyn.io/?hostname=<domain>[&myipv4=...][&myipv6=...]
 * Header: Authorization: Token <token>
 * If updating only one family, send the other as "preserve" to avoid overwrite.
 */
const desecHandler: DdnsHandler = async (domain, realDdnsToken, ipv4Choice, ipv6Choice) => {
  const qs = new URLSearchParams();
  qs.set("hostname", domain);

  const updatingV4 = ipv4Choice.update;
  const updatingV6 = ipv6Choice.update;

  if (updatingV4 && updatingV6) {
    qs.set("myipv4", ipv4Choice.value!);
    qs.set("myipv6", ipv6Choice.value!);
  } else if (updatingV4 && !updatingV6) {
    qs.set("myipv4", ipv4Choice.value!);
    qs.set("myipv6", "preserve");
  } else if (!updatingV4 && updatingV6) {
    qs.set("myipv4", "preserve");
    qs.set("myipv6", ipv6Choice.value!);
  }

  const url = "https://update.dedyn.io/?" + qs.toString();
  const resp = await fetch(url, {
    method: "GET",
    headers: { Authorization: `Token ${realDdnsToken}` },
  });
  const text = await resp.text();

  return {
    ok: resp.ok,
    providerStatus: resp.status,
    providerResponse: {
      provider: "desec",
      request: {
        domain,
        with_myipv4: updatingV4,
        with_myipv6: updatingV6,
        myipv4_value: updatingV4 ? ipv4Choice.value : "preserve",
        myipv6_value: updatingV6 ? ipv6Choice.value : "preserve",
      },
      response_text: text,
    },
    error: resp.ok ? undefined : `desec: ${text.trim() || "request failed"}`,
  };
};

/** ---- Registry ---- */
export const HANDLERS = {
  duckdns: duckdnsHandler,
  desec: desecHandler,
};

/** Derive Platform union type from registry keys */
export type Platform = keyof typeof HANDLERS;

/** Normalize platform from URL param using registry keys */
function normalizePlatform(raw: string | null): Platform | null {
  if (!raw) return null;
  const key = raw.toLowerCase().trim() as Platform;
  return key in HANDLERS ? key : null;
}

/** ===== Worker Entrypoint ===== */
export default {
  async fetch(request: Request, env: any): Promise<Response> {
    const url = new URL(request.url);
    const sp = url.searchParams;
    const pathname = url.pathname;

    // --- /encrypt: return encrypted token in plain text ---
    if (pathname === "/encrypt") {
      const raw = sp.get("token");
      if (!raw) {
        return new Response("missing token", {
          status: 400,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
      const master = env?.uuid;
      if (!master) {
        return new Response("missing uuid", {
          status: 500,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
      try {
        const enc = await encryptToken(master, raw);
        return new Response(enc, {
          status: 200,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      } catch (_e) {
        return new Response("encrypt failed", {
          status: 500,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
    }

    // --- /decrypt: return JSON { code, decrypted, msg? } ---
    if (pathname === "/decrypt") {
      const enc = sp.get("encrypted");
      const master = env?.uuid;

      if (!env?.allow_decrypt) {
        return new Response(
          "Please set enviromental variable allow_decrypt to true to enable this function",
          {
            status: 404,
            headers: { "content-type": "text/plain; charset=utf-8" },
          }
        );
      }

      if (!enc) {
        const body = { code: 400, decrypted: null, msg: "missing 'encrypted' param" };
        return new Response(JSON.stringify(body), {
          status: 400,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
      if (!master) {
        const body = { code: 500, decrypted: null, msg: "missing uuid" };
        return new Response(JSON.stringify(body), {
          status: 500,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
      try {
        const dec = await decryptToken(master, enc);
        const body = { code: 200, decrypted: dec };
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      } catch (_e) {
        const body = { code: 400, decrypted: null, msg: "invalid encrypted token" };
        return new Response(JSON.stringify(body), {
          status: 400,
          headers: { "content-type": "application/json; charset=utf-8" },
        });
      }
    }

    // --- /update: DDNS update (provider-agnostic parsing) ---
    if (pathname === "/update") {
      const platform = normalizePlatform(sp.get("platform"));
      const encToken = sp.get("token");          // encrypted token (from /encrypt)
      const domain = sp.get("domain")?.trim();    // Single domain (no suffix like .duckdns.org)
      const ipParam = sp.get("ip");               // IPv4 input: null=keep, ""=use CF IP, "<value>"=set
      const ipv6Param = sp.get("ipv6");           // IPv6 input: same semantics as above

      const cfConnectingIp = request.headers.get("CF-Connecting-IP") ?? undefined;

      // Both families cannot be auto at the same time
      const bothAuto = ipParam === "" && ipv6Param === "";

      const ipv4Choice = pickAddress(ipParam, cfConnectingIp);
      const ipv6Choice = pickAddress(ipv6Param, cfConnectingIp);

      let ddnsOp:
        | {
          ok: boolean;
          providerResponse?: unknown;
          providerStatus?: number;
          error?: string;
        }
        | null = null;

      // Validate args before contacting provider
      if (bothAuto) {
        ddnsOp = { ok: false, error: "both IPv4 and IPv6 are set to auto ('')" };
      } else if (!platform) {
        ddnsOp = { ok: false, error: "Invalid or missing platform" };
      } else if (!encToken) {
        ddnsOp = { ok: false, error: "Missing 'token' (encrypted)" };
      } else if (!domain) {
        ddnsOp = { ok: false, error: "Missing 'domain'" };
      } else if (ipv4Choice.update && !ipv4Choice.value) {
        ddnsOp = { ok: false, error: "IPv4 update requested but value is missing" };
      } else if (ipv6Choice.update && !ipv6Choice.value) {
        ddnsOp = { ok: false, error: "IPv6 update requested but value is missing" };
      } else {
        const master = env?.uuid;
        if (!master) {
          ddnsOp = { ok: false, error: "missing uuid" };
        } else {
          try {
            const realDdnsToken = await decryptToken(master, encToken);
            const handler = HANDLERS[platform];

            if (!ipv4Choice.update && !ipv6Choice.update) {
              // No-op: do not contact provider
              ddnsOp = {
                ok: true,
                providerStatus: 200,
                providerResponse: { note: "no-op: keep both IPv4/IPv6; no request sent" },
              };
            } else {
              const inner = await handler(domain, realDdnsToken, ipv4Choice, ipv6Choice);
              ddnsOp = {
                ok: inner.ok,
                providerStatus: inner.providerStatus,
                providerResponse: inner.providerResponse,
                error: inner.error,
              };
            }
          } catch (_e) {
            ddnsOp = { ok: false, error: "invalid encrypted token" };
          }
        }
      }

      const result = {
        ok: !!platform && !!encToken && !!ddnsOp?.ok,
        platform: platform ?? null,
        token_key_received: redactToken(encToken), // preview only (encrypted)
        domain: domain ?? null,
        decisions: { ipv4: ipv4Choice, ipv6: ipv6Choice },
        ddns_op: ddnsOp,
        client: {
          cf_connecting_ip: cfConnectingIp ?? null,
          user_agent: request.headers.get("user-agent") ?? null,
        },
      };

      // Inherit provider HTTP status when present
      const statusCode = ddnsOp?.providerStatus ?? (result.ok ? 200 : 400);

      return new Response(JSON.stringify(result, null, 2), {
        status: statusCode,
        headers: { "content-type": "application/json; charset=utf-8" },
      });
    }

    // --- Default: show brief help (plain text) ---
    const platforms = Object.keys(HANDLERS).join(", ");
    const help = [
      "DDNS bridge",
      "",
      "Endpoints:",
      "  GET /encrypt?token=<RAW_DDNS_TOKEN>           -> returns encrypted token (text/plain)",
      "  GET /decrypt?encrypted=<ENCRYPTED_TOKEN>      -> returns JSON { code, decrypted, msg? }",
      "  GET /update?platform=<name>&domain=<d>&token=<ENCRYPTED_TOKEN>&[ip=<v4|''>]&[ipv6=<v6|''>]",
      "",
      "Notes:",
      "  - 'ip' / 'ipv6': omit to keep, empty string ('') to use CF-Connecting-IP, or provide explicit value.",
      "  - Both families cannot be auto ('') at the same time.",
      `  - Allowed platforms: ${platforms}`,
      "",
      "OpenWrt custom URL:",
      `  ${url.protocol}://${url.host}/update?platform=[USERNAME]&domain=[DOMAIN]&token=[PASSWORD]&ipv6=[IP]`
    ].join("\n");

    return new Response(help, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  },
};
