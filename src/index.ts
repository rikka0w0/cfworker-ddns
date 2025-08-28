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

/** Secret name = PLATFORM + '_' + URL_TOKEN (uppercased, '-' replaced with '_') */
function buildSecretName(platform: Platform, urlToken: string): string {
  return `${platform}_${urlToken}`.toUpperCase().replace(/-/g, "_");
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

    const platform = normalizePlatform(sp.get("platform"));
    const urlToken = sp.get("token");           // Your URL token (uuid) to find the real provider token
    const domain = sp.get("domain")?.trim();    // Single domain (no suffix like .duckdns.org)
    const ipParam = sp.get("ip");               // IPv4 input: null=keep, ""=use CF IP, "<value>"=set
    const ipv6Param = sp.get("ipv6");           // IPv6 input: same semantics as above

    const cfConnectingIp = request.headers.get("CF-Connecting-IP") ?? undefined;

    // Prohibit both families being auto ("") at the same time
    const bothAuto = ipParam === "" && ipv6Param === "";

    const ipv4Choice = pickAddress(ipParam, cfConnectingIp);
    const ipv6Choice = pickAddress(ipv6Param, cfConnectingIp);

    // === Validate args and prepare execution plan (provider-agnostic) ===
    let ddnsOp:
      | {
          ok: boolean;
          secretFound: boolean;
          providerResponse?: unknown;
          providerStatus?: number;
          error?: string;
        }
      | null = null;

    if (bothAuto) {
      ddnsOp = {
        ok: false,
        secretFound: false,
        error:
          "Invalid args: both IPv4 and IPv6 are set to auto (''). Only one can be auto-resolved from CF-Connecting-IP.",
      };
    } else if (!platform) {
      ddnsOp = { ok: false, secretFound: false, error: "Invalid or missing platform" };
    } else if (!urlToken) {
      ddnsOp = { ok: false, secretFound: false, error: "Missing 'token' (URL token)" };
    } else if (!domain) {
      ddnsOp = { ok: false, secretFound: false, error: "Missing 'domain'" };
    } else if (ipv4Choice.update && !ipv4Choice.value) {
      ddnsOp = { ok: false, secretFound: false, error: "IPv4 update requested but value is missing" };
    } else if (ipv6Choice.update && !ipv6Choice.value) {
      ddnsOp = { ok: false, secretFound: false, error: "IPv6 update requested but value is missing" };
    } else {
      // Resolve secret and dispatch to handler
      const secretName = buildSecretName(platform, urlToken);
      const realDdnsToken: string | undefined = env?.[secretName];
      const handler = HANDLERS[platform];

      if (!realDdnsToken) {
        ddnsOp = { ok: false, secretFound: false, error: "Missing secret for the given token" };
      } else if (!handler) {
        ddnsOp = { ok: false, secretFound: true, error: "No handler registered for the platform" };
      } else if (!ipv4Choice.update && !ipv6Choice.update) {
        // No-op: keep records as-is, do not call provider
        ddnsOp = {
          ok: true,
          secretFound: true,
          providerStatus: 200,
          providerResponse: { note: "no-op: keep both IPv4/IPv6; no request sent" },
        };
      } else {
        const inner = await handler(domain, realDdnsToken, ipv4Choice, ipv6Choice);
        ddnsOp = {
          ok: inner.ok,
          secretFound: true,
          providerStatus: inner.providerStatus,
          providerResponse: inner.providerResponse,
          error: inner.error,
        };
      }
    }

    // === Build response (no provider-specific logic here, and no secret name exposed) ===
    const result = {
      ok: !!platform && !!urlToken && !!ddnsOp?.ok,
      platform: platform ?? null,
      token_key_received: redactToken(urlToken),
      domain: domain ?? null,
      decisions: { ipv4: ipv4Choice, ipv6: ipv6Choice },
      ddns_op: {
        ok: ddnsOp?.ok ?? false,
        secretFound: ddnsOp?.secretFound ?? false,
        providerStatus: ddnsOp?.providerStatus ?? undefined,
        providerResponse: ddnsOp?.providerResponse ?? undefined,
        error: ddnsOp?.error ?? undefined,
      },
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
  },
};
