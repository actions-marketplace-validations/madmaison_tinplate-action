export class TinplateError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly requestId?: string | undefined;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "TinplateError";
    this.status = status;
    this.code = code;
    if (requestId !== undefined) {
      this.requestId = requestId;
    }
  }
}

export interface ReceiptJwk extends Record<string, unknown> {
  kty: string;
  crv: string;
  x: string;
  y?: string;
  kid?: string;
  alg: "EdDSA" | "ES256";
  use: "sig";
}

export interface ReceiptJwks {
  keys: ReceiptJwk[];
}

export interface VerifyReceiptOfflineResult {
  valid: boolean;
  reason?: string;
  alg?: "EdDSA" | "ES256" | "HS256";
  kid?: string;
  payload?: Record<string, unknown>;
}

export interface TinplateCallOptions {
  /** Override client-level requestReceipts for this call */
  receipt?: boolean;
  /** Per-call signing secret header (X-Tinplate-Signing-Secret) */
  signingSecret?: string;
}

export interface TinplateClientOptions {
  /** Base gateway URL (defaults to https://api.tinplate.dev) */
  baseUrl?: string;
  /** Allow non-HTTPS baseUrl when credentials are set (unsafe except for local testing; localhost is always allowed) */
  allowInsecure?: boolean;
  /** Direct Polar All-Access Bearer Key (`tp_...`) or ADMIN_KEY */
  apiKey?: string;
  /** RapidAPI X-RapidAPI-Key header */
  rapidApiKey?: string;
  /** RapidAPI X-RapidAPI-Host header */
  rapidApiHost?: string;
  /** Zyla API Hub Bearer Key (set `baseUrl` to your Zyla endpoint host URL) */
  zylaApiKey?: string;
  /** Request cryptographic signed audit receipts (Ed25519/ES256 via JWKS or HMAC-SHA256) on every call */
  requestReceipts?: boolean;
  /** Ephemeral per-call signing secret sent via X-Tinplate-Signing-Secret (not stored by Tinplate) */
  signingSecret?: string;
  /** Request timeout in milliseconds (default: 8000) */
  timeoutMs?: number;
  /** Maximum automatic retries on 429/503 responses honoring Retry-After (default: 2) */
  maxRetries?: number;
  /** Optional custom fetch implementation */
  fetch?: typeof globalThis.fetch;
}

export interface TinplateEnvelope<T = Record<string, unknown>> {
  ok: boolean;
  data: T;
  meta: {
    request_id: string;
    ms: number;
    version?: string;
    ignored_fields?: string[];
  };
  /** Populated when requestReceipts=true or ?receipt=true */
  receipt?: {
    token: string | null;
    hash: string | null;
  };
}

export interface TinplatePipelineStep {
  id?: string;
  endpoint: string;
  body: Record<string, unknown>;
}

export interface TinplatePipelineStepResult {
  id: string;
  endpoint: string;
  status: number;
  ok: boolean;
  blocked: boolean;
  ms: number;
  data: unknown;
}

export type TinplatePresetId =
  | "llm-ingest-safe"
  | "llm-output-safe"
  | "agent-pre-exec";

function isLocalHostname(hostname: string): boolean {
  const h = hostname.toLowerCase();
  if (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h === "0.0.0.0" ||
    h === "::1" ||
    h === "[::1]"
  ) {
    return true;
  }
  const parts = h.split(".");
  if (parts.length === 4 && parts[0] === "127") {
    return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
  }
  return false;
}

const SDK_BLOCKING_VERDICTS = new Set([
  "block",
  "fail",
  "reject",
  "ungrounded",
  "contradicted",
  "vulnerable",
  "invalid",
]);
const SDK_ESCALATED_VERDICTS = new Set(["review", "warn", "flagged", "partially_grounded"]);
const SDK_NON_BLOCKING_VERDICTS = new Set([
  "allow",
  "safe",
  "pass",
  "grounded",
  "clean",
  "sanitize",
  "sanitized",
  "repaired",
]);

function isOutputBlocked(
  outData: { verdict?: unknown; safe?: unknown; allowed?: unknown } | undefined,
  blockOnReview: boolean,
): boolean {
  if (!outData || typeof outData !== "object") return true;
  if (typeof outData.verdict === "string") {
    if (SDK_BLOCKING_VERDICTS.has(outData.verdict)) return true;
    if (SDK_ESCALATED_VERDICTS.has(outData.verdict)) return blockOnReview;
    if (SDK_NON_BLOCKING_VERDICTS.has(outData.verdict)) return false;
  }
  return outData.safe === false || outData.allowed === false;
}

export class TinplateClient {
  private readonly baseUrl: string;
  private readonly baseOrigin: string;
  private readonly allowInsecure: boolean;
  private readonly isSecureOrLocalBase: boolean;
  private readonly headers: Record<string, string>;
  private readonly requestReceipts: boolean;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: TinplateClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "https://api.tinplate.dev").replace(/\/+$/, "");
    let parsedBase: URL;
    try {
      parsedBase = new URL(this.baseUrl);
    } catch {
      throw new TinplateError(
        0,
        "invalid_base_url",
        `Invalid Tinplate baseUrl '${this.baseUrl}'.`,
      );
    }
    if (parsedBase.protocol !== "https:" && parsedBase.protocol !== "http:") {
      throw new TinplateError(
        0,
        "invalid_base_url",
        `Unsupported Tinplate baseUrl protocol '${parsedBase.protocol}'.`,
      );
    }
    if (parsedBase.username || parsedBase.password) {
      throw new TinplateError(
        0,
        "insecure_base_url",
        "Refusing baseUrl with embedded credentials.",
      );
    }

    this.allowInsecure = Boolean(options.allowInsecure);
    this.isSecureOrLocalBase =
      parsedBase.protocol === "https:" || isLocalHostname(parsedBase.hostname);
    this.baseOrigin = parsedBase.origin;

    const hasAuth = Boolean(
      options.apiKey || options.zylaApiKey || options.rapidApiKey || options.signingSecret,
    );
    if (hasAuth && !this.isSecureOrLocalBase && !this.allowInsecure) {
      throw new TinplateError(
        0,
        "insecure_base_url",
        `Refusing to send Tinplate credentials over non-HTTPS baseUrl '${this.baseUrl}'. Pass allowInsecure: true only for controlled testing.`,
      );
    }

    this.requestReceipts = options.requestReceipts ?? false;
    this.timeoutMs = options.timeoutMs ?? 8000;
    this.maxRetries = Math.max(0, options.maxRetries ?? 2);
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.headers = {
      "Content-Type": "application/json",
    };

    if (options.apiKey) {
      this.headers["Authorization"] = `Bearer ${options.apiKey}`;
    } else if (options.zylaApiKey) {
      this.headers["Authorization"] = `Bearer ${options.zylaApiKey}`;
    }
    if (options.rapidApiKey) {
      this.headers["X-RapidAPI-Key"] = options.rapidApiKey;
    }
    if (options.rapidApiHost) {
      this.headers["X-RapidAPI-Host"] = options.rapidApiHost;
    }
    if (options.signingSecret) {
      this.headers["X-Tinplate-Signing-Secret"] = options.signingSecret;
    }
  }

  private buildEndpointUrl(endpoint: string): URL {
    if (
      !endpoint ||
      /[\s\x00-\x1f\x7f\\]/.test(endpoint) ||
      endpoint.includes("://") ||
      /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(endpoint)
    ) {
      throw new TinplateError(0, "invalid_endpoint", `Invalid Tinplate endpoint '${endpoint}'.`);
    }
    const path = endpoint.startsWith("/") ? endpoint : `/v1/${endpoint}`;
    const pathOnly = path.split(/[?#]/)[0] ?? "";
    if (path.startsWith("//") || pathOnly.includes("@")) {
      throw new TinplateError(0, "invalid_endpoint", `Invalid Tinplate endpoint '${endpoint}'.`);
    }
    let url: URL;
    try {
      url = new URL(`${this.baseUrl}${path}`);
    } catch {
      throw new TinplateError(0, "invalid_endpoint", `Invalid Tinplate endpoint '${endpoint}'.`);
    }
    if (url.origin !== this.baseOrigin || url.username || url.password) {
      throw new TinplateError(
        0,
        "invalid_endpoint",
        `Endpoint '${endpoint}' resolves outside configured baseUrl origin.`,
      );
    }
    return url;
  }

  private async fetchJsonWithRetry(
    method: "GET" | "POST",
    url: URL,
    reqHeaders: Record<string, string>,
    serializedBody?: string,
  ): Promise<{ res: Response; rawText: string; parsed: unknown; headerReqId: string | undefined }> {
    let attempt = 0;

    while (true) {
      const res = await this.fetchImpl(url.toString(), {
        method,
        headers: reqHeaders,
        redirect: "manual",
        ...(serializedBody !== undefined ? { body: serializedBody } : {}),
        ...(typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
          ? { signal: AbortSignal.timeout(this.timeoutMs) }
          : {}),
      });

      const headerReqId = res.headers.get("X-Request-Id") ?? undefined;
      if (res.status >= 300 && res.status < 400) {
        throw new TinplateError(
          res.status,
          "redirect_blocked",
          `Refusing HTTP ${res.status} redirect from Tinplate endpoint.`,
          headerReqId,
        );
      }

      if ((res.status === 429 || res.status === 503) && attempt < this.maxRetries) {
        attempt += 1;
        const retryAfterRaw = res.headers.get("Retry-After");
        const parsedSec = retryAfterRaw ? Number(retryAfterRaw) : Number.NaN;
        const delayMs =
          Number.isFinite(parsedSec) && parsedSec > 0
            ? Math.min(parsedSec * 1000, 2000)
            : Math.min(150 * 2 ** (attempt - 1), 1500);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }

      const rawText = await res.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawText);
      } catch {
        throw new TinplateError(
          res.status,
          "invalid_response",
          `Tinplate API returned non-JSON response (HTTP ${res.status}): ${rawText.slice(0, 200)}`,
          headerReqId,
        );
      }

      return { res, rawText, parsed, headerReqId };
    }
  }

  private async requestWithRetry<T = Record<string, unknown>>(
    method: "GET" | "POST",
    endpoint: string,
    body?: Record<string, unknown>,
    options?: { receipt?: boolean; signingSecret?: string },
  ): Promise<TinplateEnvelope<T>> {
    if (options?.signingSecret && !this.isSecureOrLocalBase && !this.allowInsecure) {
      throw new TinplateError(
        0,
        "insecure_base_url",
        `Refusing to send Tinplate signingSecret over non-HTTPS baseUrl '${this.baseUrl}'. Pass allowInsecure: true only for controlled testing.`,
      );
    }

    const url = this.buildEndpointUrl(endpoint);
    const wantReceipt = method === "POST" && (options?.receipt ?? this.requestReceipts);
    const reqHeaders: Record<string, string> = { ...this.headers };
    if (options?.signingSecret) {
      reqHeaders["X-Tinplate-Signing-Secret"] = options.signingSecret;
    }
    if (wantReceipt) {
      url.searchParams.set("receipt", "true");
      reqHeaders["X-Tinplate-Receipt-Request"] = "true";
    }
    if (method === "GET") {
      delete reqHeaders["Content-Type"];
    }

    const serializedBody = body !== undefined ? JSON.stringify(body) : undefined;
    const { res, parsed, headerReqId } = await this.fetchJsonWithRetry(
      method,
      url,
      reqHeaders,
      serializedBody,
    );

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new TinplateError(
        res.status,
        "invalid_response",
        `Tinplate API returned non-object JSON (HTTP ${res.status})`,
        headerReqId,
      );
    }

    const json = parsed as TinplateEnvelope<T> & {
      error?: { code?: string; message?: string };
    };

    if (!res.ok || !json.ok) {
      const code =
        typeof json.error === "object" && json.error !== null && typeof json.error.code === "string"
          ? json.error.code
          : "http_error";
      const msg =
        typeof json.error === "object" && json.error !== null && typeof json.error.message === "string"
          ? json.error.message
          : `Tinplate API error (HTTP ${res.status})`;
      const errReqId =
        (typeof json.meta === "object" && json.meta !== null && typeof json.meta.request_id === "string"
          ? json.meta.request_id
          : undefined) ?? headerReqId;
      throw new TinplateError(res.status, code, msg, errReqId);
    }

    const receiptToken = res.headers.get("X-Tinplate-Receipt");
    const receiptHash = res.headers.get("X-Tinplate-Receipt-Hash");
    if (receiptToken || receiptHash) {
      json.receipt = {
        token: receiptToken,
        hash: receiptHash,
      };
    }

    return json;
  }

  /**
   * Invoke any Tinplate /v1/* endpoint with typed response envelope and optional cryptographic receipt.
   */
  async call<T = Record<string, unknown>>(
    endpoint: string,
    body: Record<string, unknown>,
    options?: TinplateCallOptions,
  ): Promise<TinplateEnvelope<T>> {
    return this.requestWithRetry<T>("POST", endpoint, body, options);
  }

  /** Fetch public asymmetric receipt verification JWKS (`GET /.well-known/jwks.json`). */
  async getJwks(): Promise<ReceiptJwks> {
    const url = this.buildEndpointUrl("/.well-known/jwks.json");
    const { res, parsed, headerReqId } = await this.fetchJsonWithRetry("GET", url, {
      Accept: "application/json",
    });
    if (!res.ok) {
      throw new TinplateError(
        res.status,
        "jwks_fetch_failed",
        `Failed to fetch JWKS (HTTP ${res.status})`,
        headerReqId,
      );
    }
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      !Array.isArray((parsed as { keys?: unknown }).keys)
    ) {
      throw new TinplateError(
        res.status,
        "invalid_jwks",
        "JWKS response missing keys array",
        headerReqId,
      );
    }
    return parsed as ReceiptJwks;
  }

  /** Verify a receipt token or hash-linked chain via the gateway (`POST /verify`). */
  async verifyReceipt(input: {
    receipt_token?: string;
    chain?: string[];
  }): Promise<TinplateEnvelope<{
    valid: boolean;
    chain_intact: boolean;
    verified_count: number;
    reason?: string | null;
    links: unknown[];
  }>> {
    return this.requestWithRetry("POST", "/verify", input as Record<string, unknown>, {
      receipt: false,
    });
  }

  /**
   * Verify an `X-Tinplate-Receipt` token completely offline using WebCrypto (`crypto.subtle`).
   * Supports `EdDSA` (`Ed25519`), `ES256` (`P-256`), and `HS256` (`HMAC-SHA256`).
   */
  async verifyReceiptOffline(
    token: string,
    options?: { jwks?: ReceiptJwks; secret?: string; nowEpoch?: number },
  ): Promise<VerifyReceiptOfflineResult> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      return { valid: false, reason: "malformed_token" };
    }
    const [h64, p64, s64] = parts as [string, string, string];
    const fromB64Url = (s: string): Uint8Array => {
      const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
      const bin = atob(padded);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
      return out;
    };
    const dec = new TextDecoder();
    const enc = new TextEncoder();

    let header: { alg?: string; typ?: string; kid?: string };
    let payload: Record<string, unknown>;
    try {
      const parsedHeader: unknown = JSON.parse(dec.decode(fromB64Url(h64)));
      const parsedPayload: unknown = JSON.parse(dec.decode(fromB64Url(p64)));
      if (
        typeof parsedHeader !== "object" ||
        parsedHeader === null ||
        Array.isArray(parsedHeader) ||
        typeof parsedPayload !== "object" ||
        parsedPayload === null ||
        Array.isArray(parsedPayload)
      ) {
        return { valid: false, reason: "invalid_encoding" };
      }
      header = parsedHeader as typeof header;
      payload = parsedPayload as Record<string, unknown>;
    } catch {
      return { valid: false, reason: "invalid_encoding" };
    }

    const kid = typeof header.kid === "string" ? header.kid : "";
    const alg = header.alg;
    if (
      !kid ||
      header.typ !== "AAR" ||
      (alg !== "EdDSA" && alg !== "ES256" && alg !== "HS256")
    ) {
      return { valid: false, reason: "unsupported_header" };
    }

    let sigBytes: Uint8Array;
    try {
      sigBytes = fromB64Url(s64);
    } catch {
      return { valid: false, alg, kid, reason: "invalid_encoding" };
    }

    const reserved = new Set(["__proto__", "constructor", "prototype"]);
    const signingData = enc.encode(`${h64}.${p64}`);
    const dataBuf = signingData.buffer.slice(
      signingData.byteOffset,
      signingData.byteOffset + signingData.byteLength,
    ) as ArrayBuffer;
    const sigBuf = sigBytes.buffer.slice(
      sigBytes.byteOffset,
      sigBytes.byteOffset + sigBytes.byteLength,
    ) as ArrayBuffer;

    let verified = false;
    if (alg === "HS256") {
      if (typeof options?.secret !== "string" || !options.secret) {
        return { valid: false, alg, kid, reason: "missing_secret" };
      }
      try {
        const key = await crypto.subtle.importKey(
          "raw",
          enc.encode(options.secret),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"],
        );
        verified = await crypto.subtle.verify("HMAC", key, sigBuf, dataBuf);
      } catch {
        return { valid: false, alg, kid, reason: "verification_error" };
      }
    } else {
      const keys = Array.isArray(options?.jwks?.keys) ? options.jwks.keys : undefined;
      const jwk =
        !reserved.has(kid) && keys
          ? keys.find((k) => Boolean(k) && k.kid === kid && k.alg === alg)
          : undefined;
      if (!jwk) {
        return { valid: false, alg, kid, reason: "unknown_kid" };
      }
      const hasValidShape =
        typeof jwk.kty === "string" &&
        typeof jwk.crv === "string" &&
        typeof jwk.x === "string" &&
        jwk.x.length > 0 &&
        (alg === "EdDSA"
          ? jwk.kty === "OKP" && jwk.crv === "Ed25519"
          : jwk.kty === "EC" &&
            jwk.crv === "P-256" &&
            typeof jwk.y === "string" &&
            jwk.y.length > 0);
      if (!hasValidShape) {
        return { valid: false, alg, kid, reason: "invalid_jwk" };
      }

      const pubJwk: JsonWebKey = {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        ...(typeof jwk.y === "string" ? { y: jwk.y } : {}),
      };
      let key: CryptoKey;
      try {
        key =
          alg === "EdDSA"
            ? await crypto.subtle.importKey("jwk", pubJwk, { name: "Ed25519" }, false, ["verify"])
            : await crypto.subtle.importKey(
                "jwk",
                pubJwk,
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["verify"],
              );
      } catch {
        return { valid: false, alg, kid, reason: "invalid_jwk" };
      }
      try {
        verified =
          alg === "EdDSA"
            ? await crypto.subtle.verify({ name: "Ed25519" }, key, sigBuf, dataBuf)
            : await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sigBuf, dataBuf);
      } catch {
        return { valid: false, alg, kid, reason: "verification_error" };
      }
    }

    if (!verified) {
      return { valid: false, alg, kid, reason: "invalid_signature" };
    }
    const nowEpoch = options?.nowEpoch ?? Math.floor(Date.now() / 1000);
    if (typeof payload.exp === "number" && nowEpoch >= payload.exp) {
      return { valid: false, alg, kid, reason: "receipt_expired", payload };
    }
    return { valid: true, alg, kid, payload };
  }

  /** Check gateway health (`GET /v1/health`). */
  health() {
    return this.requestWithRetry<{ status: string; service: string; timestamp: string }>(
      "GET",
      "/v1/health",
    );
  }

  /** List built-in enterprise pipeline presets (`GET /v1/presets`). */
  listPresets() {
    return this.requestWithRetry<{
      total_presets: number;
      presets: Array<{
        id: string;
        title: string;
        description: string;
        endpoints: string[];
        sample_input: Record<string, unknown>;
      }>;
    }>("GET", "/v1/presets");
  }

  /**
   * Chain up to 5 Tinplate APIs in a single network round-trip with $steps.<id>.data.<field> piping.
   */
  async pipeline(
    steps: TinplatePipelineStep[],
    stopOnBlock = true,
    options?: TinplateCallOptions & { parallel?: boolean },
  ): Promise<
    TinplateEnvelope<{
      all_passed: boolean;
      completed_steps: number;
      total_steps: number;
      halted: boolean;
      halted_at_step: string | null;
      total_ms: number;
      results: TinplatePipelineStepResult[];
      steps?: TinplatePipelineStepResult[];
    }>
  > {
    return this.call(
      "/v1/pipeline",
      {
        stop_on_block: stopOnBlock,
        ...(options?.parallel !== undefined ? { parallel: options.parallel } : {}),
        steps,
      },
      options,
    );
  }

  /**
   * Execute a named 1-call enterprise policy bundle (e.g. 'llm-ingest-safe', 'llm-output-safe', 'agent-pre-exec').
   */
  async preset(
    presetId: TinplatePresetId,
    input: Record<string, unknown>,
    options?: TinplateCallOptions,
  ): Promise<TinplateEnvelope> {
    return this.call(`/v1/presets/${encodeURIComponent(presetId)}`, input, options);
  }

  /** 01 — Prompt Injection Detection API */
  promptGuard(
    input: {
      text: string;
      context?: "user_input" | "rag_document" | "tool_output" | "llm_output";
      sensitivity?: "low" | "medium" | "high";
      block_threshold?: number;
      use_ai_judge?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      verdict: "allow" | "review" | "block";
      risk_score: number;
      blocked: boolean;
      categories: string[];
      signals: unknown[];
      normalization: Record<string, unknown>;
      judge: string;
      ai_judge: unknown;
    }>("/v1/prompt-guard", input, options);
  }

  /** 03 — PII Redactor API */
  redactPii(
    input: {
      text: string;
      locales?: Array<"GLOBAL" | "EU" | "HU">;
      mode?: "token" | "mask";
      types?: string[];
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      redacted_text: string;
      findings: unknown[];
      counts: Record<string, number>;
      total_redacted: number;
      tokens: Record<string, string>;
    }>("/v1/pii-redactor", input, options);
  }

  /** 10 — Broken JSON & LLM Output Healer API */
  healJson<T = unknown>(
    input: {
      raw: string;
      schema?: Record<string, unknown>;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      valid: boolean;
      data: T | null;
      healed_json: string | null;
      repairs: string[];
      schema_valid: boolean | null;
      schema_errors: string[];
    }>("/v1/json-heal", input, options);
  }

  /** 16 — Log Redact & Secret Scanner API */
  scanSecrets(
    input: {
      text: string;
      mode?: "token" | "mask" | "partial";
      types?: string[];
      diff_only_added?: boolean;
      min_entropy?: number;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      verdict: "allow" | "warn" | "block";
      risk_score: number;
      redacted_text: string;
      findings: unknown[];
      counts: Record<string, number>;
      total_secrets: number;
      tokens?: Record<string, string>;
    }>("/v1/secret-scanner", input, options);
  }

  /** 31 — LLM Output Guardrail & Leak Detector API */
  guardLlmOutput(
    input: {
      output: string;
      system_prompt?: string;
      canary_tokens?: string[];
      blocked_terms?: string[];
      allowed_link_domains?: string[];
      check_regulated_advice?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      verdict: "allow" | "sanitize" | "block";
      safe: boolean;
      risk_score: number;
      sanitized_output: string;
      findings: unknown[];
      metrics: Record<string, unknown>;
    }>("/v1/llm-output-guard", input, options);
  }

  /** 37 — LLM Chat Messages Policy Proxy API */
  guardMessages(
    input: {
      messages: Array<Record<string, unknown>>;
      sensitivity?: "low" | "medium" | "high";
      check_prompt_injection?: boolean;
      redact_pii?: boolean;
      scan_secrets?: boolean;
      strip_email_quotes?: boolean;
      locales?: Array<"GLOBAL" | "EU" | "HU" | "US">;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      safe: boolean;
      verdict: "allow" | "review" | "block";
      max_risk_score: number;
      sanitized_messages: Array<Record<string, unknown>>;
      restoration_map: Record<string, string>;
      summary: {
        total_messages: number;
        scanned_messages: number;
        blocked_turns: number;
        total_pii_redacted: number;
        total_secrets_redacted: number;
        injection_categories: string[];
      };
      turn_findings: unknown[];
    }>("/v1/llm-messages-guard", input, options);
  }

  /** 42 — AI-Generated Code & CI Workflow Sandbox Auditor API */
  guardAgentCode(
    input: {
      code: string;
      language?: "auto" | "python" | "javascript" | "typescript" | "github_actions_yaml" | "bash";
      allow_network?: boolean;
      allow_filesystem_write?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call<{
      verdict: "allow" | "review" | "block";
      safe: boolean;
      risk_score: number;
      detected_language: string;
      clean_code?: string;
      categories_triggered: string[];
      findings: unknown[];
    }>("/v1/agent-code-guard", input, options);
  }

  /** 03 — PII Redactor Restore API */
  restorePii(
    input: { redacted_text: string; tokens: Record<string, string> },
    options?: TinplateCallOptions,
  ) {
    return this.call<{ text: string; restored_count: number }>("/v1/pii-redactor/restore", input, options);
  }

  /** 13 — Agent URL & SSRF Signal Validator API */
  ssrfFirewall(
    input: {
      url: string;
      check_dns?: boolean;
      inspect_redirects?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/ssrf-firewall", input, options);
  }

  /** 14 — RAG Hallucination & Citation Diff API */
  hallucinationDiff(
    input: {
      answer: string;
      sources: string[];
      strictness?: "lenient" | "balanced" | "strict";
      use_ai_judge?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/hallucination-diff", input, options);
  }

  /** 15 — Consent Token Issuer API */
  issueConsentToken(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/consent-tokens/issue", input, options);
  }

  /** 15 — Consent Token Verifier API */
  verifyConsentToken(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/consent-tokens/verify", input, options);
  }

  /** 16 — Secret Scanner Restore API */
  restoreSecrets(
    input: { redacted_text: string; tokens: Record<string, string> },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/secret-scanner/restore", input, options);
  }

  /** 17 — LLM Tool-Call Validator & Repair API */
  validateToolCall(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/tool-call-validator", input, options);
  }

  /** 19 — MCP Manifest Security Linter API */
  lintMcpManifest(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/mcp-manifest-linter", input, options);
  }

  /** 27 — Semver & Lockfile Risk Judge API */
  judgeSemverLockfile(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/semver-lockfile-judge", input, options);
  }

  /** 29 — Agent Action Receipt Issuer API */
  issueActionReceipt(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/agent-action-receipts/issue", input, options);
  }

  /** 29 — Agent Action Receipt Verifier API */
  verifyActionReceipt(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/agent-action-receipts/verify", input, options);
  }

  /** 30 — Content Provenance & C2PA Inspector API */
  inspectProvenance(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/content-provenance", input, options);
  }

  /** 32 — Shell Command & SQL Injection Guard API */
  guardCommandSql(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/command-sql-guard", input, options);
  }

  /** 34 — JWT & JWK Security Inspector API */
  inspectJwtJwk(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/jwt-jwk-inspector", input, options);
  }

  /** 36 — Regex ReDoS Safety Analyzer API */
  analyzeRegexSafety(
    input: {
      pattern: string;
      flags?: string;
      test_strings?: string[];
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/regex-safety", input, options);
  }

  /** 38 — Tabular CSV/JSON RAG Cleaner API */
  cleanTabularRag(input: Record<string, unknown>, options?: TinplateCallOptions) {
    return this.call("/v1/tabular-rag-cleaner", input, options);
  }

  /** 45 — RAG Chunk & Document Poisoning Guard API */
  ragPoisonGuard(
    input: {
      chunks: Array<{
        id?: string;
        source?: string;
        content: string;
        metadata?: Record<string, unknown>;
      }>;
      query?: string;
      sensitivity?: "low" | "medium" | "high";
      strip_poisoned?: boolean;
      check_metadata?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/rag-poison-guard", input, options);
  }

  /** 46 — A2A Agent Card Security Auditor API */
  a2aCardGuard(
    input: {
      agent_card: Record<string, unknown> | string;
      allowed_hosts?: string[];
      require_auth?: boolean;
      require_https?: boolean;
      strict_schema?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/a2a-card-guard", input, options);
  }

  /** 47 — x402 Agent Payment & Budget Policy Guard API */
  x402SpendGuard(
    input: {
      payment_required: Record<string, unknown> | string;
      policy?: Record<string, unknown>;
      recent_payments?: Array<Record<string, unknown>>;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/x402-spend-guard", input, options);
  }

  /** 48 — MCP JSON-RPC Traffic & Tool-Call Firewall API */
  mcpTrafficGuard(
    input: {
      message: Record<string, unknown> | Array<Record<string, unknown>> | string;
      direction?: "auto" | "request" | "response";
      allowed_tools?: string[];
      blocked_tools?: string[];
      allow_sampling?: boolean;
      check_secrets?: boolean;
      max_batch_size?: number;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/mcp-traffic-guard", input, options);
  }

  /** 49 — Agent Action Policy & Least-Privilege RBAC Firewall API */
  agentPolicyGuard(
    input: {
      action: Record<string, unknown>;
      policy: Record<string, unknown>;
      session_history?: Array<Record<string, unknown>>;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/agent-policy-guard", input, options);
  }

  /** 50 — System Prompt Hardening & Leak-Resistance Auditor API */
  systemPromptAudit(
    input: {
      system_prompt: string;
      has_tools?: boolean;
      handles_untrusted_data?: boolean;
      check_secrets?: boolean;
      check_pii?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/system-prompt-audit", input, options);
  }

  /** 51 — Dockerfile, Compose & Kubernetes Sandbox Security Auditor API */
  iacContainerGuard(
    input: {
      manifest: string;
      format?: "auto" | "dockerfile" | "docker_compose" | "kubernetes_yaml";
      allow_root?: boolean;
      allow_latest_tag?: boolean;
      check_secrets?: boolean;
    },
    options?: TinplateCallOptions,
  ) {
    return this.call("/v1/iac-container-guard", input, options);
  }

  private async runInputGuardrail(input: {
    text: string;
    locales?: string[] | undefined;
    sensitivity?: "low" | "medium" | "high" | undefined;
    blockOnFlag?: boolean | undefined;
    blockOnReview?: boolean | undefined;
  }): Promise<{ blocked: boolean; verdict: string; redactedPrompt: string }> {
    const pre = await this.pipeline([
      {
        id: "prompt",
        endpoint: "/v1/prompt-guard",
        body: {
          text: input.text,
          context: "user_input",
          sensitivity: input.sensitivity ?? "medium",
        },
      },
      {
        id: "pii",
        endpoint: "/v1/pii-redactor",
        body: {
          text: input.text,
          locales: input.locales ?? ["GLOBAL"],
          mode: "token",
        },
      },
    ]);

    const stepList = pre.data.results ?? pre.data.steps;
    if (!Array.isArray(stepList) || stepList.length === 0) {
      throw new TinplateError(
        502,
        "guardrail_failed",
        "Input guardrail pipeline returned no step results",
        pre.meta?.request_id,
      );
    }

    const promptStep = stepList.find((s) => s.id === "prompt") ?? stepList[0];
    if (!promptStep || promptStep.ok !== true) {
      throw new TinplateError(
        promptStep?.status && promptStep.status >= 400 ? promptStep.status : 502,
        "guardrail_failed",
        "Prompt guardrail step failed",
        pre.meta?.request_id,
      );
    }

    const promptData =
      typeof promptStep.data === "object" && promptStep.data !== null
        ? (promptStep.data as Record<string, unknown>)
        : {};
    if (typeof promptData.verdict !== "string") {
      throw new TinplateError(
        502,
        "guardrail_failed",
        "Prompt guardrail step returned no verdict",
        pre.meta?.request_id,
      );
    }

    const verdict = promptData.verdict;
    const blockOnReview = Boolean(input.blockOnFlag || input.blockOnReview);
    const promptBlocked =
      Boolean(promptStep.blocked) ||
      verdict === "block" ||
      (blockOnReview && verdict === "review");

    const piiStep = stepList.find((s) => s.id === "pii") ?? stepList[1];
    const piiData =
      piiStep && typeof piiStep.data === "object" && piiStep.data !== null
        ? (piiStep.data as Record<string, unknown>)
        : {};

    if (promptBlocked) {
      const redactedPrompt =
        piiStep?.ok === true && typeof piiData.redacted_text === "string"
          ? piiData.redacted_text
          : "";
      return { blocked: true, verdict, redactedPrompt };
    }

    if (!piiStep || piiStep.ok !== true || typeof piiData.redacted_text !== "string") {
      throw new TinplateError(
        piiStep?.status && piiStep.status >= 400 ? piiStep.status : 502,
        "guardrail_failed",
        "PII redaction step failed",
        pre.meta?.request_id,
      );
    }

    return { blocked: false, verdict, redactedPrompt: piiData.redacted_text };
  }

  /**
   * Drop-in LLM turn guardrail: runs Prompt Guard + PII Redactor in one pipeline
   * before invoking `generate(safePrompt)`, then validates the LLM output.
   */
  async guardLlmTurn(input: {
    userPrompt: string;
    generate: (safePrompt: string) => Promise<string>;
    locales?: string[];
    sensitivity?: "low" | "medium" | "high";
    blockOnFlag?: boolean;
    blockOnReview?: boolean;
  }): Promise<{
    blocked: boolean;
    verdict: string;
    redactedPrompt: string;
    output: string | null;
    outputGuard?: Record<string, unknown>;
  }> {
    const blockOnReview = Boolean(input.blockOnFlag || input.blockOnReview);
    const { blocked, verdict, redactedPrompt } = await this.runInputGuardrail({
      text: input.userPrompt,
      locales: input.locales,
      sensitivity: input.sensitivity,
      blockOnReview,
    });

    if (blocked) {
      return { blocked: true, verdict, redactedPrompt, output: null };
    }

    const rawOutput = await input.generate(redactedPrompt);
    const outRes = await this.guardLlmOutput({ output: rawOutput });
    const outputBlocked = isOutputBlocked(outRes.data, blockOnReview);
    const safeOutput =
      outputBlocked
        ? null
        : outRes.data.verdict === "sanitize" && typeof outRes.data.sanitized_output === "string"
          ? outRes.data.sanitized_output
          : rawOutput;
    return {
      blocked: outputBlocked,
      verdict: outputBlocked ? String(outRes.data.verdict ?? "block") : String(outRes.data.verdict === "sanitize" ? "sanitize" : verdict),
      redactedPrompt,
      output: safeOutput,
      outputGuard: outRes.data as Record<string, unknown>,
    };
  }

  /**
   * Drop-in middleware wrapper for OpenAI, Anthropic, and Vercel AI SDK calls.
   * Automatically runs `promptGuard` + `redactPii` on inputs and `healJson` (optional) + `guardLlmOutput` on responses.
   */
  async withTinplate<T = string>(
    input: WithTinplateInput<T>,
  ): Promise<WithTinplateResult<T>> {
    const blockOnReview = Boolean(input.blockOnFlag || input.blockOnReview);
    const { blocked, verdict, redactedPrompt } = await this.runInputGuardrail({
      text: input.prompt,
      locales: input.locales,
      sensitivity: input.sensitivity,
      blockOnReview,
    });

    if (blocked) {
      if (input.onBlock === "throw") {
        throw new TinplateError(403, "prompt_blocked", `Tinplate blocked prompt (verdict: ${verdict})`);
      }
      return {
        blocked: true,
        verdict,
        redactedPrompt,
        rawResponse: null,
        output: null,
      };
    }

    const rawResponse = await input.generate(redactedPrompt);
    const outputText = input.extractText
      ? input.extractText(rawResponse)
      : typeof rawResponse === "string"
        ? rawResponse
        : JSON.stringify(rawResponse);

    let healedJson: Record<string, unknown> | undefined;
    if (input.healJson) {
      const healRes = await this.healJson({ raw: outputText });
      healedJson = healRes.data as Record<string, unknown>;
    }

    const outRes = await this.guardLlmOutput({ output: outputText });
    const outputBlocked = isOutputBlocked(outRes.data, blockOnReview);
    if (outputBlocked) {
      const outVerdict = String(outRes.data.verdict ?? "block");
      if (input.onBlock === "throw") {
        throw new TinplateError(403, "output_blocked", `Tinplate blocked output (verdict: ${outVerdict})`);
      }
      return {
        blocked: true,
        verdict: outVerdict,
        redactedPrompt,
        rawResponse: null,
        output: null,
        ...(healedJson ? { healedJson } : {}),
        outputGuard: outRes.data as Record<string, unknown>,
      };
    }

    const safeOutput =
      outRes.data.verdict === "sanitize" &&
      typeof outRes.data.sanitized_output === "string"
        ? outRes.data.sanitized_output
        : outputText;
    const effectiveVerdict =
      outRes.data.verdict === "sanitize" ? "sanitize" : verdict;

    return {
      blocked: false,
      verdict: effectiveVerdict,
      redactedPrompt,
      rawResponse,
      output: safeOutput,
      ...(healedJson ? { healedJson } : {}),
      outputGuard: outRes.data as Record<string, unknown>,
    };
  }

  /**
   * Streaming guardrail helper for Vercel AI SDK (`streamText`), OpenAI, and Anthropic streams.
   * Runs `promptGuard` + `redactPii` before opening the stream, yields chunks in real time,
   * and runs `guardLlmOutput` (+ optional `healJson`) once the stream completes.
   */
  guardStream(input: {
    prompt: string;
    stream: (
      safePrompt: string,
    ) =>
      | AsyncIterable<string>
      | ReadableStream<string>
      | Promise<AsyncIterable<string> | ReadableStream<string> | { textStream: AsyncIterable<string> }>;
    locales?: string[];
    sensitivity?: "low" | "medium" | "high";
    blockOnFlag?: boolean;
    blockOnReview?: boolean;
    healJson?: boolean;
  }): GuardStreamHandle {
    let resolveResult!: (value: GuardStreamResult) => void;
    let rejectResult!: (reason?: unknown) => void;
    const result = new Promise<GuardStreamResult>((resolve, reject) => {
      resolveResult = resolve;
      rejectResult = reject;
    });

    const self = this;
    const blockOnReview = Boolean(input.blockOnFlag || input.blockOnReview);
    async function* generateStream(): AsyncGenerator<string, void, unknown> {
      try {
        const { blocked, verdict, redactedPrompt } = await self.runInputGuardrail({
          text: input.prompt,
          locales: input.locales,
          sensitivity: input.sensitivity,
          blockOnReview,
        });

        if (blocked) {
          resolveResult({
            blocked: true,
            verdict,
            redactedPrompt,
            output: "",
          });
          return;
        }

        const source = await input.stream(redactedPrompt);
        const iterable = toAsyncIterable(source);
        const chunks: string[] = [];
        for await (const chunk of iterable) {
          chunks.push(chunk);
          yield chunk;
        }

        const fullOutput = chunks.join("");
        let healedJson: Record<string, unknown> | undefined;
        if (input.healJson) {
          const healRes = await self.healJson({ raw: fullOutput });
          healedJson = healRes.data as Record<string, unknown>;
        }
        const outRes = await self.guardLlmOutput({ output: fullOutput });
        const outputBlocked = isOutputBlocked(outRes.data, blockOnReview);
        const safeStreamOutput = outputBlocked
          ? ""
          : outRes.data.verdict === "sanitize" &&
              typeof outRes.data.sanitized_output === "string"
            ? outRes.data.sanitized_output
            : fullOutput;
        const effectiveStreamVerdict = outputBlocked
          ? String(outRes.data.verdict ?? "block")
          : outRes.data.verdict === "sanitize"
            ? "sanitize"
            : verdict;
        resolveResult({
          blocked: outputBlocked,
          verdict: effectiveStreamVerdict,
          redactedPrompt,
          output: safeStreamOutput,
          ...(healedJson ? { healedJson } : {}),
          outputGuard: outRes.data as Record<string, unknown>,
        });
      } catch (err) {
        rejectResult(err);
        throw err;
      }
    }

    return {
      stream: generateStream(),
      result,
    };
  }
}

export interface WithTinplateInput<T = string> {
  prompt: string;
  generate: (safePrompt: string) => Promise<T>;
  extractText?: (response: T) => string;
  locales?: string[];
  sensitivity?: "low" | "medium" | "high";
  blockOnFlag?: boolean;
  blockOnReview?: boolean;
  onBlock?: "return" | "throw";
  healJson?: boolean;
}

export interface WithTinplateResult<T = string> {
  blocked: boolean;
  verdict: string;
  redactedPrompt: string;
  rawResponse: T | null;
  output: string | null;
  healedJson?: Record<string, unknown>;
  outputGuard?: Record<string, unknown>;
}

export interface GuardStreamResult {
  blocked: boolean;
  verdict: string;
  redactedPrompt: string;
  output: string;
  healedJson?: Record<string, unknown>;
  outputGuard?: Record<string, unknown>;
}

export interface GuardStreamHandle {
  stream: AsyncIterable<string>;
  result: Promise<GuardStreamResult>;
}

async function* toAsyncIterable(
  source: AsyncIterable<string> | ReadableStream<string> | { textStream: AsyncIterable<string> },
): AsyncGenerator<string, void, unknown> {
  if (typeof ReadableStream !== "undefined" && source instanceof ReadableStream) {
    const reader = source.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (typeof value === "string") yield value;
      }
    } finally {
      reader.releaseLock();
    }
    return;
  }
  const iterable =
    "textStream" in (source as Record<string, unknown>)
      ? (source as { textStream: AsyncIterable<string> }).textStream
      : (source as AsyncIterable<string>);
  for await (const chunk of iterable) {
    yield chunk;
  }
}

/**
 * Standalone middleware helper for OpenAI, Anthropic, and Vercel AI SDK calls.
 */
export function withTinplate<T = string>(
  client: TinplateClient,
  input: WithTinplateInput<T>,
): Promise<WithTinplateResult<T>> {
  return client.withTinplate<T>(input);
}

/**
 * Standalone streaming guardrail helper for Vercel AI SDK, OpenAI, and Anthropic streams.
 */
export function guardStream(
  client: TinplateClient,
  input: Parameters<TinplateClient["guardStream"]>[0],
): GuardStreamHandle {
  return client.guardStream(input);
}
