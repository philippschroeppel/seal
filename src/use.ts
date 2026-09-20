import { bytesToHex, hexToBytes } from "@noble/ciphers/utils.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8Encode, wipe } from "./bytes.js";
import { SealError } from "./errors.js";
import type { IdentityAttach, IdentityBinding } from "./manifest.js";

const HOP_BY_HOP = new Set([
  "authorization",
  "connection",
  "content-length",
  "cookie",
  "host",
  "keep-alive",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export interface HttpUseRequest {
  readonly method: string;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface HttpUseResult {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

export function attachBearer(
  identity: IdentityBinding,
  headers: Record<string, string>,
  secret: string,
): Record<string, string> {
  const attach: IdentityAttach = identity.attach ?? { type: "bearer" };
  const header = attach.header ?? "Authorization";
  const scheme = attach.scheme ?? "Bearer";
  return {
    ...headers,
    [header]: scheme.length > 0 ? `${scheme} ${secret}` : secret,
  };
}

export function signPayload(
  format: string,
  payload: string,
  secret: string,
): string {
  const message = utf8Encode(payload);
  if (format === "hmac-sha256") {
    const key = utf8Encode(secret);
    try {
      return bytesToHex(hmac(sha256, key, message));
    } finally {
      wipe(key);
    }
  }
  if (format === "ed25519") {
    const key = hexToBytes(secret);
    try {
      return bytesToHex(ed25519.sign(message, key));
    } finally {
      wipe(key);
    }
  }
  throw new SealError("unsupported_op", `unsupported sign format: ${format}`);
}

export function sanitizeAgentHeaders(
  headers: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) {
    return out;
  }
  for (const [key, value] of Object.entries(headers)) {
    if (HOP_BY_HOP.has(key.toLowerCase())) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

export function matchesPeer(
  url: string,
  peers: readonly string[] | undefined,
): boolean {
  if (!peers || peers.length === 0) {
    return false;
  }
  return peers.some((peer) => urlMatchesPrefix(url, peer));
}

export function urlMatchesPrefix(url: string, peer: string): boolean {
  if (url === peer) {
    return true;
  }
  if (!url.startsWith(peer)) {
    return false;
  }
  if (peer.endsWith("/")) {
    return true;
  }
  const next = url[peer.length];
  return next === "/" || next === "?" || next === "#";
}

export function parseHttpUrl(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new SealError("bad_request", "invalid url");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SealError("forbidden", "only http(s) urls are allowed");
  }
  if (parsed.username || parsed.password) {
    throw new SealError("forbidden", "urls must not include credentials");
  }
  return parsed;
}

export function normalizeMethod(method: string): string {
  const upper = method.toUpperCase();
  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].includes(upper)) {
    throw new SealError("bad_request", `unsupported method: ${method}`);
  }
  return upper;
}

export async function fetchPeer(
  request: HttpUseRequest,
  headers: Record<string, string>,
  fetchImpl: typeof fetch,
): Promise<HttpUseResult> {
  const hasBody =
    request.body !== undefined &&
    request.method !== "GET" &&
    request.method !== "HEAD";
  const body = !hasBody
    ? undefined
    : typeof request.body === "string"
      ? request.body
      : JSON.stringify(request.body);

  if (
    hasBody &&
    typeof request.body !== "string" &&
    !hasHeader(headers, "content-type")
  ) {
    headers["Content-Type"] = "application/json";
  }

  let response: Response;
  try {
    response = await fetchImpl(request.url, {
      method: request.method,
      headers,
      ...(body === undefined ? {} : { body }),
      redirect: "manual",
    });
  } catch (error) {
    throw new SealError(
      "peer_failed",
      error instanceof Error ? error.message : "peer request failed",
    );
  }

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  return {
    status: response.status,
    headers: responseHeaders,
    body: await response.text(),
  };
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  const needle = name.toLowerCase();
  return Object.keys(headers).some((key) => key.toLowerCase() === needle);
}
