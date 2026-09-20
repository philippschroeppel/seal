import { SealError } from "../errors.js";
import type { Plugin } from "../plugin.js";
import { isRecord } from "../types.js";
import {
  attachBearer,
  fetchPeer,
  matchesPeer,
  normalizeMethod,
  parseHttpUrl,
  sanitizeAgentHeaders,
} from "../use.js";

export const httpPlugin: Plugin = {
  name: "http",
  use(secret, input, ctx) {
    const request = parseHttpInput(input);
    parseHttpUrl(request.url);
    if (!matchesPeer(request.url, ctx.identity.peers)) {
      throw new SealError("forbidden", "identity is not bound to that peer");
    }
    const headers = sanitizeAgentHeaders(request.headers);
    return fetchPeer(
      request,
      attachBearer(ctx.identity, headers, secret),
      ctx.fetch,
    );
  },
};

export function parseHttpInput(input: unknown): {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
} {
  if (
    !isRecord(input) ||
    typeof input.method !== "string" ||
    typeof input.url !== "string"
  ) {
    throw new SealError("bad_request", "http input must be { method, url }");
  }
  const headers = isRecord(input.headers)
    ? Object.fromEntries(
        Object.entries(input.headers).filter(
          (entry): entry is [string, string] => typeof entry[1] === "string",
        ),
      )
    : undefined;
  return {
    method: normalizeMethod(input.method),
    url: input.url,
    ...(headers ? { headers } : {}),
    ...("body" in input ? { body: input.body } : {}),
  };
}
