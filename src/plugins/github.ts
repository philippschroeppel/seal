import { SealError } from "../errors.js";
import type { Plugin } from "../plugin.js";
import { isRecord } from "../types.js";
import {
  attachBearer,
  fetchPeer,
  matchesPeer,
  normalizeMethod,
} from "../use.js";

const GITHUB_API = "https://api.github.com";
const DEFAULT_PEERS = [`${GITHUB_API}/`];

export const githubPlugin: Plugin = {
  name: "github",
  use(secret, input, ctx) {
    const request = parseGithubInput(input);
    const peers = ctx.identity.peers ?? DEFAULT_PEERS;
    if (!matchesPeer(request.url, peers)) {
      throw new SealError("forbidden", "identity is not bound to that peer");
    }
    return fetchPeer(
      request,
      attachBearer(
        ctx.identity,
        { Accept: "application/vnd.github+json" },
        secret,
      ),
      ctx.fetch,
    );
  },
};

function parseGithubInput(input: unknown): {
  method: string;
  url: string;
  body?: unknown;
} {
  if (!isRecord(input)) {
    throw new SealError("bad_request", "github input must be an object");
  }

  if (input.op === "createPullRequest") {
    if (
      typeof input.repo !== "string" ||
      typeof input.title !== "string" ||
      typeof input.head !== "string" ||
      typeof input.base !== "string"
    ) {
      throw new SealError(
        "bad_request",
        "createPullRequest needs { repo, title, head, base }",
      );
    }
    return {
      method: "POST",
      url: `${GITHUB_API}/repos/${input.repo}/pulls`,
      body: {
        title: input.title,
        head: input.head,
        base: input.base,
        ...(typeof input.body === "string" ? { body: input.body } : {}),
      },
    };
  }

  if (typeof input.path !== "string") {
    throw new SealError(
      "bad_request",
      'github input must be { path } or { op: "createPullRequest", ... }',
    );
  }
  const path = input.path.startsWith("/") ? input.path : `/${input.path}`;
  return {
    method: normalizeMethod(
      typeof input.method === "string" ? input.method : "GET",
    ),
    url: `${GITHUB_API}${path}`,
    ...("body" in input ? { body: input.body } : {}),
  };
}
