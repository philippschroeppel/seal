import { randomUUID } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { bytesToHex, randomBytes } from "@noble/ciphers/utils.js";
import { wipe } from "./bytes.js";
import type { RunResult, SpawnOptions } from "./child.js";
import { spawnChild } from "./child.js";
import { type ErrorCode, SealError } from "./errors.js";
import {
  approvalMode,
  type IdentityBinding,
  type Manifest,
  secretEnvKeys,
} from "./manifest.js";
import { OPENAPI_DOCUMENT } from "./openapi.js";
import { createCedarPdp, type PolicyDecisionPoint } from "./pdp.js";
import { ENV } from "./protocol.js";
import { generateKeyPair } from "./seal.js";
import type { SecretStore, SessionToken } from "./types.js";
import {
  attachBearer,
  fetchPeer,
  formatMatches,
  matchesPeer,
  normalizeMethod,
  parseHttpUrl,
  sanitizeAgentHeaders,
  signPayload,
  withUnsealedSecret,
} from "./use.js";

const BODY_LIMIT = 1_000_000;
const CHILD_SECRET_ENV = [
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "SSH_AUTH_SOCK",
  "GNUPGHOME",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_ACCESS_KEY_ID",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
];

export interface PendingIntent {
  readonly op: "http" | "sign";
  readonly identity: string;
  readonly detail: string;
}

export type Approver = (intent: PendingIntent) => Promise<boolean>;

export interface AgentSessionOptions {
  readonly store: SecretStore;
  readonly manifest: Manifest;
  readonly ttlMs?: number;
  readonly sessionId?: string;
  readonly approve?: Approver;
  readonly fetch?: typeof fetch;
}

export interface AgentSession {
  readonly url: string;
  readonly token: SessionToken;
  readonly sessionId: string;
  close(): void;
}

export interface RunManifestOptions extends AgentSessionOptions, SpawnOptions {}

export interface HttpIntent {
  readonly identity: string;
  readonly method: string;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export interface SignIntent {
  readonly identity: string;
  readonly payload: string;
  readonly format: string;
}

interface SessionState {
  readonly store: SecretStore;
  readonly grantId: string;
  readonly secretKey: Uint8Array;
  readonly token: SessionToken;
  readonly sessionId: string;
  readonly identities: ReadonlyMap<string, IdentityBinding>;
  readonly pdp: PolicyDecisionPoint;
  readonly approve?: Approver;
  readonly fetch: typeof fetch;
  readonly unlocked: Set<string>;
}

export async function startAgentSession(
  options: AgentSessionOptions,
): Promise<AgentSession> {
  const ttlMs = options.ttlMs ?? options.manifest.ttlMs;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("ttlMs must be a positive number");
  }
  if (options.manifest.identities.length === 0) {
    throw new Error("manifest identities must not be empty");
  }

  const grantId = randomUUID();
  const sessionId = options.sessionId ?? options.manifest.sessionId ?? grantId;
  const token: SessionToken = bytesToHex(randomBytes(16));
  const { publicKey, secretKey } = generateKeyPair();
  const secretNames = options.manifest.identities.map(
    (identity) => identity.secret,
  );
  options.store.issueGrant(grantId, secretNames, publicKey, ttlMs);

  const pdp = await createCedarPdp({
    policies: options.manifest.policies,
    ...(options.manifest.schema === undefined
      ? {}
      : { schema: options.manifest.schema }),
    identities: options.manifest.identities.map((identity) => identity.name),
    sessionId,
  });

  const state: SessionState = {
    store: options.store,
    grantId,
    secretKey,
    token,
    sessionId,
    identities: new Map(
      options.manifest.identities.map((identity) => [identity.name, identity]),
    ),
    pdp,
    ...(options.approve ? { approve: options.approve } : {}),
    fetch: options.fetch ?? globalThis.fetch,
    unlocked: new Set(),
  };

  const server = createServer((req, res) => {
    void handleHttp(req, res, state);
  });

  const { url } = await listenLoopback(server);

  const expire = () => {
    options.store.revokeGrant(grantId);
    wipe(secretKey);
  };

  let closed = false;
  const close = () => {
    if (closed) {
      return;
    }
    closed = true;
    clearTimeout(ttlTimer);
    expire();
    server.close();
  };

  const ttlTimer = setTimeout(expire, ttlMs);

  return { url, token, sessionId, close };
}

export async function runWithManifest(
  options: RunManifestOptions,
): Promise<RunResult> {
  const session = await startAgentSession(options);
  try {
    return await spawnChild(
      options,
      {
        [ENV.url]: session.url,
        [ENV.token]: session.token,
      },
      [ENV.socket, ...CHILD_SECRET_ENV, ...secretEnvKeys(options.manifest)],
    );
  } finally {
    session.close();
  }
}

async function handleHttp(
  req: IncomingMessage,
  res: ServerResponse,
  state: SessionState,
): Promise<void> {
  try {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (isSecretPath(url.pathname)) {
      sendError(res, 404, "not_granted", "secrets are not disclosed to agents");
      return;
    }

    if (!authorize(req, state.token)) {
      sendError(res, 401, "unauthorized", "unauthorized");
      return;
    }

    if (req.method === "GET" && url.pathname === "/v1/capabilities") {
      sendJson(res, 200, capabilities(state));
      return;
    }
    if (
      req.method === "GET" &&
      (url.pathname === "/v1/openapi.json" || url.pathname === "/openapi.json")
    ) {
      sendJson(res, 200, OPENAPI_DOCUMENT);
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/http") {
      const intent = parseHttpIntent(await readJson(req));
      sendJson(res, 200, await performHttp(state, intent));
      return;
    }
    if (req.method === "POST" && url.pathname === "/v1/sign") {
      const intent = parseSignIntent(await readJson(req));
      sendJson(res, 200, await performSign(state, intent));
      return;
    }

    sendError(res, 404, "bad_request", "unknown endpoint");
  } catch (error) {
    writeSealError(res, error);
  }
}

async function performHttp(
  state: SessionState,
  intent: HttpIntent,
): Promise<Record<string, unknown>> {
  const identity = requireIdentity(state, intent.identity);
  if (identity.attach.type !== "bearer") {
    throw new SealError("unsupported_op", "identity cannot perform http");
  }
  const method = normalizeMethod(intent.method);
  parseHttpUrl(intent.url);
  if (!matchesPeer(intent.url, identity.peers)) {
    throw new SealError("forbidden", "identity is not bound to that peer");
  }

  const userApproved = await resolveApproval(state, identity, {
    op: "http",
    identity: identity.name,
    detail: `${method} ${intent.url}`,
  });
  authorizeUse(state, {
    action: "Http",
    identity: identity.name,
    context: { url: intent.url, method, userApproved },
  });

  const headers = sanitizeAgentHeaders(intent.headers);
  const result = withUnsealedSecret(
    state.store,
    state.grantId,
    state.secretKey,
    identity.secret,
    (secret) =>
      fetchPeer(
        { method, url: intent.url, body: intent.body },
        attachBearer(identity, headers, secret),
        state.fetch,
      ),
  );
  return { ok: true, ...(await result) };
}

async function performSign(
  state: SessionState,
  intent: SignIntent,
): Promise<Record<string, unknown>> {
  const identity = requireIdentity(state, intent.identity);
  if (!formatMatches(identity.attach, intent.format)) {
    throw new SealError(
      "unsupported_op",
      "identity cannot sign with that format",
    );
  }

  const userApproved = await resolveApproval(state, identity, {
    op: "sign",
    identity: identity.name,
    detail: `${intent.format} ${truncate(intent.payload)}`,
  });
  authorizeUse(state, {
    action: "Sign",
    identity: identity.name,
    context: { format: intent.format, userApproved },
  });

  const signature = withUnsealedSecret(
    state.store,
    state.grantId,
    state.secretKey,
    identity.secret,
    (secret) => signPayload(identity.attach, intent.payload, secret),
  );
  return { ok: true, signature };
}

function authorizeUse(
  state: SessionState,
  request: {
    action: "Http" | "Sign";
    identity: string;
    context: {
      url?: string;
      method?: string;
      format?: string;
      userApproved: boolean;
    };
  },
): void {
  if (!state.store.fetchGrant(state.grantId)) {
    throw new SealError("grant_expired", "grant expired or revoked");
  }
  const allowed = state.pdp.isAllowed({
    sessionId: state.sessionId,
    action: request.action,
    identity: request.identity,
    context: request.context,
  });
  if (allowed) {
    return;
  }
  if (
    !request.context.userApproved &&
    state.pdp.isAllowed({
      sessionId: state.sessionId,
      action: request.action,
      identity: request.identity,
      context: { ...request.context, userApproved: true },
    })
  ) {
    throw new SealError("approval_required", "human approval required");
  }
  throw new SealError("forbidden", "denied by policy");
}

async function resolveApproval(
  state: SessionState,
  identity: IdentityBinding,
  intent: PendingIntent,
): Promise<boolean> {
  const mode = approvalMode(identity);
  if (mode === "never") {
    return false;
  }
  if (mode === "once" && state.unlocked.has(identity.name)) {
    return true;
  }

  const needsPrompt =
    !state.pdp.isAllowed({
      sessionId: state.sessionId,
      action: intent.op === "http" ? "Http" : "Sign",
      identity: identity.name,
      context: contextFromIntent(intent, false),
    }) &&
    state.pdp.isAllowed({
      sessionId: state.sessionId,
      action: intent.op === "http" ? "Http" : "Sign",
      identity: identity.name,
      context: contextFromIntent(intent, true),
    });

  if (!needsPrompt) {
    return false;
  }
  if (!state.approve) {
    return false;
  }
  const approved = await state.approve(intent);
  if (approved && mode === "once") {
    state.unlocked.add(identity.name);
  }
  return approved;
}

function contextFromIntent(
  intent: PendingIntent,
  userApproved: boolean,
): {
  url?: string;
  method?: string;
  format?: string;
  userApproved: boolean;
} {
  if (intent.op === "http") {
    const [method = "", ...rest] = intent.detail.split(" ");
    return { method, url: rest.join(" "), userApproved };
  }
  const [format = ""] = intent.detail.split(" ");
  return { format, userApproved };
}

function capabilities(state: SessionState): Record<string, unknown> {
  const identities = [...state.identities.values()].map((identity) => {
    const ops: string[] = [];
    if (identity.attach.type === "bearer") {
      const allowed = (identity.peers ?? []).some((peer) =>
        httpProbes(peer).some(
          (url) =>
            state.pdp.isAllowed({
              sessionId: state.sessionId,
              action: "Http",
              identity: identity.name,
              context: { url, method: "GET", userApproved: false },
            }) ||
            state.pdp.isAllowed({
              sessionId: state.sessionId,
              action: "Http",
              identity: identity.name,
              context: { url, method: "GET", userApproved: true },
            }),
        ),
      );
      if (allowed) {
        ops.push("http");
      }
    } else if (
      state.pdp.isAllowed({
        sessionId: state.sessionId,
        action: "Sign",
        identity: identity.name,
        context: {
          format: identity.attach.type,
          userApproved: true,
        },
      })
    ) {
      ops.push("sign");
    }

    return {
      name: identity.name,
      ops,
      approve: approvalMode(identity),
      ...(identity.peers ? { peers: identity.peers } : {}),
      ...(identity.attach.type !== "bearer"
        ? { formats: [identity.attach.type] }
        : {}),
    };
  });

  return {
    ok: true,
    session: state.sessionId,
    ops: ["http", "sign"],
    identities,
    openapi: "/v1/openapi.json",
  };
}

function requireIdentity(state: SessionState, name: string): IdentityBinding {
  const identity = state.identities.get(name);
  if (!identity) {
    throw new SealError("not_granted", `unknown identity: ${name}`);
  }
  return identity;
}

function authorize(req: IncomingMessage, token: SessionToken): boolean {
  const header = req.headers.authorization;
  if (typeof header !== "string") {
    return false;
  }
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1] === token;
}

function parseHttpIntent(raw: unknown): HttpIntent {
  if (
    !isRecord(raw) ||
    typeof raw.identity !== "string" ||
    typeof raw.method !== "string" ||
    typeof raw.url !== "string"
  ) {
    throw new SealError(
      "bad_request",
      "request must be { identity, method, url }",
    );
  }
  if ("value" in raw) {
    throw new SealError("bad_request", "credential disclosure is not allowed");
  }
  const headers = isRecord(raw.headers)
    ? Object.fromEntries(
        Object.entries(raw.headers).filter(
          (entry): entry is [string, string] => typeof entry[1] === "string",
        ),
      )
    : undefined;
  return {
    identity: raw.identity,
    method: raw.method,
    url: raw.url,
    ...(headers ? { headers } : {}),
    ...("body" in raw ? { body: raw.body } : {}),
  };
}

function parseSignIntent(raw: unknown): SignIntent {
  if (
    !isRecord(raw) ||
    typeof raw.identity !== "string" ||
    typeof raw.payload !== "string" ||
    typeof raw.format !== "string"
  ) {
    throw new SealError(
      "bad_request",
      "request must be { identity, payload, format }",
    );
  }
  if ("value" in raw) {
    throw new SealError("bad_request", "credential disclosure is not allowed");
  }
  return {
    identity: raw.identity,
    payload: raw.payload,
    format: raw.format,
  };
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > BODY_LIMIT) {
      throw new SealError("bad_request", "body too large");
    }
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  if (text.length === 0) {
    throw new SealError("bad_request", "expected a JSON body");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new SealError("bad_request", "malformed JSON");
  }
}

function listenLoopback(server: Server): Promise<{ url: string }> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        reject(new Error("failed to bind loopback HTTP"));
        return;
      }
      resolve({ url: `http://127.0.0.1:${addr.port}` });
    });
  });
}

function isSecretPath(pathname: string): boolean {
  return (
    pathname === "/secrets" ||
    pathname.startsWith("/secrets/") ||
    pathname === "/v1/secrets" ||
    pathname.startsWith("/v1/secrets/")
  );
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

function sendError(
  res: ServerResponse,
  status: number,
  error: ErrorCode,
  message: string,
): void {
  sendJson(res, status, { ok: false, error, message });
}

function writeSealError(res: ServerResponse, error: unknown): void {
  if (error instanceof SealError) {
    sendError(res, statusFor(error.code), error.code, error.message);
    return;
  }
  sendError(
    res,
    500,
    "protocol",
    error instanceof Error ? error.message : "internal error",
  );
}

function statusFor(code: ErrorCode): number {
  switch (code) {
    case "bad_request":
      return 400;
    case "unauthorized":
    case "not_attached":
      return 401;
    case "forbidden":
    case "not_granted":
    case "approval_required":
    case "unsupported_op":
      return 403;
    case "grant_expired":
      return 410;
    case "peer_failed":
      return 502;
    default:
      return 400;
  }
}

function httpProbes(peer: string): string[] {
  const base = peer.endsWith("/") ? peer.slice(0, -1) : peer;
  return [
    peer,
    `${base}/`,
    `${base}/repos/probe`,
    `${base}/repos/acme/seal/issues`,
    `${base}/repos/philippschroeppel/seal/issues`,
    `${base}/user`,
  ];
}

function truncate(value: string): string {
  return value.length <= 64 ? value : `${value.slice(0, 61)}...`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
