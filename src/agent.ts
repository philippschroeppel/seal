import { chmodSync, mkdirSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { RunResult, SpawnOptions } from "./child.js";
import { spawnChild } from "./child.js";
import { type ErrorCode, SealError } from "./errors.js";
import type {
  CheckIntent,
  CheckResult,
  HttpIntent,
  PendingIntent,
  SessionCapabilities,
  SignIntent,
} from "./intents.js";
import {
  approvalMode,
  type IdentityBinding,
  type Manifest,
  secretEnvKeys,
} from "./manifest.js";
import { OPENAPI_DOCUMENT } from "./openapi.js";
import { createCedarPdp, type PolicyDecisionPoint } from "./pdp.js";
import { ENV } from "./protocol.js";
import type { Sandbox } from "./sandbox.js";
import { openGrantLease } from "./session.js";
import { isRecord, type SecretStore, type SessionToken } from "./types.js";
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

export type {
  CheckIntent,
  CheckResult,
  HttpIntent,
  PendingIntent,
  SignIntent,
} from "./intents.js";
export { formatPendingIntent } from "./intents.js";

const BODY_LIMIT = 1_000_000;
const CHILD_UNSET = ["SEAL_SOCK", "SSH_AUTH_SOCK", "GNUPGHOME"];

export type Approver = (intent: PendingIntent) => Promise<boolean>;

export interface AgentSessionOptions {
  readonly store: SecretStore;
  readonly manifest: Manifest;
  readonly ttlMs?: number;
  readonly sessionId?: string;
  readonly approve?: Approver;
  readonly fetch?: typeof fetch;
  readonly sandbox?: Sandbox;
  readonly socketPath?: string;
}

export interface AgentSession {
  readonly url: string;
  readonly token: SessionToken;
  readonly sessionId: string;
  close(): void;
}

export interface RunManifestOptions extends AgentSessionOptions, SpawnOptions {}

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
  if (options.manifest.identities.length === 0) {
    throw new Error("manifest identities must not be empty");
  }

  const ttlMs = options.ttlMs ?? options.manifest.ttlMs;
  const lease = openGrantLease({
    store: options.store,
    secretNames: options.manifest.identities.map((identity) => identity.secret),
    ttlMs,
  });
  const sessionId =
    options.sessionId ?? options.manifest.sessionId ?? lease.grantId;

  const pdp = await createCedarPdp({
    policies: options.manifest.policies,
    identities: options.manifest.identities.map((identity) => identity.name),
    sessionId,
  });

  const state: SessionState = {
    store: options.store,
    grantId: lease.grantId,
    secretKey: lease.secretKey,
    token: lease.token,
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

  const socketPath = options.socketPath;
  const { url } = socketPath
    ? await listenUnix(server, socketPath)
    : await listenLoopback(server);

  return {
    url,
    token: lease.token,
    sessionId,
    close: () =>
      lease.close(() => {
        server.close();
        if (socketPath) {
          try {
            unlinkSync(socketPath);
          } catch {
            /* already gone */
          }
        }
      }),
  };
}

export async function runWithManifest(
  options: RunManifestOptions,
): Promise<RunResult> {
  const sandbox = options.sandbox ?? options.manifest.sandbox;
  const socketDir = sandbox
    ? mkdtempSync(join(tmpdir(), "seal-http-"))
    : undefined;
  const session = await startAgentSession({
    ...options,
    ...(sandbox ? { sandbox } : {}),
    ...(socketDir ? { socketPath: join(socketDir, "http.sock") } : {}),
  });
  try {
    return await spawnChild(
      {
        ...options,
        ...(sandbox ? { sandbox } : {}),
        ...(socketDir ? { bindDirs: [socketDir] } : {}),
      },
      {
        [ENV.url]: session.url,
        [ENV.token]: session.token,
      },
      [...CHILD_UNSET, ...secretEnvKeys(options.manifest)],
    );
  } finally {
    session.close();
    if (socketDir) {
      rmSync(socketDir, { recursive: true, force: true });
    }
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
      sendJson(res, 200, { ok: true, ...capabilities(state) });
      return;
    }
    if (req.method === "GET" && url.pathname === "/v1/openapi.json") {
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
    if (req.method === "POST" && url.pathname === "/v1/check") {
      const intent = parseCheckIntent(await readJson(req));
      sendJson(res, 200, { ok: true, ...performCheck(state, intent) });
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
  const bound = bindHttp(state, intent.identity, intent.method, intent.url);
  await authorizeUse(state, bound.identity, {
    op: "http",
    identity: bound.identity.name,
    method: bound.method,
    url: bound.url,
  });

  const headers = sanitizeAgentHeaders(intent.headers);
  const result = withUnsealedSecret(
    state.store,
    state.grantId,
    state.secretKey,
    bound.identity.secret,
    (secret) =>
      fetchPeer(
        { method: bound.method, url: bound.url, body: intent.body },
        attachBearer(bound.identity, headers, secret),
        state.fetch,
      ),
  );
  return { ok: true, ...(await result) };
}

async function performSign(
  state: SessionState,
  intent: SignIntent,
): Promise<Record<string, unknown>> {
  const bound = bindSign(state, intent.identity, intent.format);
  await authorizeUse(state, bound.identity, {
    op: "sign",
    identity: bound.identity.name,
    format: bound.format,
    payloadPreview: truncate(intent.payload),
  });

  const signature = withUnsealedSecret(
    state.store,
    state.grantId,
    state.secretKey,
    bound.identity.secret,
    (secret) => signPayload(bound.identity.attach, intent.payload, secret),
  );
  return { ok: true, signature };
}

function performCheck(state: SessionState, intent: CheckIntent): CheckResult {
  if (intent.op === "http") {
    const bound = bindHttp(
      state,
      intent.identity,
      intent.method ?? "",
      intent.url ?? "",
    );
    return decide(state, bound.identity, {
      op: "http",
      identity: bound.identity.name,
      method: bound.method,
      url: bound.url,
    });
  }

  const bound = bindSign(state, intent.identity, intent.format ?? "");
  return decide(state, bound.identity, {
    op: "sign",
    identity: bound.identity.name,
    format: bound.format,
  });
}

function bindHttp(
  state: SessionState,
  identityName: string,
  method: string,
  url: string,
): { identity: IdentityBinding; method: string; url: string } {
  const identity = requireIdentity(state, identityName);
  if (identity.attach.type !== "bearer") {
    throw new SealError("unsupported_op", "identity cannot perform http");
  }
  const normalized = normalizeMethod(method);
  parseHttpUrl(url);
  if (!matchesPeer(url, identity.peers)) {
    throw new SealError("forbidden", "identity is not bound to that peer");
  }
  return { identity, method: normalized, url };
}

function bindSign(
  state: SessionState,
  identityName: string,
  format: string,
): { identity: IdentityBinding; format: string } {
  const identity = requireIdentity(state, identityName);
  if (!formatMatches(identity.attach, format)) {
    throw new SealError(
      "unsupported_op",
      "identity cannot sign with that format",
    );
  }
  return { identity, format };
}

function decide(
  state: SessionState,
  identity: IdentityBinding,
  intent: PendingIntent,
): CheckResult {
  const outcome = policyOutcome(state, identity, intent);
  if (outcome === "allow") {
    return { allowed: true };
  }
  return { allowed: false, reason: outcome };
}

async function authorizeUse(
  state: SessionState,
  identity: IdentityBinding,
  intent: PendingIntent,
): Promise<void> {
  const outcome = policyOutcome(state, identity, intent);
  if (outcome === "allow") {
    return;
  }
  if (outcome === "forbidden") {
    throw new SealError("forbidden", "denied by policy");
  }

  const mode = approvalMode(identity);
  if (mode === "never" || !state.approve) {
    throw new SealError("approval_required", "human approval required");
  }
  const approved = await state.approve(intent);
  if (!approved) {
    throw new SealError("approval_required", "human approval required");
  }
  if (mode === "once") {
    state.unlocked.add(identity.name);
  }
}

function policyOutcome(
  state: SessionState,
  identity: IdentityBinding,
  intent: PendingIntent,
): "allow" | "approval_required" | "forbidden" {
  if (!state.store.fetchGrant(state.grantId)) {
    throw new SealError("grant_expired", "grant expired or revoked");
  }

  const action = intent.op === "http" ? "Http" : "Sign";
  const context =
    intent.op === "http"
      ? { url: intent.url ?? "", method: intent.method ?? "" }
      : { format: intent.format ?? "" };
  const unlocked =
    approvalMode(identity) === "once" && state.unlocked.has(identity.name);

  if (
    state.pdp.isAllowed({
      sessionId: state.sessionId,
      action,
      identity: identity.name,
      context: { ...context, userApproved: unlocked },
    })
  ) {
    return "allow";
  }
  if (
    state.pdp.isAllowed({
      sessionId: state.sessionId,
      action,
      identity: identity.name,
      context: { ...context, userApproved: true },
    })
  ) {
    return "approval_required";
  }
  return "forbidden";
}

function capabilities(state: SessionState): SessionCapabilities {
  const identities = [...state.identities.values()].map((identity) => {
    const http = identity.attach.type === "bearer";
    return {
      name: identity.name,
      ops: http ? ["http"] : ["sign"],
      approve: approvalMode(identity),
      ...(identity.peers ? { peers: identity.peers } : {}),
      ...(!http ? { formats: [identity.attach.type] } : {}),
    };
  });

  return {
    session: state.sessionId,
    ops: [...new Set(identities.flatMap((identity) => identity.ops))],
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
  refuseDisclosure(raw);
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
  refuseDisclosure(raw);
  return {
    identity: raw.identity,
    payload: raw.payload,
    format: raw.format,
  };
}

function parseCheckIntent(raw: unknown): CheckIntent {
  if (
    !isRecord(raw) ||
    (raw.op !== "http" && raw.op !== "sign") ||
    typeof raw.identity !== "string"
  ) {
    throw new SealError("bad_request", "request must be { op, identity }");
  }
  refuseDisclosure(raw);
  if (raw.op === "http") {
    return {
      op: "http",
      identity: raw.identity,
      ...(typeof raw.method === "string" ? { method: raw.method } : {}),
      ...(typeof raw.url === "string" ? { url: raw.url } : {}),
    };
  }
  return {
    op: "sign",
    identity: raw.identity,
    ...(typeof raw.format === "string" ? { format: raw.format } : {}),
  };
}

function refuseDisclosure(raw: Record<string, unknown>): void {
  if ("value" in raw) {
    throw new SealError("bad_request", "credential disclosure is not allowed");
  }
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

function listenLoopback(
  server: ReturnType<typeof createServer>,
): Promise<{ url: string }> {
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

function listenUnix(
  server: ReturnType<typeof createServer>,
  socketPath: string,
): Promise<{ url: string }> {
  mkdirSync(dirname(socketPath), { recursive: true });
  try {
    unlinkSync(socketPath);
  } catch {
    /* first listen */
  }
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      chmodSync(socketPath, 0o600);
      resolve({ url: `unix://${socketPath}` });
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

function truncate(value: string): string {
  return value.length <= 64 ? value : `${value.slice(0, 61)}...`;
}
