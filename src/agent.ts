import { chmodSync, mkdirSync, mkdtempSync, rmSync, unlinkSync } from "node:fs";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { type RunResult, type SpawnOptions, spawnChild } from "./child.js";
import { type ErrorCode, SealError } from "./errors.js";
import type {
  PendingIntent,
  PutIntent,
  RequestIntent,
  UseIntent,
} from "./intents.js";
import {
  type IdentityBinding,
  identityAllowsPlugin,
  type Manifest,
  secretEnvKeys,
} from "./manifest.js";
import { getPlugin } from "./plugin.js";
import { ENV } from "./protocol.js";
import type { Sandbox } from "./sandbox.js";
import { openSessionLease } from "./session.js";
import { isRecord, type SecretStore, type SessionToken } from "./types.js";

export type {
  PendingIntent,
  PutIntent,
  RequestIntent,
  UseIntent,
} from "./intents.js";
export { formatPendingIntent } from "./intents.js";

const BODY_LIMIT = 1_000_000;
const CHILD_UNSET = ["SEAL_SOCK", "SSH_AUTH_SOCK", "GNUPGHOME"];

export interface Consent {
  readonly granted: boolean;
  readonly passphrase?: string;
  readonly secret?: string;
}

export type Consenter = (intent: PendingIntent) => Promise<Consent>;

export interface AgentSessionOptions {
  readonly store: SecretStore;
  readonly manifest: Manifest;
  readonly ttlMs?: number;
  readonly sessionId?: string;
  readonly passphrase?: string;
  readonly consent?: Consenter;
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
  readonly token: SessionToken;
  readonly sessionId: string;
  readonly passphrase?: string;
  readonly identities: Map<string, IdentityBinding>;
  readonly granted: Set<string>;
  readonly consent?: Consenter;
  readonly fetch: typeof fetch;
  expired: () => boolean;
}

export async function startAgentSession(
  options: AgentSessionOptions,
): Promise<AgentSession> {
  const ttlMs = options.ttlMs ?? options.manifest.ttlMs;
  const lease = openSessionLease({
    ttlMs,
    ...(options.sessionId
      ? { sessionId: options.sessionId }
      : options.manifest.sessionId
        ? { sessionId: options.manifest.sessionId }
        : {}),
  });

  const identities = new Map<string, IdentityBinding>();
  const granted = new Set<string>();
  for (const identity of options.manifest.identities) {
    if (!options.store.has(identity.secret)) {
      throw new SealError(
        "unknown_secret",
        `identity ${identity.name} is not in the store`,
      );
    }
    identities.set(identity.name, identity);
    granted.add(identity.name);
  }

  const passphrase = options.passphrase ?? options.manifest.passphrase;
  const state: SessionState = {
    store: options.store,
    token: lease.token,
    sessionId: lease.sessionId,
    ...(passphrase !== undefined ? { passphrase } : {}),
    identities,
    granted,
    ...(options.consent ? { consent: options.consent } : {}),
    fetch: options.fetch ?? globalThis.fetch,
    expired: lease.expired,
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
    sessionId: lease.sessionId,
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

    if (state.expired()) {
      throw new SealError("grant_expired", "session expired");
    }

    if (req.method === "POST" && url.pathname === "/v1/use") {
      const intent = parseUseIntent(await readJson(req));
      sendJson(res, 200, { ok: true, result: await performUse(state, intent) });
      return;
    }
    if (req.method === "POST" && url.pathname === "/v1/put") {
      const intent = parsePutIntent(await readJson(req));
      sendJson(res, 200, { ok: true, ...(await performPut(state, intent)) });
      return;
    }
    if (req.method === "POST" && url.pathname === "/v1/request") {
      const intent = parseRequestIntent(await readJson(req));
      sendJson(res, 200, {
        ok: true,
        ...(await performRequest(state, intent)),
      });
      return;
    }

    sendError(res, 404, "bad_request", "unknown endpoint");
  } catch (error) {
    writeSealError(res, error);
  }
}

async function performUse(
  state: SessionState,
  intent: UseIntent,
): Promise<unknown> {
  if (!state.granted.has(intent.identity)) {
    throw new SealError(
      "not_granted",
      `identity ${intent.identity} is not granted; call request`,
    );
  }
  const identity = requireIdentity(state, intent.identity);
  if (!identityAllowsPlugin(identity, intent.plugin)) {
    throw new SealError(
      "unsupported_op",
      `identity ${identity.name} cannot use plugin ${intent.plugin}`,
    );
  }
  const plugin = getPlugin(intent.plugin);
  return state.store.use(identity.secret, (secret) =>
    plugin.use(secret, intent.input, {
      identity,
      fetch: state.fetch,
    }),
  );
}

async function performPut(
  state: SessionState,
  intent: PutIntent,
): Promise<{ name: string }> {
  const pending: PendingIntent = {
    op: "put",
    identity: intent.name,
    needsSecret: true,
    ...(intent.plugin ? { plugin: intent.plugin } : {}),
    ...(intent.peers ? { peers: intent.peers } : {}),
    ...(intent.format ? { format: intent.format } : {}),
  };
  const consent = await askConsent(state, pending);
  const value = consent.secret;
  if (!value) {
    throw new SealError("approval_required", "secret value is required to put");
  }

  const binding = bindingFromIntent(intent.name, intent, state);
  state.store.put(binding.secret, value);
  state.identities.set(binding.name, binding);
  state.granted.delete(binding.name);
  return { name: binding.name };
}

async function performRequest(
  state: SessionState,
  intent: RequestIntent,
): Promise<{ granted: true; name: string }> {
  if (state.granted.has(intent.name) && state.identities.has(intent.name)) {
    return { granted: true, name: intent.name };
  }

  const existing = state.identities.get(intent.name);
  const inStore = existing
    ? state.store.has(existing.secret)
    : state.store.has(intent.name);
  const pending: PendingIntent = {
    op: "request",
    identity: intent.name,
    needsSecret: !inStore,
    ...(intent.plugin ? { plugin: intent.plugin } : {}),
    ...(intent.peers ? { peers: intent.peers } : {}),
    ...(intent.format ? { format: intent.format } : {}),
    ...(intent.reason ? { reason: intent.reason } : {}),
  };

  const consent = await askConsent(state, pending);
  if (
    state.passphrase !== undefined &&
    consent.passphrase !== state.passphrase
  ) {
    throw new SealError("approval_required", "passphrase did not match");
  }

  const binding = existing ?? bindingFromIntent(intent.name, intent, state);
  if (!inStore) {
    if (!consent.secret) {
      throw new SealError(
        "approval_required",
        "secret value is required to grant a new name",
      );
    }
    state.store.put(binding.secret, consent.secret);
  }

  state.identities.set(binding.name, binding);
  state.granted.add(binding.name);
  return { granted: true, name: binding.name };
}

async function askConsent(
  state: SessionState,
  intent: PendingIntent,
): Promise<Consent> {
  if (!state.consent) {
    throw new SealError("approval_required", "human consent required");
  }
  const consent = await state.consent(intent);
  if (!consent.granted) {
    throw new SealError("approval_required", "human consent required");
  }
  if (intent.op === "request" && !consent.passphrase) {
    throw new SealError("approval_required", "consent requires a passphrase");
  }
  return consent;
}

function bindingFromIntent(
  name: string,
  intent: { plugin?: string; peers?: readonly string[]; format?: string },
  state: SessionState,
): IdentityBinding {
  const existing = state.identities.get(name);
  if (existing) {
    return {
      ...existing,
      ...(intent.plugin
        ? {
            plugins: unique([...(existing.plugins ?? []), intent.plugin]),
          }
        : {}),
      ...(intent.peers ? { peers: intent.peers } : {}),
      ...(intent.format ? { format: intent.format } : {}),
    };
  }
  return {
    name,
    secret: name,
    ...(intent.plugin ? { plugins: [intent.plugin] } : {}),
    ...(intent.peers ? { peers: intent.peers } : {}),
    ...(intent.format ? { format: intent.format } : {}),
  };
}

function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
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

function parseUseIntent(raw: unknown): UseIntent {
  if (
    !isRecord(raw) ||
    typeof raw.plugin !== "string" ||
    typeof raw.identity !== "string"
  ) {
    throw new SealError(
      "bad_request",
      "request must be { plugin, identity, input }",
    );
  }
  refuseDisclosure(raw);
  return {
    plugin: raw.plugin,
    identity: raw.identity,
    input: "input" in raw ? raw.input : {},
  };
}

function parsePutIntent(raw: unknown): PutIntent {
  if (!isRecord(raw) || typeof raw.name !== "string") {
    throw new SealError("bad_request", "request must be { name }");
  }
  refuseDisclosure(raw);
  return namedBinding(raw);
}

function parseRequestIntent(raw: unknown): RequestIntent {
  if (!isRecord(raw) || typeof raw.name !== "string") {
    throw new SealError("bad_request", "request must be { name }");
  }
  refuseDisclosure(raw);
  return {
    ...namedBinding(raw),
    ...(typeof raw.reason === "string" ? { reason: raw.reason } : {}),
  };
}

function namedBinding(raw: Record<string, unknown>): PutIntent {
  const peers = Array.isArray(raw.peers)
    ? raw.peers.filter((peer): peer is string => typeof peer === "string")
    : undefined;
  return {
    name: raw.name as string,
    ...(typeof raw.plugin === "string" ? { plugin: raw.plugin } : {}),
    ...(peers && peers.length > 0 ? { peers } : {}),
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
