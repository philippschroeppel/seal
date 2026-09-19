import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bytesToHex, randomBytes } from "@noble/ciphers/utils.js";
import { wipe } from "./bytes.js";
import type { ErrorCode } from "./errors.js";
import {
  createLineReader,
  type DecryptResponse,
  ENV,
  encodeLine,
  parseDecryptRequest,
} from "./protocol.js";
import { generateKeyPair, unseal } from "./seal.js";
import { decryptValue } from "./store.js";
import type {
  ClientConnection,
  SecretName,
  SecretStore,
  SessionToken,
} from "./types.js";

export interface BrokerOptions {
  readonly store: SecretStore;
  readonly secretNames: readonly SecretName[];
  readonly ttlMs: number;
}

export interface Broker extends ClientConnection {
  close(): void;
}

export interface RunOptions extends BrokerOptions {
  readonly command: string;
  readonly args?: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly stdio?: "inherit" | "pipe";
}

export interface RunResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

/**
 * Open a Unix socket that unwraps DEKs for one grant, then forgets the
 * recipient secret key when the TTL elapses or `close()` is called.
 */
export async function startBroker(options: BrokerOptions): Promise<Broker> {
  const { store, secretNames, ttlMs } = options;
  if (secretNames.length === 0) {
    throw new Error("secretNames must not be empty");
  }
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("ttlMs must be a positive number");
  }

  const grantId = randomUUID();
  const token: SessionToken = bytesToHex(randomBytes(16));
  const { publicKey, secretKey } = generateKeyPair();
  store.issueGrant(grantId, secretNames, publicKey, ttlMs);

  const socketPath = join(tmpdir(), `seal-${grantId}.sock`);
  if (existsSync(socketPath)) {
    unlinkSync(socketPath);
  }

  const sockets = new Set<Socket>();
  const server = createServer((conn) => {
    sockets.add(conn);
    conn.on("close", () => sockets.delete(conn));
    conn.on("error", () => conn.destroy());
    conn.on(
      "data",
      createLineReader((line) => {
        conn.write(
          encodeLine(handleRequest(line, token, grantId, store, secretKey)),
        );
      }),
    );
  });

  await listenUnix(server, socketPath);

  const expire = () => {
    store.revokeGrant(grantId);
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
    for (const socket of sockets) {
      socket.destroy();
    }
    server.close();
    if (existsSync(socketPath)) {
      unlinkSync(socketPath);
    }
  };

  // Revoke and drop the unsealing key at TTL, but keep the socket so a
  // still-running child gets a typed `grant_expired` instead of ENOENT.
  const ttlTimer = setTimeout(expire, ttlMs);

  return { socketPath, token, close };
}

export async function runWithGrant(options: RunOptions): Promise<RunResult> {
  const broker = await startBroker(options);
  try {
    return await spawnChild(options, broker);
  } finally {
    broker.close();
  }
}

function handleRequest(
  line: string,
  token: SessionToken,
  grantId: string,
  store: SecretStore,
  secretKey: Uint8Array,
): DecryptResponse {
  let request: ReturnType<typeof parseDecryptRequest>;
  try {
    request = parseDecryptRequest(line);
  } catch {
    return fail("bad_request", "malformed request");
  }

  if (request.token !== token) {
    return fail("unauthorized", "unauthorized");
  }

  const grant = store.fetchGrant(grantId);
  if (!grant) {
    return fail("grant_expired", "grant expired or revoked");
  }

  const entry = grant.entries.find((item) => item.name === request.name);
  if (!entry) {
    return fail("not_granted", "not granted");
  }

  try {
    const dek = unseal(entry.wrappedDek, secretKey);
    try {
      return { ok: true, value: decryptValue(entry, dek) };
    } finally {
      wipe(dek);
    }
  } catch {
    return fail("decrypt_failed", "failed to decrypt secret");
  }
}

function fail(error: ErrorCode, message: string): DecryptResponse {
  return { ok: false, error, message };
}

function listenUnix(
  server: ReturnType<typeof createServer>,
  socketPath: string,
): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      try {
        chmodSync(socketPath, 0o600);
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  });
}

function spawnChild(
  options: RunOptions,
  broker: ClientConnection,
): Promise<RunResult> {
  const child = spawn(options.command, options.args ?? [], {
    stdio: options.stdio ?? "inherit",
    env: {
      ...process.env,
      ...options.env,
      [ENV.socket]: broker.socketPath,
      [ENV.token]: broker.token,
    },
  });

  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    stdout += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });

  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => {
      resolve({ exitCode: code ?? 1, stdout, stderr });
    });
  });
}
