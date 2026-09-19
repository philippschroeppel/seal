import { chmodSync, existsSync, unlinkSync } from "node:fs";
import { createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type RunResult, type SpawnOptions, spawnChild } from "./child.js";
import { type ErrorCode, SealError } from "./errors.js";
import {
  createLineReader,
  type DecryptResponse,
  ENV,
  encodeLine,
  parseDecryptRequest,
} from "./protocol.js";
import { openGrantLease } from "./session.js";
import type {
  ClientConnection,
  SecretName,
  SecretStore,
  SessionToken,
} from "./types.js";
import { withUnsealedSecret } from "./use.js";

export interface BrokerOptions {
  readonly store: SecretStore;
  readonly secretNames: readonly SecretName[];
  readonly ttlMs: number;
}

export interface Broker extends ClientConnection {
  close(): void;
}

export interface RunOptions extends BrokerOptions, SpawnOptions {}

export type { RunResult };

/**
 * Open a Unix socket that unwraps DEKs for one grant, then forgets the
 * recipient secret key when the TTL elapses or `close()` is called.
 */
export async function startBroker(options: BrokerOptions): Promise<Broker> {
  const lease = openGrantLease(options);
  const socketPath = join(tmpdir(), `seal-${lease.grantId}.sock`);
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
          encodeLine(
            handleRequest(
              line,
              lease.token,
              lease.grantId,
              options.store,
              lease.secretKey,
            ),
          ),
        );
      }),
    );
  });

  await listenUnix(server, socketPath);

  return {
    socketPath,
    token: lease.token,
    close: () =>
      lease.close(() => {
        for (const socket of sockets) {
          socket.destroy();
        }
        server.close();
        if (existsSync(socketPath)) {
          unlinkSync(socketPath);
        }
      }),
  };
}

export async function runWithGrant(options: RunOptions): Promise<RunResult> {
  const broker = await startBroker(options);
  try {
    return await spawnChild(options, {
      [ENV.socket]: broker.socketPath,
      [ENV.token]: broker.token,
    });
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

  try {
    return {
      ok: true,
      value: withUnsealedSecret(
        store,
        grantId,
        secretKey,
        request.name,
        (value) => value,
      ),
    };
  } catch (error) {
    if (error instanceof SealError) {
      if (error.code === "grant_expired" || error.code === "not_granted") {
        return fail(error.code, error.message);
      }
    }
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
