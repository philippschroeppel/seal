import { randomUUID } from "node:crypto";
import { bytesToHex, randomBytes } from "@noble/ciphers/utils.js";
import type { SessionToken } from "./types.js";

export interface SessionLease {
  readonly sessionId: string;
  readonly token: SessionToken;
  expired(): boolean;
  expire(): void;
  close(cleanup: () => void): void;
}

/**
 * Session token + TTL. On expiry or close the token stops working and
 * the caller wipes whatever it was holding.
 */
export function openSessionLease(options: {
  readonly ttlMs: number;
  readonly sessionId?: string;
}): SessionLease {
  const { ttlMs } = options;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("ttlMs must be a positive number");
  }

  const sessionId = options.sessionId ?? randomUUID();
  const token: SessionToken = bytesToHex(randomBytes(16));
  let dead = false;

  const expire = () => {
    dead = true;
  };

  let closed = false;
  const ttlTimer = setTimeout(expire, ttlMs);

  return {
    sessionId,
    token,
    expired: () => dead,
    expire,
    close(cleanup) {
      if (closed) {
        return;
      }
      closed = true;
      clearTimeout(ttlTimer);
      expire();
      cleanup();
    },
  };
}
