import { randomUUID } from "node:crypto";
import { bytesToHex, randomBytes } from "@noble/ciphers/utils.js";
import { wipe } from "./bytes.js";
import { generateKeyPair } from "./seal.js";
import type { SecretName, SecretStore, SessionToken } from "./types.js";

export interface GrantLease {
  readonly grantId: string;
  readonly token: SessionToken;
  readonly secretKey: Uint8Array;
  expire(): void;
  close(cleanup: () => void): void;
}

/**
 * Shared grant lifecycle for agent sessions and the script broker:
 * issue a sealed-box grant, revoke + wipe on TTL or close.
 */
export function openGrantLease(options: {
  readonly store: SecretStore;
  readonly secretNames: readonly SecretName[];
  readonly ttlMs: number;
}): GrantLease {
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

  const expire = () => {
    store.revokeGrant(grantId);
    wipe(secretKey);
  };

  let closed = false;
  const ttlTimer = setTimeout(expire, ttlMs);

  return {
    grantId,
    token,
    secretKey,
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
