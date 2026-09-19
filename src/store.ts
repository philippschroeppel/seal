import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { utf8Decode, utf8Encode, wipe } from "./bytes.js";
import { SealError } from "./errors.js";
import { seal } from "./seal.js";
import type {
  Grant,
  GrantEntry,
  GrantId,
  SecretName,
  SecretStore,
} from "./types.js";

const DEK_LENGTH = 32;
const NONCE_LENGTH = 12;

interface StoredSecret {
  dek: Uint8Array;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

interface StoredGrant {
  entries: GrantEntry[];
  expiresAt: number;
  revoked: boolean;
}

/**
 * In-process stand-in for a secrets backend.
 *
 * A production store would hold DEKs in an HSM or KMS and only materialize
 * them long enough to seal a grant. This class keeps them in memory so the
 * demo and tests can run without extra services.
 */
export class MemorySecretStore implements SecretStore {
  readonly #secrets = new Map<SecretName, StoredSecret>();
  readonly #grants = new Map<GrantId, StoredGrant>();

  put(name: SecretName, value: string): void {
    const existing = this.#secrets.get(name);
    const dek = randomBytes(DEK_LENGTH);
    const nonce = randomBytes(NONCE_LENGTH);
    const ciphertext = gcm(dek, nonce).encrypt(utf8Encode(value));
    this.#secrets.set(name, { dek, ciphertext, nonce });
    if (existing) {
      wipe(existing.dek);
    }
  }

  issueGrant(
    grantId: GrantId,
    secretNames: readonly SecretName[],
    recipientPublicKey: Uint8Array,
    ttlMs: number,
  ): void {
    if (secretNames.length === 0) {
      throw new Error("secretNames must not be empty");
    }
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new Error("ttlMs must be a positive number");
    }

    const entries = secretNames.map((name) => {
      const secret = this.#secrets.get(name);
      if (!secret) {
        throw new SealError("unknown_secret", `unknown secret: ${name}`);
      }
      return {
        name,
        ciphertext: secret.ciphertext,
        nonce: secret.nonce,
        wrappedDek: seal(secret.dek, recipientPublicKey),
      };
    });

    this.#grants.set(grantId, {
      entries,
      expiresAt: Date.now() + ttlMs,
      revoked: false,
    });
  }

  fetchGrant(grantId: GrantId): Grant | undefined {
    const grant = this.#grants.get(grantId);
    if (!grant || grant.revoked || Date.now() >= grant.expiresAt) {
      return undefined;
    }
    return { entries: grant.entries, expiresAt: grant.expiresAt };
  }

  revokeGrant(grantId: GrantId): void {
    const grant = this.#grants.get(grantId);
    if (grant) {
      grant.revoked = true;
    }
  }
}

export function decryptValue(entry: GrantEntry, dek: Uint8Array): string {
  return utf8Decode(gcm(dek, entry.nonce).decrypt(entry.ciphertext));
}
