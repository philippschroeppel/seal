import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { utf8Decode, utf8Encode, wipe } from "./bytes.js";
import { SealError } from "./errors.js";
import type { SecretName, SecretStore } from "./types.js";

const DEK_LENGTH = 32;
const NONCE_LENGTH = 12;

interface StoredSecret {
  dek: Uint8Array;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * In-process named vault. Each value is AES-256-GCM under a random DEK
 * that never leaves this process. Callers use `use()` so plaintext is
 * wiped after the callback.
 */
export class MemorySecretStore implements SecretStore {
  readonly #secrets = new Map<SecretName, StoredSecret>();

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

  has(name: SecretName): boolean {
    return this.#secrets.has(name);
  }

  async use<T>(
    name: SecretName,
    fn: (value: string) => T | Promise<T>,
  ): Promise<T> {
    const stored = this.#secrets.get(name);
    if (!stored) {
      throw new SealError("unknown_secret", `unknown secret: ${name}`);
    }
    let plaintext: Uint8Array;
    try {
      plaintext = gcm(stored.dek, stored.nonce).decrypt(stored.ciphertext);
    } catch {
      throw new SealError("decrypt_failed", `failed to decrypt ${name}`);
    }
    const value = utf8Decode(plaintext);
    try {
      return await fn(value);
    } finally {
      wipe(plaintext);
      wipe(utf8Encode(value));
    }
  }

  wipe(name?: SecretName): void {
    if (name) {
      const stored = this.#secrets.get(name);
      if (stored) {
        wipe(stored.dek);
        this.#secrets.delete(name);
      }
      return;
    }
    for (const stored of this.#secrets.values()) {
      wipe(stored.dek);
    }
    this.#secrets.clear();
  }
}
