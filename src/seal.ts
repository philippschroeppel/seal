import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8Encode, wipe } from "./bytes.js";
import type { KeyPair } from "./types.js";

const PUBLIC_KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const KEY_LENGTH = 32;
const POLY1305_TAG_LENGTH = 16;
const SEALED_OVERHEAD = PUBLIC_KEY_LENGTH + NONCE_LENGTH + POLY1305_TAG_LENGTH;
const HKDF_INFO = utf8Encode("seal/v1");

export function generateKeyPair(): KeyPair {
  const { secretKey, publicKey } = x25519.keygen();
  return { secretKey, publicKey };
}

/**
 * Sealed box: ephemeral X25519 + HKDF-SHA-256 + ChaCha20-Poly1305.
 * Layout: ephemeral_public (32) || nonce (12) || ciphertext+tag.
 */
export function seal(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
): Uint8Array {
  assertLength(recipientPublicKey, PUBLIC_KEY_LENGTH, "recipient public key");
  const ephemeral = generateKeyPair();
  try {
    const key = deriveSealKey(ephemeral.secretKey, recipientPublicKey);
    try {
      const nonce = randomBytes(NONCE_LENGTH);
      const ciphertext = chacha20poly1305(key, nonce).encrypt(plaintext);
      return concatBytes(ephemeral.publicKey, nonce, ciphertext);
    } finally {
      wipe(key);
    }
  } finally {
    wipe(ephemeral.secretKey);
  }
}

export function unseal(
  sealed: Uint8Array,
  recipientSecretKey: Uint8Array,
): Uint8Array {
  assertLength(recipientSecretKey, PUBLIC_KEY_LENGTH, "recipient secret key");
  if (sealed.length < SEALED_OVERHEAD) {
    throw new Error("sealed box is too short");
  }

  const ephemeralPublic = sealed.subarray(0, PUBLIC_KEY_LENGTH);
  const nonce = sealed.subarray(
    PUBLIC_KEY_LENGTH,
    PUBLIC_KEY_LENGTH + NONCE_LENGTH,
  );
  const ciphertext = sealed.subarray(PUBLIC_KEY_LENGTH + NONCE_LENGTH);
  const key = deriveSealKey(recipientSecretKey, ephemeralPublic);
  try {
    return chacha20poly1305(key, nonce).decrypt(ciphertext);
  } finally {
    wipe(key);
  }
}

function deriveSealKey(
  secretKey: Uint8Array,
  peerPublicKey: Uint8Array,
): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, peerPublicKey);
  try {
    return hkdf(sha256, shared, undefined, HKDF_INFO, KEY_LENGTH);
  } finally {
    wipe(shared);
  }
}

function assertLength(
  bytes: Uint8Array,
  expected: number,
  label: string,
): void {
  if (bytes.length !== expected) {
    throw new Error(`${label} must be ${expected} bytes`);
  }
}
